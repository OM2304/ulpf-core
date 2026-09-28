import json
import logging
import sqlite3
import hashlib
from typing import Any, Dict, List, Optional
from ulpf.models import EventEnvelope, EventStatus

logger = logging.getLogger("PostgresStorage")

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False
    RealDictCursor = None


class NormalizedStorage:
    def __init__(self, db_path: Optional[str] = None, **kwargs):
        self.db_path = db_path
        self.use_sqlite = bool(db_path)
        self.db_password = "root"

        self.conn_params = {
            "dbname": "postgres",
            "user": "postgres",
            "password": self.db_password,
            "host": "localhost",
            "port": "5432"
        }

        if not self.use_sqlite and not POSTGRES_AVAILABLE:
            self.use_sqlite = True
            self.db_path = "ulpf_storage.db"

        self._initialize_db()

    def _get_connection(self):
        if self.use_sqlite:
            conn = sqlite3.connect(self.db_path or "ulpf_storage.db")
            conn.row_factory = sqlite3.Row
            return conn
        return psycopg2.connect(**self.conn_params)

    def _initialize_db(self) -> None:
        if self.use_sqlite:
            try:
                with self._get_connection() as conn:
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS normalized_events (
                            event_id TEXT PRIMARY KEY,
                            received_at TEXT NOT NULL,
                            source_transport TEXT NOT NULL,
                            raw_payload TEXT NOT NULL,
                            raw_sha256 TEXT NOT NULL,
                            parser_id TEXT NOT NULL,
                            parser_version TEXT NOT NULL,
                            action TEXT NOT NULL,
                            disposition TEXT NOT NULL,
                            src_ip TEXT,
                            src_port INTEGER,
                            dst_ip TEXT,
                            dst_port INTEGER,
                            protocol TEXT,
                            ocsf_json TEXT NOT NULL
                        )
                    """)
                    conn.commit()
            except Exception as e:
                logger.error(f"SQLite NormalizedStorage init failed: {e}")
            return

        try:
            with self._get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS ocsf_ledger (
                            id SERIAL PRIMARY KEY,
                            event_id VARCHAR(255) UNIQUE NOT NULL,
                            class_uid VARCHAR(50) NOT NULL,
                            parser_id VARCHAR(100),
                            raw_payload TEXT,
                            raw_sha256 VARCHAR(64),
                            normalized_data JSONB,
                            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                    """)
                    cur.execute("""
                        ALTER TABLE ocsf_ledger ADD COLUMN IF NOT EXISTS raw_sha256 VARCHAR(64);
                    """)
                conn.commit()
            logger.info("🐘 PostgreSQL Immutable Ledger connected and verified.")
        except Exception as e:
            logger.warning(f"⚠️ PostgreSQL Connection Failed ({e}). Falling back to SQLite.")
            self.use_sqlite = True
            self.db_path = "ulpf_storage.db"
            self._initialize_db()

    def commit_event(self, envelope: EventEnvelope) -> bool:
        if envelope.status != EventStatus.COMMITTED or not getattr(envelope, "ocsf_event", None):
            return False

        ocsf = envelope.ocsf_event
        if hasattr(ocsf, "model_dump"):
            ocsf_dict = ocsf.model_dump()
        elif hasattr(ocsf, "dict"):
            ocsf_dict = ocsf.dict()
        elif isinstance(ocsf, dict):
            ocsf_dict = ocsf
        else:
            ocsf_dict = {}

        raw_sha256 = getattr(envelope, "raw_sha256", None) or hashlib.sha256(
            (envelope.raw_payload or "").encode("utf-8")
        ).hexdigest()

        if self.use_sqlite:
            def field(key: str, default: Any = None) -> Any:
                return ocsf_dict.get(key, default)

            def endpoint_val(ep_name: str, key: str) -> Any:
                ep = ocsf_dict.get(ep_name)
                return ep.get(key) if isinstance(ep, dict) else None

            try:
                with self._get_connection() as conn:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO normalized_events (
                            event_id, received_at, source_transport, raw_payload, raw_sha256,
                            parser_id, parser_version, action, disposition,
                            src_ip, src_port, dst_ip, dst_port, protocol, ocsf_json
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            envelope.event_id,
                            envelope.received_at,
                            envelope.source_transport,
                            envelope.raw_payload,
                            raw_sha256,
                            envelope.parser_id or "unknown",
                            envelope.parser_version or "1.0.0",
                            field("action", "Unknown"),
                            field("disposition", "Unknown"),
                            endpoint_val("src_endpoint", "ip"),
                            endpoint_val("src_endpoint", "port"),
                            endpoint_val("dst_endpoint", "ip"),
                            endpoint_val("dst_endpoint", "port"),
                            endpoint_val("connection_info", "protocol_name"),
                            json.dumps(ocsf_dict),
                        ),
                    )
                    conn.commit()
                return True
            except Exception as e:
                logger.error(f"Failed to write to SQLite ledger: {e}")
                return False

        try:
            with self._get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO ocsf_ledger 
                        (event_id, class_uid, parser_id, raw_payload, raw_sha256, normalized_data)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT (event_id) DO NOTHING;
                    """, (
                        envelope.event_id,
                        getattr(envelope, 'class_uid', '4001'),
                        envelope.parser_id,
                        envelope.raw_payload,
                        raw_sha256,
                        json.dumps(ocsf_dict)
                    ))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"❌ Failed to write to Ledger: {e}")
            return False

    def get_event_by_id(self, event_id: str) -> Optional[Dict]:
        if self.use_sqlite:
            with self._get_connection() as conn:
                row = conn.execute("SELECT * FROM normalized_events WHERE event_id = ?", (event_id,)).fetchone()
                if row:
                    return dict(row)
            return None

        try:
            with self._get_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("SELECT * FROM ocsf_ledger WHERE event_id = %s", (event_id,))
                    row = cur.fetchone()
                    if row:
                        data = dict(row)
                        normalized = data.get("normalized_data") or {}
                        if isinstance(normalized, str):
                            try:
                                normalized = json.loads(normalized)
                            except Exception:
                                normalized = {}
                        event = dict(normalized) if isinstance(normalized, dict) else {}
                        event.update({
                            "event_id": str(data.get("event_id", "")),
                            "parser_id": str(data.get("parser_id") or ""),
                            "raw_payload": str(data.get("raw_payload") or ""),
                            "raw_sha256": str(data.get("raw_sha256") or ""),
                            "class_uid": str(data.get("class_uid") or "4001"),
                            "status": "COMMITTED",
                            "action": str(event.get("action", "Unknown")),
                            "disposition": str(event.get("disposition", "Unknown")),
                            "src_ip": str(event.get("src_endpoint", {}).get("ip", "")),
                            "dst_ip": str(event.get("dst_endpoint", {}).get("ip", "")),
                            "protocol": str(event.get("connection_info", {}).get("protocol_name", "")),
                            "time": str(data.get("timestamp") or event.get("time") or ""),
                        })
                        return event
        except Exception as e:
            logger.error(f"Failed to get event by id: {e}")
        return None

    def list_events(
        self,
        limit: int = 50,
        offset: int = 0,
        disposition: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []

        if self.use_sqlite:
            query = """
                SELECT event_id, parser_id, src_ip, dst_ip, protocol,
                       action, disposition, raw_payload, raw_sha256, ocsf_json, received_at
                FROM normalized_events
            """
            parameters: List[Any] = []
            if disposition is not None and disposition.strip() and disposition.lower() != "all":
                query += " WHERE disposition = ?"
                parameters.append(disposition)
            query += " ORDER BY rowid DESC LIMIT ? OFFSET ?"
            parameters.extend([limit, offset])

            with self._get_connection() as conn:
                rows = conn.execute(query, parameters).fetchall()

            for row in rows:
                try:
                    event = json.loads(row["ocsf_json"])
                except Exception:
                    event = {}
                event.update({
                    "event_id": str(row["event_id"]),
                    "parser_id": str(row["parser_id"] or ""),
                    "src_ip": str(row["src_ip"] or ""),
                    "dst_ip": str(row["dst_ip"] or ""),
                    "protocol": str(row["protocol"] or ""),
                    "action": str(row["action"] or "Unknown"),
                    "disposition": str(row["disposition"] or "Unknown"),
                    "status": "COMMITTED",
                    "raw_payload": str(row["raw_payload"] or ""),
                    "raw_sha256": str(row["raw_sha256"] or ""),
                    "class_uid": str(event.get("class_uid", "4001")),
                    "time": str(row["received_at"] or event.get("time") or ""),
                })
                events.append(event)
            return events

        query = """
            SELECT event_id, class_uid, parser_id, raw_payload, raw_sha256, normalized_data, timestamp
            FROM ocsf_ledger
        """
        params: List[Any] = []
        if disposition is not None and disposition.strip() and disposition.lower() != "all":
            query += " WHERE (normalized_data->>'disposition') ILIKE %s"
            params.append(disposition)

        query += " ORDER BY id DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])

        try:
            with self._get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(query, tuple(params))
                    rows = cur.fetchall()

            for row in rows:
                event_id, class_uid, parser_id, raw_payload, raw_sha256, normalized_data, timestamp = row

                event = normalized_data if isinstance(normalized_data, dict) else {}
                if not raw_sha256 and raw_payload:
                    raw_sha256 = hashlib.sha256(raw_payload.encode('utf-8')).hexdigest()

                event.update({
                    "event_id": str(event_id),
                    "class_uid": str(class_uid or event.get("class_uid", "4001")),
                    "parser_id": str(parser_id or ""),
                    "raw_payload": str(raw_payload or ""),
                    "raw_sha256": str(raw_sha256 or ""),
                    "status": "COMMITTED",
                    "src_ip": str(event.get("src_endpoint", {}).get("ip", "")),
                    "dst_ip": str(event.get("dst_endpoint", {}).get("ip", "")),
                    "protocol": str(event.get("connection_info", {}).get("protocol_name", "")),
                    "action": str(event.get("action", "Unknown")),
                    "disposition": str(event.get("disposition", "Unknown")),
                    "time": str(timestamp or event.get("time") or ""),
                })
                events.append(event)
        except Exception as e:
            logger.error(f"Failed to list events: {e}")

        return events

    def get_source_distribution(self) -> Dict[str, int]:
        distribution: Dict[str, int] = {}
        if self.use_sqlite:
            try:
                with self._get_connection() as conn:
                    rows = conn.execute("""
                        SELECT COALESCE(NULLIF(parser_id, ''), 'unassigned') as pid, count(*)
                        FROM normalized_events
                        GROUP BY pid
                    """).fetchall()
                    for pid, count in rows:
                        distribution[str(pid)] = int(count)
            except Exception as e:
                logger.error(f"Failed to query source distribution from SQLite: {e}")
            return distribution

        try:
            with self._get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT COALESCE(NULLIF(parser_id, ''), 'unassigned') as pid, count(*)
                        FROM ocsf_ledger
                        GROUP BY pid
                    """)
                    rows = cur.fetchall()
                    for pid, count in rows:
                        distribution[str(pid)] = int(count)
        except Exception as e:
            logger.error(f"Failed to query source distribution from Postgres: {e}")

        return distribution