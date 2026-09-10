import json
import sqlite3
from typing import Any, Dict, List, Mapping, Optional
from ulpf.models import EventEnvelope, EventStatus, OCSFNetworkActivity


class NormalizedStorage:
    """Analytical and forensic storage for committed OCSF events[cite: 1]."""

    def __init__(self, db_path: str = "ulpf_analytics.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self) -> None:
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
                    action TEXT,
                    disposition TEXT,
                    src_ip TEXT,
                    src_port INTEGER,
                    dst_ip TEXT,
                    dst_port INTEGER,
                    protocol TEXT,
                    ocsf_json TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_norm_src_ip ON normalized_events(src_ip);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_norm_disposition ON normalized_events(disposition);")

    def commit_event(self, envelope: EventEnvelope) -> bool:
        """Store committed event ensuring cryptographic linkage between raw and normalized data[cite: 1]."""
        if envelope.status != EventStatus.COMMITTED or not envelope.ocsf_event:
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

        def field(name: str, default: Any = None) -> Any:
            if isinstance(ocsf, Mapping):
                return ocsf.get(name, default)
            return getattr(ocsf, name, default)

        def endpoint_value(endpoint_name: str, value_name: str) -> Any:
            endpoint = field(endpoint_name, {})
            if isinstance(endpoint, Mapping):
                return endpoint.get(value_name)
            return getattr(endpoint, value_name, None)

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
                    envelope.raw_sha256,
                    envelope.parser_id or "unknown",
                    envelope.parser_version or "1.0.0",
                    field("action", "Unknown"),
                    field("disposition"),
                    endpoint_value("src_endpoint", "ip"),
                    endpoint_value("src_endpoint", "port"),
                    endpoint_value("dst_endpoint", "ip"),
                    endpoint_value("dst_endpoint", "port"),
                    endpoint_value("connection_info", "protocol_name"),
                    json.dumps(ocsf_dict),
                ),
            )
        return True

    def get_event_by_id(self, event_id: str) -> Optional[Dict]:
        """Fetch committed record for verification and forensic audit[cite: 1]."""
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM normalized_events WHERE event_id = ?", (event_id,))
            row = cursor.fetchone()
            if row:
                return dict(row)
        return None

    def list_events(
        self,
        limit: int = 50,
        offset: int = 0,
        disposition: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch committed events with parsed OCSF JSON and pagination metadata."""
        query = """
            SELECT event_id, parser_id, src_ip, dst_ip, protocol,
                   action, disposition, raw_payload, raw_sha256, ocsf_json
            FROM normalized_events
        """
        parameters: List[Any] = []
        if disposition is not None:
            query += " WHERE disposition = ?"
            parameters.append(disposition)
        query += " ORDER BY rowid DESC LIMIT ? OFFSET ?"
        parameters.extend([limit, offset])

        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, parameters).fetchall()

        events: List[Dict[str, Any]] = []
        for row in rows:
            event = json.loads(row["ocsf_json"])
            event.update({
                "event_id": str(row["event_id"]),
                "parser_id": str(row["parser_id"] or ""),
                "src_ip": str(row["src_ip"] or ""),
                "dst_ip": str(row["dst_ip"] or ""),
                "protocol": str(row["protocol"] or ""),
                "action": str(row["action"] or ""),
                "disposition": str(row["disposition"] or ""),
                "raw_payload": str(row["raw_payload"] or ""),
                "raw_sha256": str(row["raw_sha256"] or ""),
            })
            events.append(event)
        return events
