import json
import sqlite3
from typing import Dict, List, Optional
from ulpf.models import EventEnvelope, EventStatus, OCSFNetworkActivity


class NormalizedStorage:
    """Analytical and forensic storage for committed OCSF events[cite: 1]."""

    def __init__(self, db_path: str = "ulpf_analytics.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")
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
        ocsf_dict = ocsf.model_dump()

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
                    ocsf.action,
                    ocsf.disposition,
                    ocsf.src_endpoint.get("ip"),
                    ocsf.src_endpoint.get("port"),
                    ocsf.dst_endpoint.get("ip"),
                    ocsf.dst_endpoint.get("port"),
                    ocsf.connection_info.get("protocol_name"),
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
        search: str = "",
        disposition_filter: str = ""
    ) -> list:
        """Paginated query of committed OCSF events for the analytical dashboard table."""
        base_query = "SELECT * FROM normalized_events"
        conditions = []
        params = []

        if search:
            conditions.append(
                "(src_ip LIKE ? OR dst_ip LIKE ? OR action LIKE ? OR parser_id LIKE ? OR raw_payload LIKE ?)"
            )
            like = f"%{search}%"
            params.extend([like, like, like, like, like])

        if disposition_filter:
            conditions.append("disposition = ?")
            params.append(disposition_filter)

        if conditions:
            base_query += " WHERE " + " AND ".join(conditions)

        base_query += " ORDER BY received_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._get_connection() as conn:
            conn.row_factory = __import__('sqlite3').Row
            rows = conn.execute(base_query, params).fetchall()
        return [dict(r) for r in rows]

    def get_total_event_count(self, search: str = "", disposition_filter: str = "") -> int:
        """Return total committed event count (with optional filter) for pagination."""
        base_query = "SELECT COUNT(*) FROM normalized_events"
        conditions = []
        params = []

        if search:
            conditions.append(
                "(src_ip LIKE ? OR dst_ip LIKE ? OR action LIKE ? OR parser_id LIKE ? OR raw_payload LIKE ?)"
            )
            like = f"%{search}%"
            params.extend([like, like, like, like, like])

        if disposition_filter:
            conditions.append("disposition = ?")
            params.append(disposition_filter)

        if conditions:
            base_query += " WHERE " + " AND ".join(conditions)

        with self._get_connection() as conn:
            row = conn.execute(base_query, params).fetchone()
        return row[0] if row else 0

    def get_stats(self) -> dict:
        """Return aggregated stats: total, by disposition, unique parsers, unique src IPs."""
        with self._get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM normalized_events").fetchone()[0]
            by_disposition = conn.execute(
                "SELECT disposition, COUNT(*) FROM normalized_events GROUP BY disposition"
            ).fetchall()
            by_parser = conn.execute(
                "SELECT parser_id, COUNT(*) FROM normalized_events GROUP BY parser_id ORDER BY COUNT(*) DESC"
            ).fetchall()
            unique_src = conn.execute(
                "SELECT COUNT(DISTINCT src_ip) FROM normalized_events WHERE src_ip IS NOT NULL"
            ).fetchone()[0]
        return {
            "total_committed": total,
            "by_disposition": {r[0]: r[1] for r in by_disposition},
            "by_parser": {r[0]: r[1] for r in by_parser},
            "unique_src_ips": unique_src,
        }