import sqlite3
from typing import List
from ulpf.models import EventEnvelope, EventStatus


class DurableSpool:
    """Embedded SQLite Write-Ahead Log (WAL) recovery spool."""

    def __init__(self, db_path: str = "ulpf_spool.db"):
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
                CREATE TABLE IF NOT EXISTS raw_spool (
                    event_id TEXT PRIMARY KEY,
                    received_at TEXT NOT NULL,
                    source_transport TEXT NOT NULL,
                    raw_payload TEXT NOT NULL,
                    raw_sha256 TEXT NOT NULL,
                    status TEXT NOT NULL,
                    retry_count INTEGER DEFAULT 0
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_status ON raw_spool(status);")

    def persist_raw(self, payload: str, transport: str = "syslog_udp") -> EventEnvelope:
        """Persist raw payload and hash before any parsing occurs."""
        envelope = EventEnvelope(raw_payload=payload, source_transport=transport)
        envelope.status = EventStatus.DURABLY_STORED

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO raw_spool (event_id, received_at, source_transport, raw_payload, raw_sha256, status)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    envelope.event_id,
                    envelope.received_at,
                    envelope.source_transport,
                    envelope.raw_payload,
                    envelope.raw_sha256,
                    envelope.status.value
                )
            )
        return envelope

    def fetch_pending(self, limit: int = 100) -> List[EventEnvelope]:
        """Retrieve uncommitted events ready for processing."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT event_id, received_at, source_transport, raw_payload, raw_sha256, status
                FROM raw_spool 
                WHERE status IN (?, ?, ?) 
                LIMIT ?
                """,
                (
                    EventStatus.DURABLY_STORED.value,
                    EventStatus.RECEIVED.value,
                    EventStatus.RETRY.value,
                    limit
                )
            )
            rows = cursor.fetchall()
            return [
                EventEnvelope(
                    event_id=r[0],
                    received_at=r[1],
                    source_transport=r[2],
                    raw_payload=r[3],
                    raw_sha256=r[4],
                    status=EventStatus(r[5])
                )
                for r in rows
            ]

    def update_status(self, event_id: str, status: EventStatus) -> None:
        """Update event lifecycle status."""
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE raw_spool SET status = ? WHERE event_id = ?",
                (status.value, event_id)
            )