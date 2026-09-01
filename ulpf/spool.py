import sqlite3
from typing import List, Optional
from ulpf.models import EventEnvelope, EventStatus


class DurableSpool:
    """Crash-resilient disk spool backed by SQLite WAL mode.
    
    Guarantees raw log persistence to disk before deterministic parsing
    or agentic AI analysis occurs, preventing data loss during unexpected crashes.
    """

    def __init__(self, db_path: str = "ulpf_spool.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Create and configure a SQLite connection with Write-Ahead Logging (WAL)."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initialize the durable spool table schema if it does not exist."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS spool_events (
                    event_id TEXT PRIMARY KEY,
                    received_at TEXT NOT NULL,
                    raw_sha256 TEXT NOT NULL,
                    raw_payload TEXT NOT NULL,
                    status TEXT NOT NULL,
                    parser_id TEXT,
                    source_transport TEXT DEFAULT 'direct'
                );
            """)
            conn.commit()

    def persist_raw(self, payload: str, transport: str = "direct") -> EventEnvelope:
        """Create an EventEnvelope, persist it to SQLite disk spool, and return the envelope.
        
        Sets lifecycle state to DURABLY_STORED upon successful disk commit.
        """
        envelope = EventEnvelope(
            raw_payload=payload,
            source_transport=transport,
            status=EventStatus.DURABLY_STORED
        )
        self.spool(envelope)
        return envelope

    def spool(self, envelope: EventEnvelope) -> None:
        """Insert or replace an event envelope into the durable SQLite spool."""
        status_val = envelope.status.value if hasattr(envelope.status, "value") else str(envelope.status)
        
        # Safely extract timestamp attribute across schema variations (received_at / arrival_timestamp)
        ts = getattr(envelope, "received_at", getattr(envelope, "arrival_timestamp", None))
        timestamp_str = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)
        transport = getattr(envelope, "source_transport", "direct")

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO spool_events (
                    event_id, received_at, raw_sha256, raw_payload, status, parser_id, source_transport
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    envelope.event_id,
                    timestamp_str,
                    envelope.raw_sha256,
                    envelope.raw_payload,
                    status_val,
                    envelope.parser_id,
                    transport,
                ),
            )
            conn.commit()

    # --- Backward-Compatibility & Interface Aliases ---

    def enqueue(self, envelope: EventEnvelope) -> None:
        """Alias for spool(). Enqueues an event into durable storage."""
        self.spool(envelope)

    def insert_event(self, envelope: EventEnvelope) -> None:
        """Alias for spool(). Inserts an event into durable storage."""
        self.spool(envelope)

    def insert_pending(self, envelope: EventEnvelope) -> None:
        """Alias for spool(). Inserts a pending event into durable storage."""
        self.spool(envelope)

    def fetch_pending(self, limit: int = 100) -> List[EventEnvelope]:
        """Retrieve uncommitted or pending events in FIFO order for batch processing."""
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT event_id, received_at, raw_sha256, raw_payload, status, parser_id, source_transport
                FROM spool_events
                WHERE status IN ('RECEIVED', 'DURABLY_STORED', 'PENDING')
                ORDER BY rowid ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        events = []
        for r in rows:
            raw_status = r["status"]
            try:
                status_enum = EventStatus(raw_status)
            except ValueError:
                status_enum = getattr(EventStatus, raw_status, EventStatus.RECEIVED)

            env = EventEnvelope(
                event_id=r["event_id"],
                received_at=r["received_at"],
                raw_payload=r["raw_payload"],
                source_transport=r["source_transport"] if "source_transport" in r.keys() and r["source_transport"] else "direct",
                status=status_enum,
                parser_id=r["parser_id"],
            )
            events.append(env)
        return events

    def update_status(self, event_id: str, status: EventStatus, parser_id: Optional[str] = None) -> None:
        """Update the lifecycle status and parser association of a spooled event."""
        status_val = status.value if hasattr(status, "value") else str(status)
        with self._get_connection() as conn:
            if parser_id:
                conn.execute(
                    "UPDATE spool_events SET status = ?, parser_id = ? WHERE event_id = ?",
                    (status_val, parser_id, event_id),
                )
            else:
                conn.execute(
                    "UPDATE spool_events SET status = ? WHERE event_id = ?",
                    (status_val, event_id),
                )
            conn.commit()