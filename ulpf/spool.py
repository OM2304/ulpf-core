import os
import sqlite3
from typing import Any, Dict, List, Optional
from ulpf.models import EventEnvelope, EventStatus


class DurableSpool:
    """Crash-resilient disk spool backed by SQLite WAL mode.
    
    Guarantees raw log persistence to disk before deterministic parsing
    or agentic AI analysis occurs, preventing data loss during unexpected crashes.
    """

    def __init__(self, db_path: str = "ulpf_spool.db"):
        # Resolve to absolute path so working directory changes never lose the database file
        self.db_path = os.path.abspath(db_path)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Create and configure a SQLite connection with Write-Ahead Logging (WAL)."""
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initialize the durable spool table schema with automated safe column migrations."""
        conn = self._get_connection()
        try:
            # 1. Create table and base index, then commit immediately
            conn.execute("""
                CREATE TABLE IF NOT EXISTS spool_events (
                    event_id TEXT PRIMARY KEY,
                    received_at TEXT NOT NULL,
                    raw_sha256 TEXT NOT NULL,
                    raw_payload TEXT NOT NULL,
                    status TEXT NOT NULL,
                    parser_id TEXT,
                    parser_version TEXT,
                    source_transport TEXT DEFAULT 'direct',
                    retry_count INTEGER DEFAULT 0,
                    last_error TEXT
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_spool_status ON spool_events(status);")
            conn.commit()

            # 2. Inspect existing columns before attempting ALTER TABLE to avoid aborted transactions
            cursor = conn.execute("PRAGMA table_info(spool_events);")
            existing_columns = {row["name"] for row in cursor.fetchall()}

            migrations = [
                ("parser_version", "ALTER TABLE spool_events ADD COLUMN parser_version TEXT;"),
                ("source_transport", "ALTER TABLE spool_events ADD COLUMN source_transport TEXT DEFAULT 'direct';"),
                ("retry_count", "ALTER TABLE spool_events ADD COLUMN retry_count INTEGER DEFAULT 0;"),
                ("last_error", "ALTER TABLE spool_events ADD COLUMN last_error TEXT;"),
            ]

            for col_name, col_sql in migrations:
                if col_name not in existing_columns:
                    conn.execute(col_sql)
            conn.commit()
        finally:
            conn.close()

    def persist_raw(self, payload: str, transport: str = "direct") -> EventEnvelope:
        """Create an EventEnvelope, persist it to SQLite disk spool, and return the envelope."""
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
        
        # Safely extract timestamp attribute across schema variations
        ts = getattr(envelope, "received_at", getattr(envelope, "arrival_timestamp", None))
        timestamp_str = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)
        transport = getattr(envelope, "source_transport", "direct")
        parser_ver = getattr(envelope, "parser_version", None)
        retries = getattr(envelope, "retry_count", 0)
        err = getattr(envelope, "last_error", None)

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO spool_events (
                    event_id, received_at, raw_sha256, raw_payload, status, parser_id, parser_version, source_transport, retry_count, last_error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    envelope.event_id,
                    timestamp_str,
                    envelope.raw_sha256,
                    envelope.raw_payload,
                    status_val,
                    envelope.parser_id,
                    parser_ver,
                    transport,
                    retries,
                    err,
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
                SELECT event_id, received_at, raw_sha256, raw_payload, status, parser_id, parser_version, source_transport,
                       COALESCE(retry_count, 0) AS retry_count, last_error
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
                parser_version=r["parser_version"] if "parser_version" in r.keys() else None,
                retry_count=r["retry_count"] if "retry_count" in r.keys() and r["retry_count"] is not None else 0,
                last_error=r["last_error"] if "last_error" in r.keys() else None,
            )
            events.append(env)
        return events

    def update_status(
        self, 
        event_id: str, 
        status: EventStatus, 
        parser_id: Optional[str] = None,
        error_msg: Optional[str] = None
    ) -> bool:
        """Update the lifecycle status, parser association, and optional error state of a spooled event."""
        status_val = status.value if hasattr(status, "value") else str(status)
        with self._get_connection() as conn:
            if parser_id and error_msg:
                cursor = conn.execute(
                    "UPDATE spool_events SET status = ?, parser_id = ?, last_error = ? WHERE event_id = ?",
                    (status_val, parser_id, error_msg, event_id),
                )
            elif parser_id:
                cursor = conn.execute(
                    "UPDATE spool_events SET status = ?, parser_id = ? WHERE event_id = ?",
                    (status_val, parser_id, event_id),
                )
            elif error_msg:
                cursor = conn.execute(
                    "UPDATE spool_events SET status = ?, last_error = ? WHERE event_id = ?",
                    (status_val, error_msg, event_id),
                )
            else:
                cursor = conn.execute(
                    "UPDATE spool_events SET status = ? WHERE event_id = ?",
                    (status_val, event_id),
                )
            conn.commit()
            return cursor.rowcount > 0

    # --- Dead-Letter & Poison Pill Governance ---

    def get_pending_ai_ids(self) -> List[str]:
        """Return IDs of all events currently awaiting AI triage."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT event_id FROM spool_events WHERE status = 'PENDING_AI'"
            ).fetchall()
            return [r["event_id"] for r in rows]

    def increment_retries(
        self, 
        event_ids: List[str], 
        error_reason: str = "AI synthesis failed", 
        max_retries: int = 3
    ) -> List[str]:
        """Increment retry count for specified events.
        
        Quarantines events that reach or exceed max_retries into QUARANTINED status
        to prevent infinite triage retry loops.
        Returns a list of event IDs that were transitioned to QUARANTINED.
        """
        if not event_ids:
            return []

        quarantined = []
        with self._get_connection() as conn:
            for ev_id in event_ids:
                row = conn.execute(
                    "SELECT retry_count FROM spool_events WHERE event_id = ?",
                    (ev_id,)
                ).fetchone()
                if not row:
                    continue

                current_retries = row["retry_count"] if row["retry_count"] is not None else 0
                new_retries = current_retries + 1

                if new_retries >= max_retries:
                    conn.execute(
                        """
                        UPDATE spool_events 
                        SET retry_count = ?, status = ?, last_error = ?
                        WHERE event_id = ?
                        """,
                        (new_retries, EventStatus.QUARANTINED.value, f"Max retries ({max_retries}) exceeded: {error_reason}", ev_id),
                    )
                    quarantined.append(ev_id)
                else:
                    conn.execute(
                        """
                        UPDATE spool_events 
                        SET retry_count = ?, last_error = ?
                        WHERE event_id = ?
                        """,
                        (new_retries, error_reason, ev_id),
                    )
            conn.commit()
        return quarantined

    def quarantine_event(self, event_id: str, reason: str) -> None:
        """Immediately transition an unparseable or malicious log to QUARANTINED status."""
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE spool_events SET status = ?, last_error = ? WHERE event_id = ?",
                (EventStatus.QUARANTINED.value, reason, event_id),
            )
            conn.commit()

    def retry_event(self, event_id: str) -> bool:
        """Put an event back into the AI triage queue and clear stale retry state."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE spool_events
                SET status = ?, retry_count = 0, last_error = NULL
                WHERE event_id = ?
                """,
                (EventStatus.PENDING_AI.value, event_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    def delete_event(self, event_id: str) -> bool:
        """Permanently remove an event from the durable spool."""
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM spool_events WHERE event_id = ?", (event_id,))
            conn.commit()
            return cursor.rowcount > 0
