from typing import Dict, List
from ulpf.engine import DeterministicEngine
from ulpf.models import EventEnvelope, EventStatus
from ulpf.spool import DurableSpool
from ulpf.storage import NormalizedStorage


class PipelineCoordinator:
    """Orchestrates event movement across Spool, Parsing Engine, and Analytical Storage[cite: 1]."""

    def __init__(self, spool: DurableSpool, engine: DeterministicEngine, storage: NormalizedStorage):
        self.spool = spool
        self.engine = engine
        self.storage = storage

    def ingest_raw_event(self, payload: str, transport: str = "syslog_udp") -> EventEnvelope:
        """Step 1: Capture and persist raw event directly to disk spool[cite: 1]."""
        return self.spool.persist_raw(payload=payload, transport=transport)

    def process_pending_batch(self, batch_size: int = 100) -> Dict[str, int]:
        """Step 2: Pull pending events, execute deterministic parsing, commit or route to AI queue[cite: 1]."""
        pending_events = self.spool.fetch_pending(limit=batch_size)
        stats = {
            "processed": 0,
            "committed": 0,
            "pending_ai": 0,
        }

        for envelope in pending_events:
            stats["processed"] += 1
            success, processed_envelope = self.engine.parse_and_normalize(envelope)

            # Update state in durable spool
            self.spool.update_status(processed_envelope.event_id, processed_envelope.status)

            if success and processed_envelope.status == EventStatus.COMMITTED:
                # Commit to analytical storage with raw-to-normalized cryptographic link[cite: 1]
                self.storage.commit_event(processed_envelope)
                stats["committed"] += 1
            else:
                # Stays in spool with status PENDING_AI for Agentic Control Plane[cite: 1]
                stats["pending_ai"] += 1

        return stats