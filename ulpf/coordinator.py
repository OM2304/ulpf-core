from typing import Dict, List, Optional
from ulpf.engine import DeterministicEngine
from ulpf.models import EventEnvelope, EventStatus
from ulpf.spool import DurableSpool
from ulpf.storage import NormalizedStorage


class PipelineCoordinator:
    """Coordinates event ingestion into durable spool, parsing, and storage commit."""

    def __init__(
        self,
        spool: DurableSpool,
        engine: DeterministicEngine,
        storage: NormalizedStorage
    ):
        self.spool = spool
        self.engine = engine
        self.storage = storage

    def ingest_raw_event(self, raw_payload: str, transport: str = "direct") -> EventEnvelope:
        """Durable Ingestion: Logs land in disk spool immediately before any parsing."""
        return self.spool.persist_raw(payload=raw_payload, transport=transport)

    def process_pending_batch(self, batch_size: int = 100) -> Dict[str, int]:
        """Fetch pending batch from spool, parse deterministically, and commit or triage."""
        pending_events = self.spool.fetch_pending(limit=batch_size)
        stats = {
            "processed": len(pending_events),
            "committed": 0,
            "pending_ai": 0
        }

        for event in pending_events:
            success, parsed_event = self.engine.parse_and_normalize(event)

            if success and parsed_event.status == EventStatus.COMMITTED:
                self.storage.commit_event(parsed_event)
                self.spool.update_status(
                    parsed_event.event_id,
                    EventStatus.COMMITTED,
                    parser_id=parsed_event.parser_id
                )
                stats["committed"] += 1
            else:
                self.spool.update_status(event.event_id, EventStatus.PENDING_AI)
                stats["pending_ai"] += 1

        return stats