import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class EventStatus(str, Enum):
    """Event lifecycle states across the pipeline."""
    RECEIVED = "RECEIVED"
    DURABLY_STORED = "DURABLY_STORED"
    PROCESSING = "PROCESSING"
    COMMITTED = "COMMITTED"
    PENDING_AI = "PENDING_AI"
    RETRY = "RETRY"
    QUARANTINED = "QUARANTINED"
    DEAD_LETTER = "DEAD_LETTER"  # Permanent dead-letter quarantine for unparseable poison pills


class OCSFNetworkActivity(BaseModel):
    """OCSF Class UID 4001: Network Activity representation."""
    class_uid: int = 4001
    category_uid: int = 4
    severity_id: int = 1
    action: str = "Unknown"
    disposition: Optional[str] = None
    src_endpoint: Dict[str, Any] = Field(default_factory=dict)
    dst_endpoint: Dict[str, Any] = Field(default_factory=dict)
    connection_info: Dict[str, Any] = Field(default_factory=dict)


class EventEnvelope(BaseModel):
    """Lossless metadata wrapper preserving raw bytes and cryptographic hash."""
    event_id: str = Field(default_factory=lambda: f"ULPF-{uuid.uuid4().hex[:12]}")
    received_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source_transport: str = "syslog_udp"
    raw_payload: str
    raw_sha256: str = ""
    status: EventStatus = EventStatus.RECEIVED
    parser_id: Optional[str] = None
    parser_version: Optional[str] = None
    ocsf_event: Optional[OCSFNetworkActivity] = None
    
    # Poison-pill tracking & dead-letter telemetry
    retry_count: int = Field(default=0)
    last_error: Optional[str] = Field(default=None)

    def model_post_init(self, __context: Any) -> None:
        """Automatically compute SHA-256 if not provided."""
        if not self.raw_sha256 and self.raw_payload:
            self.compute_hash()

    def compute_hash(self) -> None:
        self.raw_sha256 = hashlib.sha256(self.raw_payload.encode("utf-8")).hexdigest()