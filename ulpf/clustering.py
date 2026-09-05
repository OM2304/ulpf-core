import hashlib
import re
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from ulpf.models import EventEnvelope


def extract_structural_skeleton(log: str) -> str:
    """Extract a canonical structural skeleton by masking variable tokens.
    
    Replaces dynamic tokens (timestamps, IPs, MACs, ports, quoted values,
    key-value payloads, and numbers) with structural tags while preserving
    delimiters, brackets, and structural tokens.
    """
    if not log or not log.strip():
        return "<EMPTY>"

    s = log.strip()

    # 1. ISO 8601 & Syslog timestamps
    s = re.sub(r'\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b', '<TS>', s)
    s = re.sub(r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b', '<TS>', s)

    # 2. IP Addresses & IP/Port or CIDR notation
    s = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+|/\d+)?\b', '<IP_PORT>', s)

    # 3. MAC addresses
    s = re.sub(r'\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b', '<MAC>', s)

    # 4. Quoted strings
    s = re.sub(r'"[^"]*"', '<STR>', s)
    s = re.sub(r"'[^']*'", '<STR>', s)

    # 5. Key-Value pairs: preserve Key name, mask dynamic value
    s = re.sub(r'([A-Za-z0-9_-]+)=([^\s]+)', r'\1=<VAL>', s)

    # 6. Common network actions & protocols in positional syslog logs
    s = re.sub(r'\b(tcp|udp|icmp|gre|esp)\b', '<PROTO>', s, flags=re.IGNORECASE)
    s = re.sub(r'\b(allow|deny|accept|reject|drop|permit|block)\b', '<ACTION>', s, flags=re.IGNORECASE)

    # 7. Standalone integers / numbers
    s = re.sub(r'\b\d+\b', '<NUM>', s)

    # 8. Normalize whitespace
    s = re.sub(r'\s+', ' ', s)
    return s.strip()


def compute_skeleton_fingerprint(skeleton: str) -> str:
    """Generate deterministic 8-character hex signature for a structural skeleton."""
    return hashlib.sha256(skeleton.encode("utf-8")).hexdigest()[:8]


class LogCluster(BaseModel):
    """Cluster of unrecognized log events sharing an identical structural skeleton."""
    cluster_id: str
    skeleton: str
    sample_count: int
    sample_logs: List[str]
    events: List[EventEnvelope] = Field(default_factory=list)


def cluster_unrecognized_events(events: List[EventEnvelope]) -> List[LogCluster]:
    """Group unrecognized log envelopes into homogeneous structural clusters.
    
    Prevents the LLM agent from receiving mixed log syntax within a single
    synthesis prompt, ensuring high-confidence, single-purpose regex patterns.
    """
    cluster_map: Dict[str, Dict] = {}

    for ev in events:
        skeleton = extract_structural_skeleton(ev.raw_payload)
        cluster_id = compute_skeleton_fingerprint(skeleton)

        if cluster_id not in cluster_map:
            cluster_map[cluster_id] = {
                "skeleton": skeleton,
                "events": [],
                "samples": []
            }

        cluster_map[cluster_id]["events"].append(ev)
        if len(cluster_map[cluster_id]["samples"]) < 5:
            cluster_map[cluster_id]["samples"].append(ev.raw_payload)

    clusters: List[LogCluster] = []
    for cid, data in cluster_map.items():
        clusters.append(
            LogCluster(
                cluster_id=cid,
                skeleton=data["skeleton"],
                sample_count=len(data["events"]),
                sample_logs=data["samples"],
                events=data["events"]
            )
        )

    # Sort clusters descending by sample volume to prioritize higher-frequency logs
    clusters.sort(key=lambda c: c.sample_count, reverse=True)
    return clusters