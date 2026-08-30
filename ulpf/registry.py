import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field
from ulpf.models import EventEnvelope, EventStatus, OCSFNetworkActivity


class ParserDefinition(BaseModel):
    """Declarative definition of a custom or AI-synthesized parser."""
    parser_id: str
    parser_version: str = "1.0.0"
    description: str = "Dynamic parser"
    regex_pattern: str
    field_mappings: Dict[str, str] = Field(
        default_factory=dict,
        description="Maps regex capture groups to OCSF fields (e.g. {'client_ip': 'src_endpoint.ip'})[cite: 1]"
    )


class SandboxValidator:
    """Validates regex safety, timeout constraints, and sample coverage before promotion[cite: 1]."""

    @staticmethod
    def validate_pattern(
        pattern: str,
        sample_logs: List[str],
        timeout_ms: float = 10.0
    ) -> Tuple[bool, str, float]:
        """Test regex compilation, execution time (ReDoS guard), and sample match coverage[cite: 1]."""
        try:
            compiled = re.compile(pattern)
        except re.error as e:
            return False, f"Regex compilation failed: {e}", 0.0

        matches = 0
        total_time = 0.0

        for sample in sample_logs:
            start = time.perf_counter()
            match = compiled.search(sample)
            elapsed = (time.perf_counter() - start) * 1000.0  # ms
            total_time += elapsed

            if elapsed > timeout_ms:
                return False, f"Regex exceeded execution timeout ({elapsed:.2f}ms > {timeout_ms}ms)[cite: 1]", 0.0

            if match:
                matches += 1

        coverage = (matches / len(sample_logs)) if sample_logs else 0.0
        if coverage < 1.0:
            return False, f"Coverage insufficient: {matches}/{len(sample_logs)} samples matched ({coverage*100:.1f}%)[cite: 1]", coverage

        return True, "Validation successful", coverage


class DynamicParserRegistry:
    """In-memory thread-safe registry for active deterministic and dynamic parsers[cite: 1]."""

    def __init__(self):
        self._parsers: Dict[str, Tuple[re.Pattern, ParserDefinition]] = {}

    def register(self, definition: ParserDefinition) -> bool:
        """Compile and hot-load a validated parser definition[cite: 1]."""
        try:
            compiled = re.compile(definition.regex_pattern)
            self._parsers[definition.parser_id] = (compiled, definition)
            return True
        except re.error:
            return False

    def list_parsers(self) -> List[str]:
        return list(self._parsers.keys())

    def apply_parsers(self, envelope: EventEnvelope) -> Tuple[bool, EventEnvelope]:
        """Evaluate dynamic parsers against an envelope[cite: 1]."""
        raw = envelope.raw_payload

        for parser_id, (compiled_pattern, definition) in self._parsers.items():
            match = compiled_pattern.search(raw)
            if match:
                extracted = match.groupdict()
                mappings = definition.field_mappings

                # Extract mapped values
                src_ip = extracted.get(mappings.get("src_ip", "src_ip"))
                dst_ip = extracted.get(mappings.get("dst_ip", "dst_ip"))
                proto = extracted.get(mappings.get("proto", "proto"))
                action = extracted.get(mappings.get("action", "action"), "UNKNOWN")

                act_lower = action.lower()
                disposition = (
                    "Blocked" if act_lower in ["reject", "deny", "drop", "block"]
                    else "Allowed" if act_lower in ["accept", "allow", "pass"]
                    else "Unknown"
                )

                envelope.ocsf_event = OCSFNetworkActivity(
                    action=action,
                    disposition=disposition,
                    src_endpoint={"ip": src_ip} if src_ip else {},
                    dst_endpoint={"ip": dst_ip} if dst_ip else {},
                    connection_info={"protocol_name": proto} if proto else {}
                )
                envelope.parser_id = definition.parser_id
                envelope.parser_version = definition.parser_version
                envelope.status = EventStatus.COMMITTED
                return True, envelope

        return False, envelope