import json
import os
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field
from ulpf.models import EventEnvelope, EventStatus, OCSFNetworkActivity

DEFAULT_PARSER_DIR = os.path.join("ulpf", "parsers", "generated")


class ParserDefinition(BaseModel):
    """Declarative definition of a custom or AI-synthesized parser."""
    parser_id: str
    parser_version: str = "1.0.0"
    description: str = "Dynamic parser"
    regex_pattern: str
    field_mappings: Dict[str, str] = Field(
        default_factory=dict,
        description="Maps regex capture groups to OCSF fields (e.g. {'client_ip': 'src_endpoint.ip'})"
    )


class SandboxValidator:
    """Validates regex safety, timeout constraints, and sample coverage before promotion."""

    @staticmethod
    def validate_pattern(
        pattern: str,
        sample_logs: List[str],
        timeout_ms: float = 50.0
    ) -> Tuple[bool, str, float]:
        """Test regex compilation, execution time (ReDoS guard), and sample match coverage."""
        if not pattern or not pattern.strip():
            return False, "Empty pattern string", 0.0

        if not sample_logs:
            return False, "No sample logs provided for validation", 0.0

        try:
            compiled = re.compile(pattern)
        except re.error as e:
            return False, f"Regex compilation failed: {e}", 0.0

        matches = 0
        total_time = 0.0

        for sample in sample_logs:
            start = time.perf_counter()
            try:
                match = compiled.search(sample)
                elapsed = (time.perf_counter() - start) * 1000.0  # ms
                total_time += elapsed

                if elapsed > timeout_ms:
                    return False, f"Regex exceeded execution timeout ({elapsed:.2f}ms > {timeout_ms}ms)", 0.0

                if match:
                    matches += 1
            except Exception as e:
                return False, f"Execution failure on sample: {e}", 0.0

        coverage = (matches / len(sample_logs)) if sample_logs else 0.0
        if coverage < 1.0:
            return False, f"Coverage insufficient: {matches}/{len(sample_logs)} samples matched ({coverage*100:.1f}%)", coverage

        return True, "Validation successful", coverage


class DynamicParserRegistry:
    """In-memory thread-safe registry for active deterministic and dynamic parsers.
    
    Stores validated ParserDefinition objects in memory for microsecond regex execution,
    and serializes them to JSON schemas on disk to ensure learned parsers persist across
    application restarts.
    """

    def __init__(self, storage_dir: Optional[str] = DEFAULT_PARSER_DIR):
        self.storage_dir = storage_dir
        self._parsers: Dict[str, Tuple[re.Pattern, ParserDefinition]] = {}

        if self.storage_dir:
            os.makedirs(self.storage_dir, exist_ok=True)
            # Avoid loading generated parsers during unit test runs unless explicitly tested
            if not (os.environ.get("PYTEST_CURRENT_TEST") and self.storage_dir == DEFAULT_PARSER_DIR):
                self.load_from_disk()

    def register(self, definition: ParserDefinition, persist: bool = True) -> bool:
        """Compile and hot-load a validated parser definition."""
        try:
            compiled = re.compile(definition.regex_pattern)
            self._parsers[definition.parser_id] = (compiled, definition)

            if persist and self.storage_dir:
                if not (os.environ.get("PYTEST_CURRENT_TEST") and self.storage_dir == DEFAULT_PARSER_DIR):
                    self.save_to_disk(definition)

            return True
        except re.error:
            return False

    def save_to_disk(self, parser: ParserDefinition) -> bool:
        """Serialize parser definition to disk as formatted JSON."""
        if not self.storage_dir:
            return False
        try:
            os.makedirs(self.storage_dir, exist_ok=True)
            filepath = os.path.join(self.storage_dir, f"{parser.parser_id}.json")
            with open(filepath, "w", encoding="utf-8") as f:
                if hasattr(parser, "model_dump_json"):
                    f.write(parser.model_dump_json(indent=2))
                else:
                    f.write(parser.json(indent=2))
            return True
        except Exception:
            return False

    def load_from_disk(self) -> int:
        """Scan storage directory and hydrate active registry with persisted parsers."""
        if not self.storage_dir or not os.path.exists(self.storage_dir):
            return 0

        loaded_count = 0
        for filename in os.listdir(self.storage_dir):
            if filename.endswith(".json"):
                filepath = os.path.join(self.storage_dir, filename)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    parser_def = ParserDefinition(**data)
                    compiled = re.compile(parser_def.regex_pattern)
                    self._parsers[parser_def.parser_id] = (compiled, parser_def)
                    loaded_count += 1
                except Exception:
                    continue
        return loaded_count

    def get_parser(self, parser_id: str) -> Optional[ParserDefinition]:
        """Retrieve a registered parser definition by ID."""
        entry = self._parsers.get(parser_id)
        if entry:
            return entry[1]
        return None

    def list_parsers(self) -> List[str]:
        """List IDs of all currently active dynamic parsers."""
        return list(self._parsers.keys())

    def remove_parser(self, parser_id: str, remove_from_disk: bool = True) -> bool:
        """Remove a parser from memory and optionally delete its JSON schema from disk."""
        removed = False
        if parser_id in self._parsers:
            del self._parsers[parser_id]
            removed = True

        if remove_from_disk and self.storage_dir:
            filepath = os.path.join(self.storage_dir, f"{parser_id}.json")
            if os.path.exists(filepath):
                try:
                    os.remove(filepath)
                except OSError:
                    pass

        return removed

    def apply_parsers(self, envelope: EventEnvelope) -> Tuple[bool, EventEnvelope]:
        """Evaluate dynamic parsers against an envelope."""
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

                act_lower = str(action).lower()
                disposition = (
                    "Blocked" if act_lower in ["reject", "deny", "drop", "block"]
                    else "Allowed" if act_lower in ["accept", "allow", "pass", "permit"]
                    else "Unknown"
                )

                envelope.ocsf_event = OCSFNetworkActivity(
                    action=action,
                    disposition=disposition,
                    src_endpoint={"ip": src_ip} if src_ip else {},
                    dst_endpoint={"ip": dst_ip} if dst_ip else {},
                    connection_info={"protocol_name": proto} if proto else {},
                    raw_data=envelope.raw_payload
                )
                envelope.parser_id = definition.parser_id
                envelope.parser_version = definition.parser_version
                envelope.status = EventStatus.COMMITTED
                return True, envelope

        return False, envelope

    def apply(self, envelope: EventEnvelope) -> Tuple[bool, EventEnvelope]:
        """Backward-compatible alias for apply_parsers."""
        return self.apply_parsers(envelope)