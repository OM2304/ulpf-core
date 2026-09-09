import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

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
        description="Maps regex capture groups to OCSF fields (e.g. {'client_ip': 'src_endpoint.ip'})",
    )


class SandboxValidator:
    """Validates regex safety, timeout constraints, and sample coverage before promotion."""

    @staticmethod
    def validate_pattern(
        pattern: str,
        sample_logs: List[str],
        timeout_ms: float = 50.0,
    ) -> Tuple[bool, str, float]:
        """Test regex compilation, execution time (ReDoS guard), and sample match coverage."""
        if not pattern or not pattern.strip():
            return False, "Empty pattern string", 0.0
        if not sample_logs:
            return False, "No sample logs provided for validation", 0.0

        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            return False, f"Regex compilation failed: {exc}", 0.0

        matches = 0
        for sample in sample_logs:
            start = time.perf_counter()
            try:
                match = compiled.search(sample)
                elapsed = (time.perf_counter() - start) * 1000.0
                if elapsed > timeout_ms:
                    return False, f"Regex exceeded execution timeout ({elapsed:.2f}ms > {timeout_ms}ms)", 0.0
                if match:
                    matches += 1
            except Exception as exc:
                return False, f"Execution failure on sample: {exc}", 0.0

        coverage = matches / len(sample_logs)
        if coverage < 1.0:
            return False, f"Coverage insufficient: {matches}/{len(sample_logs)} samples matched ({coverage * 100:.1f}%)", coverage
        return True, "Validation successful", coverage


class DynamicParserRegistry:
    """In-memory registry for built-in and AI-synthesized deterministic parsers."""

    def __init__(self, storage_dir: Optional[str] = DEFAULT_PARSER_DIR):
        self.storage_dir = storage_dir
        self._parsers: Dict[str, Tuple[re.Pattern, ParserDefinition]] = {}
        self._pre_seed_parsers()

        if self.storage_dir:
            os.makedirs(self.storage_dir, exist_ok=True)
            if not (os.environ.get("PYTEST_CURRENT_TEST") and self.storage_dir == DEFAULT_PARSER_DIR):
                self.load_from_disk()

    def _pre_seed_parsers(self) -> None:
        """Register standard web, authentication, and network formats."""
        self.register(
            ParserDefinition(
                parser_id="core_apache_web_v1",
                parser_version="1.0.0",
                description="WEB",
                regex_pattern=r'(?i)^(?P<src_ip>\d+\.\d+\.\d+\.\d+).*?(?P<method>GET|POST|PUT|DELETE)\s+(?P<url>\S+)\s+HTTP.*?"?\s+(?P<status>\d{3})',
                field_mappings={"src_ip": "src_ip", "method": "method", "url": "url", "status": "status"},
            ),
            persist=False,
        )
        self.register(
            ParserDefinition(
                parser_id="core_pam_auth_v1",
                parser_version="1.0.0",
                description="AUTHENTICATION",
                regex_pattern=r"(?i).*?(?P<action>session|login|password).*?(?P<status>opened|closed|failed|success).*?(?:user|for)\s+(?P<user>\S+)",
                field_mappings={"user": "user", "action": "action", "status": "status"},
            ),
            persist=False,
        )
        self.register(
            ParserDefinition(
                parser_id="core_iptables_net_v1",
                parser_version="1.0.0",
                description="NETWORK",
                regex_pattern=r"(?i).*?src=(?P<src_ip>\d+\.\d+\.\d+\.\d+).*?dst=(?P<dst_ip>\d+\.\d+\.\d+\.\d+).*?proto=(?P<proto>\S+).*?(?P<action>DROP|ACCEPT|REJECT|DENY|BLOCK|ALLOW)",
                field_mappings={"src_ip": "src_ip", "dst_ip": "dst_ip", "proto": "proto", "action": "action"},
            ),
            persist=False,
        )

    def register(self, definition: ParserDefinition, persist: bool = True) -> bool:
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
        if not self.storage_dir:
            return False
        try:
            os.makedirs(self.storage_dir, exist_ok=True)
            filepath = os.path.join(self.storage_dir, f"{parser.parser_id}.json")
            with open(filepath, "w", encoding="utf-8") as file:
                file.write(parser.model_dump_json(indent=2))
            return True
        except Exception:
            return False

    def load_from_disk(self) -> int:
        if not self.storage_dir or not os.path.exists(self.storage_dir):
            return 0
        loaded_count = 0
        for filename in os.listdir(self.storage_dir):
            if not filename.endswith(".json"):
                continue
            filepath = os.path.join(self.storage_dir, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as file:
                    parser_def = ParserDefinition(**json.load(file))
                self._parsers[parser_def.parser_id] = (re.compile(parser_def.regex_pattern), parser_def)
                loaded_count += 1
            except Exception:
                continue
        return loaded_count

    def get_parser(self, parser_id: str) -> Optional[ParserDefinition]:
        entry = self._parsers.get(parser_id)
        return entry[1] if entry else None

    def list_parsers(self) -> List[str]:
        return list(self._parsers.keys())

    def remove_parser(self, parser_id: str, remove_from_disk: bool = True) -> bool:
        removed = self._parsers.pop(parser_id, None) is not None
        if remove_from_disk and self.storage_dir:
            filepath = os.path.join(self.storage_dir, f"{parser_id}.json")
            if os.path.exists(filepath):
                try:
                    os.remove(filepath)
                except OSError:
                    pass
        return removed

    def apply_parsers(self, envelope: EventEnvelope) -> Tuple[bool, EventEnvelope]:
        raw = envelope.raw_payload
        for parser_id, (compiled_pattern, definition) in self._parsers.items():
            try:
                match = compiled_pattern.search(raw)
                if not match:
                    continue

                extracted = match.groupdict()
                mapped_data = {
                    target_key: str(extracted[group_name])
                    for target_key, group_name in definition.field_mappings.items()
                    if extracted.get(group_name) is not None
                }
                category = definition.description.upper()

                if category == "AUTHENTICATION":
                    envelope.ocsf_event = OCSFNetworkActivity(
                        class_uid=3002,
                        class_name="Authentication",
                        category_uid=3,
                        category_name="Identity & Access Management",
                        action=mapped_data.get("action", "session"),
                        status_detail=mapped_data.get("status", "unknown"),
                        user={"name": mapped_data.get("user", "unknown"), "domain": "LOCAL"},
                        raw_data=raw,
                    )
                elif category == "WEB":
                    raw_status = mapped_data.get("status", "200")
                    envelope.ocsf_event = OCSFNetworkActivity(
                        class_uid=4002,
                        class_name="HTTP Activity",
                        category_uid=4,
                        category_name="Network Activity",
                        action=mapped_data.get("method", "GET"),
                        src_endpoint={"ip": mapped_data.get("src_ip", "0.0.0.0")},
                        http_request={
                            "http_method": mapped_data.get("method", "GET"),
                            "url": {"path": mapped_data.get("url", "/")},
                        },
                        http_response={"status_code": int(raw_status) if raw_status.isdigit() else 200},
                        raw_data=raw,
                    )
                else:
                    action = mapped_data.get("action", "UNKNOWN")
                    action_lower = action.lower()
                    disposition = (
                        "Blocked" if action_lower in ["reject", "deny", "drop", "block"]
                        else "Allowed" if action_lower in ["accept", "allow", "pass", "permit"]
                        else "Unknown"
                    )
                    envelope.ocsf_event = OCSFNetworkActivity(
                        class_uid=4001,
                        class_name="Network Activity",
                        category_uid=4,
                        category_name="Network Activity",
                        action=action,
                        disposition=disposition,
                        src_endpoint={"ip": mapped_data["src_ip"]} if mapped_data.get("src_ip") else {},
                        dst_endpoint={"ip": mapped_data["dst_ip"]} if mapped_data.get("dst_ip") else {},
                        connection_info={"protocol_name": mapped_data["proto"]} if mapped_data.get("proto") else {},
                        raw_data=raw,
                    )

                envelope.parser_id = definition.parser_id
                envelope.parser_version = definition.parser_version
                envelope.status = EventStatus.COMMITTED
                return True, envelope
            except Exception:
                continue
        return False, envelope

    def apply(self, envelope: EventEnvelope) -> Tuple[bool, EventEnvelope]:
        return self.apply_parsers(envelope)
