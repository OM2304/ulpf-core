import re
from typing import Optional, Tuple
from ulpf.models import EventEnvelope, EventStatus, OCSFNetworkActivity
from ulpf.registry import DynamicParserRegistry


class DeterministicEngine:
    """High-throughput data plane parser for known and dynamically registered log formats."""

    def __init__(self, registry: Optional[DynamicParserRegistry] = None):
        self.registry = registry or DynamicParserRegistry()

        # 1. Palo Alto CEF Pattern
        self.cef_pattern = re.compile(
            r"CEF:\d+\|(?P<vendor>[^|]+)\|(?P<product>[^|]+)\|[^|]+\|[^|]+\|(?P<raw_action>[^|]+)\|(?P<severity>[^|]+)\|(?P<extension>.*)"
        )

        # 2. Firewall Key-Value Pattern
        self.kv_pattern = re.compile(
            r"src=(?P<src>[^\s]+)\s+dst=(?P<dst>[^\s]+)\s+spt=(?P<spt>\d+)\s+dpt=(?P<dpt>\d+)\s+proto=(?P<proto>\w+)\s+action=(?P<action>\w+)"
        )

        # 3. Linux SSH / Auth Syslog Header Signature
        self.auth_pattern = re.compile(
            r"sshd\[\d+\]:\s+(?P<message>Failed password|Accepted password|Accepted publickey|Invalid user|Connection closed)\b"
        )

    def _normalize_disposition(self, action: str) -> str:
        """Map heterogeneous action verbs into standard OCSF disposition."""
        act_lower = str(action).lower().strip()
        if any(k in act_lower for k in ["deny", "drop", "reject", "block", "fail", "invalid"]):
            return "Blocked"
        elif any(k in act_lower for k in ["allow", "permit", "accept"]) or re.search(r"\bpass(?:ed)?\b", act_lower):
            return "Allowed"
        else:
            return "Unknown"

    def parse_and_normalize(self, envelope: EventEnvelope) -> Tuple[bool, EventEnvelope]:
        """Attempt built-in parsers, then dynamic registry, then route to PENDING_AI."""
        raw = envelope.raw_payload

        # Check 1: Palo Alto CEF Format
        cef_match = self.cef_pattern.search(raw)
        if cef_match:
            ext = cef_match.group("extension")
            src_ip = re.search(r"src=(?P<val>[^\s]+)", ext)
            dst_ip = re.search(r"dst=(?P<val>[^\s]+)", ext)
            spt = re.search(r"spt=(?P<val>\d+)", ext)
            dpt = re.search(r"dpt=(?P<val>\d+)", ext)
            proto = re.search(r"proto=(?P<val>\w+)", ext)
            act = re.search(r"act=(?P<val>[^\s]+)", ext)

            raw_action = act.group("val") if act else cef_match.group("raw_action")
            envelope.ocsf_event = OCSFNetworkActivity(
                action=raw_action,
                disposition=self._normalize_disposition(raw_action),
                src_endpoint={
                    "ip": src_ip.group("val") if src_ip else None,
                    "port": int(spt.group("val")) if spt else None,
                },
                dst_endpoint={
                    "ip": dst_ip.group("val") if dst_ip else None,
                    "port": int(dpt.group("val")) if dpt else None,
                },
                connection_info={"protocol_name": proto.group("val") if proto else None},
            )
            envelope.parser_id = "builtin_cef_panos_v1"
            envelope.parser_version = "1.0.0"
            envelope.status = EventStatus.COMMITTED
            return True, envelope

        # Check 2: Perimeter Firewall Key-Value
        kv_match = self.kv_pattern.search(raw)
        if kv_match:
            action = kv_match.group("action")
            envelope.ocsf_event = OCSFNetworkActivity(
                action=action,
                disposition=self._normalize_disposition(action),
                src_endpoint={
                    "ip": kv_match.group("src"),
                    "port": int(kv_match.group("spt")),
                },
                dst_endpoint={
                    "ip": kv_match.group("dst"),
                    "port": int(kv_match.group("dpt")),
                },
                connection_info={"protocol_name": kv_match.group("proto")},
            )
            envelope.parser_id = "builtin_firewall_kv_v1"
            envelope.parser_version = "1.0.0"
            envelope.status = EventStatus.COMMITTED
            return True, envelope

        # Check 3: Linux SSH / Auth Syslog
        auth_match = self.auth_pattern.search(raw)
        if auth_match:
            raw_msg = auth_match.group("message")
            ip_match = re.search(r"(?:from|\buser\s+\w+)\s+(?P<src>\d+\.\d+\.\d+\.\d+)", raw)
            port_match = re.search(r"\bport\s+(?P<port>\d+)", raw)

            envelope.ocsf_event = OCSFNetworkActivity(
                action=raw_msg,
                disposition=self._normalize_disposition(raw_msg),
                src_endpoint={
                    "ip": ip_match.group("src") if ip_match else "0.0.0.0",
                    "port": int(port_match.group("port")) if port_match else None,
                },
                dst_endpoint={"ip": "127.0.0.1", "port": 22},
                connection_info={"protocol_name": "SSH"},
            )
            envelope.parser_id = "builtin_linux_auth_v1"
            envelope.parser_version = "1.0.0"
            envelope.status = EventStatus.COMMITTED
            return True, envelope

        # Check 4: Dynamic Hot-Loaded Parsers in Registry
        success, dyn_envelope = self.registry.apply_parsers(envelope)
        if success:
            return True, dyn_envelope

        # No parser matched -> Route to AI Agent Queue
        envelope.status = EventStatus.PENDING_AI
        return False, envelope