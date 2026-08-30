from ulpf.engine import DeterministicEngine
from ulpf.models import EventEnvelope, EventStatus


def test_parse_firewall_key_value():
    engine = DeterministicEngine()
    log = "<134>Aug 30 12:41:22 fw01-edge src=10.2.1.15 dst=8.8.8.8 spt=51230 dpt=443 proto=TCP action=DENY"
    envelope = EventEnvelope(raw_payload=log)

    success, processed = engine.parse_and_normalize(envelope)

    assert success is True
    assert processed.status == EventStatus.COMMITTED
    assert processed.parser_id == "builtin_firewall_kv_v1"
    assert processed.ocsf_event.src_endpoint["ip"] == "10.2.1.15"
    assert processed.ocsf_event.src_endpoint["port"] == 51230
    assert processed.ocsf_event.dst_endpoint["ip"] == "8.8.8.8"
    assert processed.ocsf_event.disposition == "Blocked"


def test_parse_palo_alto_cef():
    engine = DeterministicEngine()
    log = "CEF:0|Palo Alto Networks|PAN-OS|10.0|TRAFFIC|allow|1|src=172.20.10.4 dst=198.51.100.2 spt=445 dpt=445 proto=tcp act=allow"
    envelope = EventEnvelope(raw_payload=log)

    success, processed = engine.parse_and_normalize(envelope)

    assert success is True
    assert processed.status == EventStatus.COMMITTED
    assert processed.parser_id == "builtin_cef_panos_v1"
    assert processed.ocsf_event.disposition == "Allowed"
    assert processed.ocsf_event.connection_info["protocol_name"] == "tcp"


def test_parse_linux_auth_syslog():
    engine = DeterministicEngine()
    log = "Jan 18 06:12:01 edge-auth-01 sshd[2412]: Failed password for invalid user admin from 192.168.1.105 port 54212 ssh2"
    envelope = EventEnvelope(raw_payload=log)

    success, processed = engine.parse_and_normalize(envelope)

    assert success is True
    assert processed.status == EventStatus.COMMITTED
    assert processed.parser_id == "builtin_linux_auth_v1"
    assert processed.ocsf_event.src_endpoint["ip"] == "192.168.1.105"
    assert processed.ocsf_event.src_endpoint["port"] == 54212
    assert processed.ocsf_event.disposition == "Blocked"


def test_unrecognized_format_routes_to_pending_ai():
    engine = DeterministicEngine()
    log = "[EDGE_ROUTER_01] TS=2026-08-30T10:00:01Z CLIENT=10.50.1.20 REMOTE=203.0.113.10 PROTO=UDP STATE=REJECT"
    envelope = EventEnvelope(raw_payload=log)

    success, processed = engine.parse_and_normalize(envelope)

    assert success is False
    assert processed.status == EventStatus.PENDING_AI
    assert processed.ocsf_event is None