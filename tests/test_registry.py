from ulpf.engine import DeterministicEngine
from ulpf.models import EventEnvelope, EventStatus
from ulpf.registry import DynamicParserRegistry, ParserDefinition, SandboxValidator


def test_sandbox_validation_success():
    samples = [
        "[EDGE_ROUTER_01] TS=2026-08-30T10:00:01Z CLIENT=10.50.1.20 REMOTE=203.0.113.10 PROTO=UDP STATE=REJECT",
        "[EDGE_ROUTER_01] TS=2026-08-30T10:00:04Z CLIENT=172.16.88.4 REMOTE=1.0.0.1 PROTO=TCP STATE=ACCEPT",
    ]
    pattern = r"CLIENT=(?P<client_ip>[^\s]+)\s+REMOTE=(?P<remote_ip>[^\s]+)\s+PROTO=(?P<proto>\w+)\s+STATE=(?P<state>\w+)"

    valid, msg, coverage = SandboxValidator.validate_pattern(pattern, samples)
    assert valid is True
    assert coverage == 1.0


def test_sandbox_validation_failure_on_bad_pattern():
    samples = ["[EDGE_ROUTER_01] CLIENT=10.50.1.20 REMOTE=203.0.113.10 STATE=REJECT"]
    bad_pattern = r"SRC_IP=(?P<src>[^\s]+)"

    valid, msg, coverage = SandboxValidator.validate_pattern(bad_pattern, samples)
    assert valid is False
    assert coverage == 0.0


def test_dynamic_parser_hot_reload():
    registry = DynamicParserRegistry()
    engine = DeterministicEngine(registry=registry)

    log = "[EDGE_ROUTER_01] TS=2026-08-30T10:00:01Z CLIENT=10.50.1.20 REMOTE=203.0.113.10 PROTO=UDP STATE=REJECT"
    envelope = EventEnvelope(raw_payload=log)

    # 1. Before registration: should fail and mark PENDING_AI[cite: 1]
    success, processed = engine.parse_and_normalize(envelope)
    assert success is False
    assert processed.status == EventStatus.PENDING_AI

    # 2. Hot-load dynamic parser definition into registry[cite: 1]
    parser_def = ParserDefinition(
        parser_id="dynamic_edge_router_v1",
        regex_pattern=r"CLIENT=(?P<client_ip>[^\s]+)\s+REMOTE=(?P<remote_ip>[^\s]+)\s+PROTO=(?P<proto>\w+)\s+STATE=(?P<state>\w+)",
        field_mappings={
            "src_ip": "client_ip",
            "dst_ip": "remote_ip",
            "proto": "proto",
            "action": "state"
        }
    )
    assert registry.register(parser_def) is True

    # 3. Re-evaluate same log: should now parse deterministically without restarting[cite: 1]
    envelope_retry = EventEnvelope(raw_payload=log)
    success_dyn, processed_dyn = engine.parse_and_normalize(envelope_retry)

    assert success_dyn is True
    assert processed_dyn.status == EventStatus.COMMITTED
    assert processed_dyn.parser_id == "dynamic_edge_router_v1"
    assert processed_dyn.ocsf_event.src_endpoint["ip"] == "10.50.1.20"
    assert processed_dyn.ocsf_event.dst_endpoint["ip"] == "203.0.113.10"
    assert processed_dyn.ocsf_event.disposition == "Blocked"