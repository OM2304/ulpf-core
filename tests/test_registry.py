import os
import pytest
from ulpf.engine import DeterministicEngine
from ulpf.models import EventEnvelope, EventStatus
from ulpf.registry import DynamicParserRegistry, ParserDefinition, SandboxValidator


def test_sandbox_validation_success():
    """Test that SandboxValidator approves valid, safe regex patterns with 100% coverage."""
    pattern = r"src=(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+dst=(?P<dst_ip>\d+\.\d+\.\d+\.\d+)"
    sample_logs = [
        "Aug 30 fw01 src=192.168.1.1 dst=10.0.0.1 action=allow",
        "Aug 30 fw02 src=172.16.0.5 dst=8.8.8.8 action=deny"
    ]
    is_valid, reason, coverage = SandboxValidator.validate_pattern(pattern, sample_logs)
    assert is_valid is True
    assert coverage == 1.0


def test_sandbox_validation_failure_on_bad_pattern():
    """Test that SandboxValidator rejects patterns that fail to match all sample logs."""
    pattern = r"NON_MATCHING_KEY=(?P<val>\w+)"
    sample_logs = [
        "Aug 30 fw01 src=192.168.1.1 dst=10.0.0.1 action=allow"
    ]
    is_valid, reason, coverage = SandboxValidator.validate_pattern(pattern, sample_logs)
    assert is_valid is False
    assert coverage == 0.0


def test_dynamic_parser_hot_reload():
    """Test hot-reloading a dynamic parser into the deterministic engine without restarts."""
    registry = DynamicParserRegistry(storage_dir=None)
    engine = DeterministicEngine(registry=registry)

    # Proprietary industrial router format unrecognized by default engine
    sample_log = "[EDGE_ROUTER_01] CLIENT=10.50.1.20 REMOTE=203.0.113.10 PROTO=UDP STATE=REJECT"
    raw_event = EventEnvelope(raw_payload=sample_log)

    # Step 1: Initial parse attempts must fail and route to PENDING_AI
    success, processed = engine.parse_and_normalize(raw_event)
    assert success is False
    assert processed.status == EventStatus.PENDING_AI

    # Step 2: Register a validated dynamic parser
    parser_def = ParserDefinition(
        parser_id="edge_router_dynamic_v1",
        regex_pattern=r"CLIENT=(?P<client_ip>[^\s]+)\s+REMOTE=(?P<remote_ip>[^\s]+)\s+PROTO=(?P<proto>\w+)\s+STATE=(?P<state>\w+)",
        field_mappings={
            "src_ip": "client_ip",
            "dst_ip": "remote_ip",
            "proto": "proto",
            "action": "state"
        }
    )
    registry.register(parser_def)
    assert "edge_router_dynamic_v1" in registry.list_parsers()

    # Step 3: Re-execute without restart - must parse and commit directly into OCSF
    success_reload, processed_reload = engine.parse_and_normalize(raw_event)
    assert success_reload is True
    assert processed_reload.status == EventStatus.COMMITTED
    assert processed_reload.parser_id == "edge_router_dynamic_v1"
    assert processed_reload.ocsf_event.src_endpoint["ip"] == "10.50.1.20"
    assert processed_reload.ocsf_event.dst_endpoint["ip"] == "203.0.113.10"
    assert processed_reload.ocsf_event.disposition == "Blocked"


def test_dynamic_parser_disk_persistence(tmp_path):
    """Test that dynamic parsers serialize to disk and hydrate cleanly across cold boots."""
    storage_dir = str(tmp_path / "parsers")
    registry1 = DynamicParserRegistry(storage_dir=storage_dir)

    parser_def = ParserDefinition(
        parser_id="persisted_custom_v1",
        regex_pattern=r"HOST=(?P<host>[^\s]+)\s+VAL=(?P<val>\d+)",
        field_mappings={"src_ip": "host"}
    )
    assert registry1.register(parser_def) is True

    # Verify JSON file written to disk
    json_path = os.path.join(storage_dir, "persisted_custom_v1.json")
    assert os.path.exists(json_path)

    # Initialize a new registry instance simulating cold restart
    registry2 = DynamicParserRegistry(storage_dir=storage_dir)
    assert "persisted_custom_v1" in registry2.list_parsers()
    loaded_parser = registry2.get_parser("persisted_custom_v1")
    assert loaded_parser is not None
    assert loaded_parser.regex_pattern == parser_def.regex_pattern