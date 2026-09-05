import json
import pytest
from ulpf.agent import ParserSynthesisAgent
from ulpf.engine import DeterministicEngine
from ulpf.models import EventEnvelope, EventStatus
from ulpf.registry import DynamicParserRegistry
from ulpf.spool import DurableSpool
from ulpf.storage import NormalizedStorage


def mock_successful_llm_response(prompt: str) -> str:
    """Mock LLM returning valid named capture regex on first try."""
    return json.dumps({
        "regex_pattern": r"CLIENT=(?P<client_ip>[^\s]+)\s+REMOTE=(?P<remote_ip>[^\s]+)\s+PROTO=(?P<proto>\w+)\s+STATE=(?P<state>\w+)",
        "field_mappings": {
            "src_ip": "client_ip",
            "dst_ip": "remote_ip",
            "proto": "proto",
            "action": "state"
        }
    })


def mock_failing_llm_response(prompt: str) -> str:
    """Mock LLM returning non-matching regex."""
    return json.dumps({
        "regex_pattern": r"NON_EXISTENT_KEY=(?P<src>[^\s]+)",
        "field_mappings": {"src_ip": "src"}
    })


class MockReflectingLLM:
    """Stateful mock that fails on attempt 1 with a broken pattern, then fixes itself upon reflection."""

    def __init__(self):
        self.call_count = 0

    def __call__(self, prompt: str) -> str:
        self.call_count += 1
        if self.call_count == 1:
            # Attempt 1: Fails matching
            return json.dumps({
                "regex_pattern": r"INVALID_HEADER=(?P<src>[^\s]+)",
                "field_mappings": {"src_ip": "src"}
            })
        else:
            # Attempt 2: Self-corrected regex based on reflection prompt feedback
            return json.dumps({
                "regex_pattern": r"SRC=(?P<src_ip>[^\s]+)\s+DEST=(?P<dst_ip>[^\s]+)\s+PROTOCOL=(?P<proto>\w+)\s+VERDICT=(?P<verdict>\w+)",
                "field_mappings": {
                    "src_ip": "src_ip",
                    "dst_ip": "dst_ip",
                    "proto": "proto",
                    "action": "verdict"
                }
            })


def test_agent_synthesis_and_registry_promotion():
    """Test basic successful parser generation and hot-reload promotion."""
    registry = DynamicParserRegistry()
    engine = DeterministicEngine(registry=registry)
    agent = ParserSynthesisAgent(registry=registry, llm_caller=mock_successful_llm_response)

    sample_logs = [
        "[EDGE_ROUTER_01] TS=2026-08-30T10:00:01Z CLIENT=10.50.1.20 REMOTE=203.0.113.10 PROTO=UDP STATE=REJECT",
        "[EDGE_ROUTER_01] TS=2026-08-30T10:00:04Z CLIENT=172.16.88.4 REMOTE=1.0.0.1 PROTO=TCP STATE=ACCEPT"
    ]

    definition = agent.synthesize_and_onboard(
        parser_id="ai_edge_router_v1",
        sample_logs=sample_logs
    )

    assert definition is not None
    assert definition.parser_id == "ai_edge_router_v1"
    assert "ai_edge_router_v1" in registry.list_parsers()

    # Verify live engine handles the log without restarts
    envelope = EventEnvelope(raw_payload=sample_logs[0])
    success, processed = engine.parse_and_normalize(envelope)

    assert success is True
    assert processed.status == EventStatus.COMMITTED
    assert processed.parser_id == "ai_edge_router_v1"
    assert processed.ocsf_event.src_endpoint["ip"] == "10.50.1.20"
    assert processed.ocsf_event.dst_endpoint["ip"] == "203.0.113.10"
    assert processed.ocsf_event.disposition == "Blocked"


def test_agent_rejects_invalid_synthesis():
    """Test that failed synthesis attempts do not register broken parsers."""
    registry = DynamicParserRegistry()
    agent = ParserSynthesisAgent(registry=registry, llm_caller=mock_failing_llm_response)

    sample_logs = [
        "[EDGE_ROUTER_01] TS=2026-08-30T10:00:01Z CLIENT=10.50.1.20 REMOTE=203.0.113.10 PROTO=UDP STATE=REJECT"
    ]

    definition = agent.synthesize_and_onboard(
        parser_id="ai_broken_parser",
        sample_logs=sample_logs,
        max_attempts=2
    )

    assert definition is None
    assert "ai_broken_parser" not in registry.list_parsers()


def test_agent_self_correction_reflection_loop():
    """Test Reflexion loop: LLM fails on attempt 1, reflects on error, and succeeds on attempt 2."""
    registry = DynamicParserRegistry()
    engine = DeterministicEngine(registry=registry)
    mock_llm = MockReflectingLLM()
    agent = ParserSynthesisAgent(registry=registry, llm_caller=mock_llm)

    sample_logs = [
        "[CUSTOM_SENSOR] SRC=192.168.10.5 DEST=8.8.8.8 PROTOCOL=TCP VERDICT=DENY",
        "[CUSTOM_SENSOR] SRC=10.0.0.1 DEST=1.1.1.1 PROTOCOL=UDP VERDICT=PASS"
    ]

    definition = agent.synthesize_and_onboard(
        parser_id="ai_custom_sensor_v1",
        sample_logs=sample_logs,
        max_attempts=3
    )

    assert mock_llm.call_count == 2
    assert definition is not None
    assert definition.parser_id == "ai_custom_sensor_v1"

    # Verify live engine handles the log with the corrected parser
    envelope = EventEnvelope(raw_payload=sample_logs[0])
    success, processed = engine.parse_and_normalize(envelope)
    assert success is True
    assert processed.status == EventStatus.COMMITTED
    assert processed.ocsf_event.src_endpoint["ip"] == "192.168.10.5"
    assert processed.ocsf_event.disposition == "Blocked"


def test_agent_triage_pending_spool(tmp_path):
    """Test end-to-end triage: PENDING_AI spool items are parsed, resolved, and committed."""
    spool_db = str(tmp_path / "triage_spool.db")
    storage_db = str(tmp_path / "triage_storage.db")

    spool = DurableSpool(db_path=spool_db)
    storage = NormalizedStorage(db_path=storage_db)
    registry = DynamicParserRegistry()
    engine = DeterministicEngine(registry=registry)

    agent = ParserSynthesisAgent(
        registry=registry,
        spool=spool,
        llm_caller=mock_successful_llm_response
    )

    # Ingest unknown logs and flag as PENDING_AI
    raw_sample = "[EDGE_ROUTER_01] CLIENT=10.50.1.20 REMOTE=203.0.113.10 PROTO=UDP STATE=REJECT"
    env1 = spool.persist_raw(payload=raw_sample)
    spool.update_status(env1.event_id, EventStatus.PENDING_AI)

    # Run spool triage
    stats = agent.triage_pending_spool(engine=engine, storage=storage, batch_size=10)

    assert stats["triaged"] == 1
    assert stats["onboarded_parsers"] == 1
    assert stats["committed"] == 1

    # Verify event is now committed in analytics storage
    record = storage.get_event_by_id(env1.event_id)
    assert record is not None
    assert record["disposition"] == "Blocked"
    assert record["src_ip"] == "10.50.1.20"