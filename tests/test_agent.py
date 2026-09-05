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


class MockMultiFormatLLM:
    """Mock LLM that inspects prompt samples and generates appropriate regex for different log families."""

    def __call__(self, prompt: str) -> str:
        if "EDGE_ROUTER" in prompt:
            return json.dumps({
                "regex_pattern": r"CLIENT=(?P<client_ip>[^\s]+)\s+REMOTE=(?P<remote_ip>[^\s]+)\s+PROTO=(?P<proto>\w+)\s+STATE=(?P<state>\w+)",
                "field_mappings": {
                    "src_ip": "client_ip",
                    "dst_ip": "remote_ip",
                    "proto": "proto",
                    "action": "state"
                }
            })
        elif "SCADA_RTU" in prompt:
            return json.dumps({
                "regex_pattern": r"src=(?P<src_ip>[^\s]+)\s+dst=(?P<dst_ip>[^\s]+)\s+proto=(?P<proto>\w+)\s+status=(?P<status>\w+)",
                "field_mappings": {
                    "src_ip": "src_ip",
                    "dst_ip": "dst_ip",
                    "proto": "proto",
                    "action": "status"
                }
            })
        return json.dumps({
            "regex_pattern": r"(?P<src_ip>\d+\.\d+\.\d+\.\d+)",
            "field_mappings": {"src_ip": "src_ip"}
        })


def test_agent_synthesis_and_registry_promotion():
    """Test basic successful parser generation and hot-reload promotion."""
    registry = DynamicParserRegistry(storage_dir=None)
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
    registry = DynamicParserRegistry(storage_dir=None)
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
    registry = DynamicParserRegistry(storage_dir=None)
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

    envelope = EventEnvelope(raw_payload=sample_logs[0])
    success, processed = engine.parse_and_normalize(envelope)
    assert success is True
    assert processed.status == EventStatus.COMMITTED
    assert processed.ocsf_event.src_endpoint["ip"] == "192.168.10.5"
    assert processed.ocsf_event.disposition == "Blocked"


def test_agent_triage_pending_spool(tmp_path):
    """Test end-to-end triage: PENDING_AI spool items are clustered, parsed, and committed."""
    spool_db = str(tmp_path / "triage_spool.db")
    storage_db = str(tmp_path / "triage_storage.db")

    spool = DurableSpool(db_path=spool_db)
    storage = NormalizedStorage(db_path=storage_db)
    registry = DynamicParserRegistry(storage_dir=None)
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
    assert stats["clusters_detected"] == 1
    assert stats["onboarded_parsers"] == 1
    assert stats["committed"] == 1

    record = storage.get_event_by_id(env1.event_id)
    assert record is not None
    assert record["disposition"] == "Blocked"
    assert record["src_ip"] == "10.50.1.20"


def test_agent_triage_multi_format_clustering(tmp_path):
    """Test triage with mixed unknown formats: verifies distinct clusters synthesize distinct parsers."""
    spool_db = str(tmp_path / "multi_spool.db")
    storage_db = str(tmp_path / "multi_storage.db")

    spool = DurableSpool(db_path=spool_db)
    storage = NormalizedStorage(db_path=storage_db)
    registry = DynamicParserRegistry(storage_dir=None)
    engine = DeterministicEngine(registry=registry)

    mock_llm = MockMultiFormatLLM()
    agent = ParserSynthesisAgent(
        registry=registry,
        spool=spool,
        llm_caller=mock_llm
    )

    # Ingest 2 Router logs + 2 SCADA logs
    router_log = "[EDGE_ROUTER_01] CLIENT=10.50.1.20 REMOTE=203.0.113.10 PROTO=UDP STATE=REJECT"
    scada_log = "SCADA_RTU_08: dev=MODBUS src=10.10.1.5 dst=10.10.1.100 proto=TCP status=PERMIT"

    env_r = spool.persist_raw(payload=router_log)
    spool.update_status(env_r.event_id, EventStatus.PENDING_AI)

    env_s = spool.persist_raw(payload=scada_log)
    spool.update_status(env_s.event_id, EventStatus.PENDING_AI)

    stats = agent.triage_pending_spool(engine=engine, storage=storage, batch_size=10)

    assert stats["triaged"] == 2
    assert stats["clusters_detected"] == 2
    assert stats["onboarded_parsers"] == 2
    assert stats["committed"] == 2

    # Verify both records committed in analytical storage
    rec_r = storage.get_event_by_id(env_r.event_id)
    assert rec_r["src_ip"] == "10.50.1.20"
    assert rec_r["disposition"] == "Blocked"

    rec_s = storage.get_event_by_id(env_s.event_id)
    assert rec_s["src_ip"] == "10.10.1.5"
    assert rec_s["disposition"] == "Allowed"