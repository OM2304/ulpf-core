import json
import pytest
from ulpf.agent import ParserSynthesisAgent
from ulpf.models import EventEnvelope, EventStatus
from ulpf.registry import DynamicParserRegistry
from ulpf.engine import DeterministicEngine


def mock_successful_llm_response(prompt: str) -> str:
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
    return json.dumps({
        "regex_pattern": r"NON_EXISTENT_KEY=(?P<src>[^\s]+)",
        "field_mappings": {"src_ip": "src"}
    })


def test_agent_synthesis_and_registry_promotion():
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
    registry = DynamicParserRegistry()
    agent = ParserSynthesisAgent(registry=registry, llm_caller=mock_failing_llm_response)

    sample_logs = [
        "[EDGE_ROUTER_01] TS=2026-08-30T10:00:01Z CLIENT=10.50.1.20 REMOTE=203.0.113.10 PROTO=UDP STATE=REJECT"
    ]

    definition = agent.synthesize_and_onboard(
        parser_id="ai_broken_parser",
        sample_logs=sample_logs,
        max_attempts=1
    )

    assert definition is None
    assert "ai_broken_parser" not in registry.list_parsers()