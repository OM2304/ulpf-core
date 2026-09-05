import asyncio
import json
import os
import pytest
from ulpf.agent import ParserSynthesisAgent
from ulpf.agent_worker import AgentWorker
from ulpf.engine import DeterministicEngine
from ulpf.models import EventEnvelope, EventStatus
from ulpf.registry import DynamicParserRegistry
from ulpf.spool import DurableSpool
from ulpf.storage import NormalizedStorage


def mock_llm_responder(prompt: str) -> str:
    """Mock LLM generating valid regex for sensor format."""
    return json.dumps({
        "regex_pattern": r"SENSOR=(?P<sensor>\w+)\s+SRC=(?P<src_ip>[^\s]+)\s+DST=(?P<dst_ip>[^\s]+)\s+STATUS=(?P<status>\w+)",
        "field_mappings": {
            "src_ip": "src_ip",
            "dst_ip": "dst_ip",
            "proto": "sensor",
            "action": "status"
        }
    })


def test_worker_single_step(tmp_path):
    """Test process_once execution on queued spool events."""
    spool_db = str(tmp_path / "worker_spool.db")
    storage_db = str(tmp_path / "worker_storage.db")

    spool = DurableSpool(db_path=spool_db)
    storage = NormalizedStorage(db_path=storage_db)
    registry = DynamicParserRegistry(storage_dir=None)
    engine = DeterministicEngine(registry=registry)
    agent = ParserSynthesisAgent(registry=registry, spool=spool, llm_caller=mock_llm_responder)

    worker = AgentWorker(
        spool=spool,
        storage=storage,
        registry=registry,
        engine=engine,
        agent=agent,
        poll_interval=0.05
    )

    # Ingest 2 unrecognized logs flagged as PENDING_AI
    raw_log = "SENSOR=TEMP01 SRC=192.168.1.100 DST=10.0.0.50 STATUS=ALLOW"
    env1 = spool.persist_raw(payload=raw_log)
    spool.update_status(env1.event_id, EventStatus.PENDING_AI)

    stats = worker.process_once()

    assert stats["triaged"] == 1
    assert stats["onboarded_parsers"] == 1
    assert stats["committed"] == 1
    assert worker.total_triaged == 1
    assert worker.total_committed == 1


@pytest.mark.anyio
async def test_worker_async_lifecycle():
    """Test starting, polling, and gracefully stopping the async daemon loop."""
    registry = DynamicParserRegistry(storage_dir=None)
    agent = ParserSynthesisAgent(registry=registry, llm_caller=mock_llm_responder)

    worker = AgentWorker(registry=registry, agent=agent, poll_interval=0.02)

    task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.08)

    assert worker.is_running is True
    worker.stop()
    await task
    assert worker.is_running is False


@pytest.mark.anyio
async def test_worker_e2e_autonomous_triage(tmp_path):
    """Test background worker automatically polling and draining newly arriving logs."""
    spool_db = str(tmp_path / "e2e_spool.db")
    storage_db = str(tmp_path / "e2e_storage.db")

    spool = DurableSpool(db_path=spool_db)
    storage = NormalizedStorage(db_path=storage_db)
    registry = DynamicParserRegistry(storage_dir=None)
    engine = DeterministicEngine(registry=registry)
    agent = ParserSynthesisAgent(registry=registry, spool=spool, llm_caller=mock_llm_responder)

    worker = AgentWorker(
        spool=spool,
        storage=storage,
        registry=registry,
        engine=engine,
        agent=agent,
        poll_interval=0.03
    )

    # Start worker background task
    worker_task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.05)

    # Simulate arrival of unknown logs while worker is active
    raw_log = "SENSOR=PRESSURE02 SRC=172.16.0.4 DST=8.8.4.4 STATUS=DENY"
    env = spool.persist_raw(payload=raw_log)
    spool.update_status(env.event_id, EventStatus.PENDING_AI)

    # Allow worker to poll and process
    for _ in range(20):
        await asyncio.sleep(0.03)
        if worker.total_committed >= 1:
            break

    worker.stop()
    await worker_task

    assert worker.total_committed == 1
    rec = storage.get_event_by_id(env.event_id)
    assert rec is not None
    assert rec["src_ip"] == "172.16.0.4"
    assert rec["disposition"] == "Blocked"