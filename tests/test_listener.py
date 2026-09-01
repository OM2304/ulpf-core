import asyncio
import os
import pytest
from fastapi.testclient import TestClient
from ulpf.coordinator import PipelineCoordinator
from ulpf.engine import DeterministicEngine
from ulpf.listener import SyslogUDPProtocol, create_app, start_udp_syslog_server
from ulpf.spool import DurableSpool
from ulpf.storage import NormalizedStorage

TEST_LISTENER_SPOOL = "test_listener_spool.db"
TEST_LISTENER_STORAGE = "test_listener_storage.db"


@pytest.fixture
def test_setup():
    """Setup and teardown isolated SQLite databases for HTTP listener testing."""
    for f in [TEST_LISTENER_SPOOL, TEST_LISTENER_STORAGE]:
        if os.path.exists(f):
            os.remove(f)

    spool = DurableSpool(db_path=TEST_LISTENER_SPOOL)
    engine = DeterministicEngine()
    storage = NormalizedStorage(db_path=TEST_LISTENER_STORAGE)
    coordinator = PipelineCoordinator(spool=spool, engine=engine, storage=storage)
    app = create_app(coordinator)
    client = TestClient(app)

    yield coordinator, client, spool

    for f in [TEST_LISTENER_SPOOL, TEST_LISTENER_STORAGE]:
        if os.path.exists(f):
            os.remove(f)


def test_http_batch_ingestion_and_processing(test_setup):
    """Test HTTP API log batch ingestion, batch processing trigger, and storage query."""
    coordinator, client, spool = test_setup

    payload = {
        "logs": [
            "<134>Aug 30 12:41:22 fw01 src=10.0.0.1 dst=8.8.8.8 spt=1234 dpt=53 proto=UDP action=ALLOW",
            "CEF:0|Palo Alto Networks|PAN-OS|10.0|TRAFFIC|deny|1|src=192.168.1.1 dst=10.0.0.2 spt=80 dpt=80 proto=tcp act=deny"
        ],
        "source_transport": "http_api"
    }

    # 1. Post batch to HTTP endpoint
    response = client.post("/api/v1/ingest", json=payload)
    assert response.status_code == 202
    data = response.json()
    assert data["ingested_count"] == 2

    # 2. Trigger batch processing via API
    proc_response = client.post("/api/v1/process-batch?batch_size=10")
    assert proc_response.status_code == 200
    stats = proc_response.json()["stats"]
    assert stats["processed"] == 2
    assert stats["committed"] == 2

    # 3. Query analytical storage via API
    first_event_id = data["events"][0]["event_id"]
    event_response = client.get(f"/api/v1/events/{first_event_id}")
    assert event_response.status_code == 200
    assert event_response.json()["disposition"] == "Allowed"


@pytest.mark.anyio
async def test_udp_syslog_ingestion():
    """Test asynchronous UDP Syslog listener packet ingestion into durable spool."""
    spool_db = "test_udp_tmp.db"
    storage_db = "test_udp_storage.db"
    for f in [spool_db, storage_db]:
        if os.path.exists(f):
            os.remove(f)

    spool = DurableSpool(db_path=spool_db)
    coordinator = PipelineCoordinator(
        spool=spool,
        engine=DeterministicEngine(),
        storage=NormalizedStorage(storage_db)
    )

    # 1. Verify asynchronous UDP socket server startup and teardown lifecycle
    transport = await start_udp_syslog_server(coordinator, host="127.0.0.1", port=0)
    assert transport is not None
    sockname = transport.get_extra_info("sockname")
    assert sockname[1] > 0
    transport.close()

    # 2. Verify SyslogUDPProtocol ingestion directly into durable spool
    protocol = SyslogUDPProtocol(coordinator)
    raw_packet = b"<134>Aug 30 12:41:22 fw01 src=1.2.3.4 dst=5.6.7.8 spt=1 dpt=2 proto=TCP action=DENY"
    protocol.datagram_received(raw_packet, ("127.0.0.1", 514))

    # 3. Verify event is durably spooled with exact payload and metadata
    pending = spool.fetch_pending(limit=5)
    assert len(pending) == 1
    assert "src=1.2.3.4" in pending[0].raw_payload
    assert pending[0].source_transport == "syslog_udp"

    for f in [spool_db, storage_db]:
        if os.path.exists(f):
            os.remove(f)