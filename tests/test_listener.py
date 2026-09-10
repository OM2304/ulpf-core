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


def test_path_ingest_endpoint(tmp_path):
    """Test HTTP POST /api/v1/ingest/path with temporary log file."""
    from ulpf.listener import app
    test_log_file = tmp_path / "test_ingest.log"
    test_log_file.write_text(
        "CEF:0|Palo Alto Networks|PAN-OS|10.0|TRAFFIC|allow|1|src=10.0.0.5 dst=8.8.8.8 spt=53 dpt=53 proto=udp act=allow\n"
        "sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 2222 ssh2\n"
    )

    with TestClient(app) as client:
        # Test valid path
        res = client.post("/api/v1/ingest/path", json={"path": str(test_log_file)})
        assert res.status_code == 201
        data = res.json()
        assert data["status"] == "success"
        assert data["total_ingested"] == 2

        # Test non-existent path
        res_404 = client.post("/api/v1/ingest/path", json={"path": "C:\\non_existent_file_path.log"})
        assert res_404.status_code == 404


def test_parsers_endpoints(tmp_path):
    """Test GET /api/v1/parsers and DELETE /api/v1/parsers/{parser_id}."""
    import json
    from ulpf.listener import app

    with TestClient(app) as client:
        # 1. Test GET /api/v1/parsers
        res = client.get("/api/v1/parsers")
        assert res.status_code == 200
        parsers = res.json()
        assert isinstance(parsers, list)
        assert len(parsers) > 0

        # Verify core parsers exist and are marked correctly
        core_parsers = [p for p in parsers if p.get("parser_type") == "core"]
        assert len(core_parsers) > 0
        for cp in core_parsers:
            assert cp.get("read_only") is True
            assert cp.get("deletable") is False

        # Verify generated parsers have deletable=True
        gen_parsers = [p for p in parsers if p.get("parser_type") == "generated"]
        for gp in gen_parsers:
            assert gp.get("deletable") is True
            assert gp.get("read_only") is False

        # 2. Test DELETE core parser returns 403 Forbidden
        first_core_id = core_parsers[0]["parser_id"]
        res_core_del = client.delete(f"/api/v1/parsers/{first_core_id}")
        assert res_core_del.status_code == 403

        # 3. Create dummy generated parser, verify delete works
        gen_dir = os.path.join(os.path.dirname(__file__), "..", "ulpf", "parsers", "generated")
        dummy_id = "test_dummy_generated_v1"
        dummy_file = os.path.join(gen_dir, f"{dummy_id}.json")
        with open(dummy_file, "w", encoding="utf-8") as f:
            json.dump({
                "parser_id": dummy_id,
                "parser_version": "1.0.0",
                "description": "Test dummy parser",
                "regex_pattern": r"test:\s+(?P<val>\w+)",
                "field_mappings": {"val": "test_val"}
            }, f)

        try:
            # Confirm it shows in GET
            res_after_add = client.get("/api/v1/parsers")
            assert any(p["parser_id"] == dummy_id for p in res_after_add.json())

            # Delete generated parser
            del_res = client.delete(f"/api/v1/parsers/{dummy_id}")
            assert del_res.status_code == 200
            assert del_res.json()["status"] == "success"
            assert not os.path.exists(dummy_file)

            # Confirm 404 when deleting again
            del_res_404 = client.delete(f"/api/v1/parsers/{dummy_id}")
            assert del_res_404.status_code == 404
        finally:
            if os.path.exists(dummy_file):
                os.remove(dummy_file)
