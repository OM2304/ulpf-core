import os
import pytest
from ulpf.coordinator import PipelineCoordinator
from ulpf.engine import DeterministicEngine
from ulpf.models import EventStatus
from ulpf.spool import DurableSpool
from ulpf.storage import NormalizedStorage

TEST_SPOOL_DB = "test_coord_spool.db"
TEST_STORAGE_DB = "test_coord_storage.db"


@pytest.fixture
def coordinator_instance():
    for f in [TEST_SPOOL_DB, TEST_STORAGE_DB]:
        if os.path.exists(f):
            os.remove(f)

    spool = DurableSpool(db_path=TEST_SPOOL_DB)
    engine = DeterministicEngine()
    storage = NormalizedStorage(db_path=TEST_STORAGE_DB)
    coordinator = PipelineCoordinator(spool=spool, engine=engine, storage=storage)

    yield coordinator, spool, storage

    for f in [TEST_SPOOL_DB, TEST_STORAGE_DB]:
        if os.path.exists(f):
            os.remove(f)


def test_end_to_end_batch_processing(coordinator_instance):
    coordinator, spool, storage = coordinator_instance

    sample_logs = [
        # Known Format 1: Firewall KV
        "<134>Aug 30 12:41:22 fw01-edge src=10.2.1.15 dst=8.8.8.8 spt=51230 dpt=443 proto=TCP action=DENY",
        # Known Format 2: Palo Alto CEF
        "CEF:0|Palo Alto Networks|PAN-OS|10.0|TRAFFIC|allow|1|src=172.20.10.4 dst=198.51.100.2 spt=445 dpt=445 proto=tcp act=allow",
        # Known Format 3: Linux Auth Syslog
        "Jan 18 06:12:01 edge-auth-01 sshd[2412]: Failed password for invalid user admin from 192.168.1.105 port 54212 ssh2",
        # Unknown Format: Proprietary Router Log
        "[EDGE_ROUTER_01] TS=2026-08-30T10:00:01Z CLIENT=10.50.1.20 REMOTE=203.0.113.10 PROTO=UDP STATE=REJECT",
    ]

    # 1. Ingest all logs
    envelopes = [coordinator.ingest_raw_event(log) for log in sample_logs]
    assert len(envelopes) == 4

    # 2. Process batch
    stats = coordinator.process_pending_batch(batch_size=10)
    assert stats["processed"] == 4
    assert stats["committed"] == 3
    assert stats["pending_ai"] == 1

    # 3. Verify committed events in analytical storage
    for env in envelopes[:3]:
        record = storage.get_event_by_id(env.event_id)
        assert record is not None
        assert record["raw_sha256"] == env.raw_sha256
        assert record["raw_payload"] == env.raw_payload

    # 4. Verify unknown event is safely retained in spool as PENDING_AI without data loss[cite: 1]
    unknown_env = envelopes[3]
    unknown_in_storage = storage.get_event_by_id(unknown_env.event_id)
    assert unknown_in_storage is None  # Not prematurely committed to analytics

    pending_events = spool.fetch_pending(limit=10)
    assert len(pending_events) == 0  # No longer in generic pending status