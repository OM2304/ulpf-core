import os
import pytest
from ulpf.models import EventStatus
from ulpf.spool import DurableSpool

TEST_DB = "test_spool_tmp.db"


@pytest.fixture
def spool_instance():
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)
    spool = DurableSpool(db_path=TEST_DB)
    yield spool
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)


def test_durable_spool_persistence(spool_instance):
    raw_log = "<134>Aug 30 12:41:22 fw01-edge src=10.2.1.15 dst=8.8.8.8 action=DENY"
    envelope = spool_instance.persist_raw(payload=raw_log, transport="syslog_udp")

    assert envelope.status == EventStatus.DURABLY_STORED
    assert len(envelope.raw_sha256) == 64

    pending = spool_instance.fetch_pending(limit=10)
    assert len(pending) == 1
    assert pending[0].event_id == envelope.event_id
    assert pending[0].raw_payload == raw_log


def test_durable_spool_status_update(spool_instance):
    raw_log = "CEF:0|Vendor|Product|1.0|TRAFFIC|drop|1|src=1.1.1.1 dst=2.2.2.2"
    envelope = spool_instance.persist_raw(payload=raw_log)

    spool_instance.update_status(envelope.event_id, EventStatus.COMMITTED)
    pending = spool_instance.fetch_pending(limit=10)
    assert len(pending) == 0


def test_crash_recovery_across_restarts(spool_instance):
    raw_log = "[EDGE_ROUTER_01] CLIENT=10.50.1.20 REMOTE=203.0.113.10 STATE=REJECT"
    envelope = spool_instance.persist_raw(payload=raw_log)

    new_spool_session = DurableSpool(db_path=TEST_DB)
    recovered_events = new_spool_session.fetch_pending(limit=10)

    assert len(recovered_events) == 1
    assert recovered_events[0].event_id == envelope.event_id
    assert recovered_events[0].raw_sha256 == envelope.raw_sha256