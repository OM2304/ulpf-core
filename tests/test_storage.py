import os
import pytest
from ulpf.models import EventEnvelope, EventStatus, OCSFNetworkActivity
from ulpf.storage import NormalizedStorage

TEST_ANALYTICS_DB = "test_analytics_tmp.db"


@pytest.fixture
def storage_instance():
    if os.path.exists(TEST_ANALYTICS_DB):
        os.remove(TEST_ANALYTICS_DB)
    storage = NormalizedStorage(db_path=TEST_ANALYTICS_DB)
    yield storage
    if os.path.exists(TEST_ANALYTICS_DB):
        os.remove(TEST_ANALYTICS_DB)


def test_commit_valid_event(storage_instance):
    raw_log = "<134>Aug 30 12:41:22 fw01-edge src=10.2.1.15 dst=8.8.8.8 spt=51230 dpt=443 proto=TCP action=DENY"
    envelope = EventEnvelope(
        raw_payload=raw_log,
        status=EventStatus.COMMITTED,
        parser_id="builtin_firewall_kv_v1",
        parser_version="1.0.0",
        ocsf_event=OCSFNetworkActivity(
            action="DENY",
            disposition="Blocked",
            src_endpoint={"ip": "10.2.1.15", "port": 51230},
            dst_endpoint={"ip": "8.8.8.8", "port": 443},
            connection_info={"protocol_name": "TCP"}
        )
    )

    success = storage_instance.commit_event(envelope)
    assert success is True

    record = storage_instance.get_event_by_id(envelope.event_id)
    assert record is not None
    assert record["raw_sha256"] == envelope.raw_sha256
    assert record["src_ip"] == "10.2.1.15"
    assert record["disposition"] == "Blocked"
    assert record["parser_id"] == "builtin_firewall_kv_v1"


def test_reject_uncommitted_event(storage_instance):
    envelope = EventEnvelope(
        raw_payload="unknown log text",
        status=EventStatus.PENDING_AI
    )

    success = storage_instance.commit_event(envelope)
    assert success is False
    assert storage_instance.get_event_by_id(envelope.event_id) is None