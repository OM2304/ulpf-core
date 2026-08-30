from ulpf.models import EventEnvelope, EventStatus, OCSFNetworkActivity


def test_event_envelope_hash_generation():
    raw_log = "<134>Aug 30 12:41:22 fw01 src=10.0.0.1 dst=8.8.8.8 action=DENY"
    envelope = EventEnvelope(raw_payload=raw_log)

    assert envelope.raw_payload == raw_log
    assert len(envelope.raw_sha256) == 64
    assert envelope.status == EventStatus.RECEIVED
    assert envelope.event_id.startswith("ULPF-")


def test_ocsf_normalization_assignment():
    envelope = EventEnvelope(
        raw_payload="CEF:0|Vendor|Product|1.0|TRAFFIC|drop|1|src=1.1.1.1 dst=2.2.2.2",
        status=EventStatus.COMMITTED,
        parser_id="builtin_cef_v1",
        ocsf_event=OCSFNetworkActivity(
            action="drop",
            disposition="Blocked",
            src_endpoint={"ip": "1.1.1.1"},
            dst_endpoint={"ip": "2.2.2.2"}
        )
    )

    assert envelope.status == EventStatus.COMMITTED
    assert envelope.ocsf_event.class_uid == 4001
    assert envelope.ocsf_event.src_endpoint["ip"] == "1.1.1.1"