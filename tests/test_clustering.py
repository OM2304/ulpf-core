import pytest
from ulpf.clustering import (
    cluster_unrecognized_events,
    compute_skeleton_fingerprint,
    extract_structural_skeleton,
)
from ulpf.models import EventEnvelope, EventStatus


def test_structural_skeleton_extraction():
    """Verify variable tokens are masked while structure and keys are preserved."""
    sample = "[EDGE_ROUTER_01] TS=2026-08-30T10:00:01Z CLIENT=10.50.1.20 REMOTE=203.0.113.10 PROTO=UDP STATE=REJECT"
    skeleton = extract_structural_skeleton(sample)

    assert "<VAL>" in skeleton
    assert "10.50.1.20" not in skeleton
    assert "2026-08-30" not in skeleton
    assert "CLIENT=" in skeleton
    assert "REMOTE=" in skeleton
    assert "[EDGE_ROUTER_01]" in skeleton


def test_clustering_groups_homogeneous_formats():
    """Verify different records with the same format produce the same cluster ID."""
    log1 = "[EDGE_ROUTER_01] TS=2026-08-30T10:00:01Z CLIENT=10.50.1.20 REMOTE=203.0.113.10 PROTO=UDP STATE=REJECT"
    log2 = "[EDGE_ROUTER_01] TS=2026-08-30T10:00:04Z CLIENT=172.16.88.4 REMOTE=1.0.0.1 PROTO=TCP STATE=ACCEPT"

    sk1 = extract_structural_skeleton(log1)
    sk2 = extract_structural_skeleton(log2)
    assert sk1 == sk2

    fp1 = compute_skeleton_fingerprint(sk1)
    fp2 = compute_skeleton_fingerprint(sk2)
    assert fp1 == fp2


def test_clustering_partitions_heterogeneous_formats():
    """Verify distinct log formats are cleanly split into separate clusters."""
    events = [
        EventEnvelope(raw_payload="[ROUTER] TS=2026-08-30 CLIENT=10.0.0.1 REMOTE=8.8.8.8 PROTO=TCP STATE=ALLOW"),
        EventEnvelope(raw_payload="[ROUTER] TS=2026-08-30 CLIENT=10.0.0.2 REMOTE=1.1.1.1 PROTO=UDP STATE=DENY"),
        EventEnvelope(raw_payload="%ASA-4-106023: Deny udp src outside:192.0.2.1/1052 dst inside:198.51.100.4/53 by access-group"),
        EventEnvelope(raw_payload="SCADA_RTU_08: dev=MODBUS cmd=READ src=10.10.1.5 dst=10.10.1.100 proto=TCP status=PERMIT")
    ]

    clusters = cluster_unrecognized_events(events)

    # Must produce 3 distinct clusters
    assert len(clusters) == 3

    # First cluster must be the router with count=2
    assert clusters[0].sample_count == 2
    assert "[ROUTER]" in clusters[0].skeleton