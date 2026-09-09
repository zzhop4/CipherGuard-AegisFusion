#!/usr/bin/env python3
"""Deterministic regression tests for the frozen ChainLens-QoA V2 graph."""
from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from research.chainlens.chainlens_qoa_v2 import (
    build_graph,
    normalize_alerts,
)


def frozen_selftest_alerts():
    return [
        {
            "alert_id": "a1",
            "timestamp": "2026-08-03T10:00:00",
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.20",
            "behavior": "scan_short_connection",
            "attack_stage": "discovery",
            "risk_score": 88,
            "detection_source": "cross_flow_realtime_rule",
            "evidence": ["scan"],
        },
        {
            "alert_id": "a2",
            "timestamp": "2026-08-03T10:00:20",
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.20",
            "behavior": "ssh_bruteforce",
            "attack_stage": "credential_access",
            "risk_score": 93,
            "detection_source": "metadata_behavior_rule",
            "packet_evidence": [{"packet": 1}],
        },
        {
            "alert_id": "a3",
            "timestamp": "2026-08-03T10:02:00",
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.20",
            "behavior": "bruteforce_post_action",
            "attack_stage": "post_compromise",
            "risk_score": 95,
            "detection_source": "cross_flow_post_bruteforce_correlation",
            "correlated_bruteforce_alert_ids": ["a2"],
            "model_evidence": {"family": "Infiltration"},
        },
        {
            "alert_id": "z1",
            "timestamp": "2026-08-03T10:20:00",
            "src_ip": "10.0.0.99",
            "dst_ip": "10.0.0.100",
            "behavior": "dos_syn_flood",
            "attack_stage": "impact",
            "risk_score": 96,
            "detection_source": "cross_flow_realtime_rule",
        },
    ]


def main():
    nodes = normalize_alerts(frozen_selftest_alerts())
    graph = build_graph(nodes)

    assert graph["schema_version"] == "chainlens-qoa-v2"
    assert graph["node_count"] == 4
    assert graph["chain_count"] == 2
    assert graph["edge_count"] == 3, graph["edges"]

    pair_edges = [
        edge for edge in graph["edges"]
        if edge["relation"] == "same_pair_temporal"
    ]
    explicit_edges = [
        edge for edge in graph["edges"]
        if edge["relation"] == "explicit_correlation"
    ]
    assert [(e["source"], e["target"]) for e in pair_edges] == [
        ("a1", "a2"),
        ("a2", "a3"),
    ]
    assert [(e["source"], e["target"]) for e in explicit_edges] == [
        ("a2", "a3")
    ]

    main_chain = next(
        chain for chain in graph["chains"]
        if chain["alert_ids"] == ["a1", "a2", "a3"]
    )
    isolated = next(
        chain for chain in graph["chains"]
        if chain["alert_ids"] == ["z1"]
    )

    assert main_chain["qoa"]["tier"] == "A"
    assert main_chain["qoa"]["explicit_edge_count"] == 1
    assert main_chain["qoa"]["pair_edge_count"] == 2
    assert main_chain["qoa"]["evidence_layer_count"] == 5
    assert main_chain["qoa"]["behavior_count"] == 3
    assert main_chain["qoa"]["stage_count"] == 3
    assert main_chain["qoa"]["temporal_span_seconds"] == 120.0
    assert isolated["qoa"]["tier"] == "D"

    same_pair = normalize_alerts([
        {
            "alert_id": "p%d" % index,
            "timestamp": 1000.0 + index * 10.0,
            "src_ip": "192.0.2.10",
            "dst_ip": "192.0.2.20",
            "behavior": "b%d" % index,
            "detection_source": "metadata_behavior_rule",
        }
        for index in range(4)
    ])
    sparse = build_graph(same_pair)
    assert sparse["edge_count"] == 3
    assert sparse["chain_count"] == 1

    weak_nodes = normalize_alerts([
        {
            "alert_id": "w1",
            "timestamp": 2000.0,
            "src_ip": "198.51.100.10",
            "dst_ip": "198.51.100.20",
            "behavior": "scan_short_connection",
            "detection_source": "cross_flow_realtime_rule",
        },
        {
            "alert_id": "w2",
            "timestamp": 2030.0,
            "src_ip": "198.51.100.10",
            "dst_ip": "198.51.100.30",
            "behavior": "scan_short_connection",
            "detection_source": "cross_flow_realtime_rule",
        },
    ])
    weak_graph = build_graph(weak_nodes)
    assert weak_graph["edge_count"] == 1
    assert weak_graph["edges"][0]["relation"] == "same_source_temporal"
    assert weak_graph["edges"][0]["component_edge"] is False
    assert weak_graph["chain_count"] == 2
    assert {chain["qoa"]["tier"] for chain in weak_graph["chains"]} == {"D"}

    future = normalize_alerts([
        {
            "alert_id": "f1",
            "timestamp": 3000.0,
            "src_ip": "203.0.113.10",
            "dst_ip": "203.0.113.20",
            "correlated_bruteforce_alert_ids": ["f2"],
        },
        {
            "alert_id": "f2",
            "timestamp": 3010.0,
            "src_ip": "203.0.113.30",
            "dst_ip": "203.0.113.40",
        },
    ])
    future_graph = build_graph(future)
    assert not any(
        edge["relation"] == "explicit_correlation"
        for edge in future_graph["edges"]
    )

    print("[OK] V2 nearest-predecessor sparsification")
    print("[OK] component connectivity and QoA A/D tiers")
    print("[OK] weak source context does not merge chains")
    print("[OK] future -> past explicit evidence rejected")
    print("CHAINLENS_QOA_V2_TEST_OK")


if __name__ == "__main__":
    main()
