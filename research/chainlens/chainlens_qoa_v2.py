#!/usr/bin/env python3
"""ChainLens-QoA V2: sparse causal attribution graph construction.

This module is a portable reconstruction of the frozen competition research
script. ChainLens is an attribution/organization layer, not an attack detector
and not an attack probability.

V2 inherits the V1 normalization, component and QoA rules. Its only algorithmic
change is causal-edge sparsification:

- preserve every valid explicit prior-alert reference;
- for the same src/dst pair, connect only the nearest previous alert (<=600 s);
- for the same source but a different destination, keep only the nearest
  previous alert (<=120 s) as weak visual context;
- weak same-source context never merges components.

No payload text or decrypted content is used. IP addresses and ports are only
correlation keys in this attribution layer and are never model features here.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


def parse_time(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)

    text = str(value).strip()
    try:
        return float(text)
    except Exception:
        pass

    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except Exception:
        return None


def evidence_layers(alert: dict[str, Any]) -> list[str]:
    layers: set[str] = set()
    source = str(alert.get("detection_source") or "").lower()

    if alert.get("model_evidence"):
        layers.add("MODEL")
    if alert.get("packet_evidence"):
        layers.add("PACKET")
    if alert.get("rule_hits"):
        layers.add("PACKET_RULE")
    if "cross_flow" in source:
        layers.add("CROSS_FLOW")
    if "metadata" in source or "behavior_rule" in source:
        layers.add("METADATA_RULE")
    if "model" in source or "aegisfusion" in source:
        layers.add("MODEL")
    if alert.get("correlated_bruteforce_alert_ids"):
        layers.add("EXPLICIT_CORRELATION")
    if not layers:
        layers.add("UNSPECIFIED")
    return sorted(layers)


def normalize_alert(alert: dict[str, Any], fallback_id: str) -> dict[str, Any]:
    value = dict(alert)
    alert_id = value.get("alert_id") or fallback_id
    return {
        "id": str(alert_id),
        "alert_id": str(alert_id),
        "flow_id": value.get("flow_id"),
        "timestamp": value.get("timestamp"),
        "_ts": parse_time(value.get("timestamp")),
        "src_ip": value.get("src_ip"),
        "dst_ip": value.get("dst_ip"),
        "src_port": value.get("src_port"),
        "dst_port": value.get("dst_port"),
        "behavior": value.get("behavior"),
        "attack_stage": value.get("attack_stage"),
        "risk_score": float(value.get("risk_score") or 0.0),
        "detection_source": value.get("detection_source"),
        "evidence_layers": evidence_layers(value),
        "evidence": list(value.get("evidence") or []),
        "explicit_prior_alert_ids": [
            str(item)
            for item in (value.get("correlated_bruteforce_alert_ids") or [])
            if item is not None
        ],
    }


def extract_alerts_object(obj: Any) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []

    if isinstance(obj, list):
        for item in obj:
            if isinstance(item, dict):
                alerts.append(item)
        return alerts

    if not isinstance(obj, dict):
        return alerts

    if isinstance(obj.get("alerts"), list):
        alerts.extend(item for item in obj["alerts"] if isinstance(item, dict))

    result = obj.get("result")
    if isinstance(result, dict) and isinstance(result.get("alerts"), list):
        alerts.extend(
            item for item in result["alerts"] if isinstance(item, dict)
        )

    payload = obj.get("payload")
    if isinstance(payload, dict):
        if obj.get("event_type") == "alert":
            alerts.append(payload)
        if isinstance(payload.get("alerts"), list):
            alerts.extend(
                item for item in payload["alerts"] if isinstance(item, dict)
            )
        payload_result = payload.get("result")
        if (
            isinstance(payload_result, dict)
            and isinstance(payload_result.get("alerts"), list)
        ):
            alerts.extend(
                item
                for item in payload_result["alerts"]
                if isinstance(item, dict)
            )

    single_alert = obj.get("alert")
    if isinstance(single_alert, dict):
        alerts.append(single_alert)

    return alerts


def normalize_alerts(alerts: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()

    for index, alert in enumerate(alerts, start=1):
        node = normalize_alert(alert, "chainlens_alert_%08d" % index)
        key = node["alert_id"]
        if key in seen:
            continue
        seen.add(key)
        normalized.append(node)

    normalized.sort(
        key=lambda item: (
            item["_ts"] is None,
            item["_ts"] or 0.0,
            item["alert_id"],
        )
    )
    return normalized


def load_alerts(path: str | Path) -> list[dict[str, Any]]:
    path = Path(path)
    alerts: list[dict[str, Any]] = []

    if path.suffix.lower() == ".jsonl":
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                alerts.extend(extract_alerts_object(obj))
    else:
        obj = json.load(path.open("r", encoding="utf-8"))
        alerts.extend(extract_alerts_object(obj))

    return normalize_alerts(alerts)


def add_edge(
    edges: list[dict[str, Any]],
    seen: set[tuple[str, str, str]],
    src: str,
    dst: str,
    relation: str,
    strength: str,
    delta_seconds: float | None,
    component_edge: bool,
) -> None:
    key = (src, dst, relation)
    if key in seen:
        return
    seen.add(key)
    edges.append(
        {
            "source": src,
            "target": dst,
            "relation": relation,
            "strength": strength,
            "delta_seconds": (
                None
                if delta_seconds is None
                else round(float(delta_seconds), 6)
            ),
            "component_edge": bool(component_edge),
        }
    )


def build_edges(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build the frozen V2 sparse causal backbone."""
    edges: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    by_id = {node["alert_id"]: node for node in nodes}

    # 1. Preserve every valid explicit product-provided prior-alert reference.
    for current in nodes:
        for prior_id in current["explicit_prior_alert_ids"]:
            prior = by_id.get(prior_id)
            if prior is None:
                continue
            if (
                prior["_ts"] is not None
                and current["_ts"] is not None
                and prior["_ts"] > current["_ts"]
            ):
                # Never create future -> past evidence.
                continue

            delta = None
            if prior["_ts"] is not None and current["_ts"] is not None:
                delta = current["_ts"] - prior["_ts"]

            add_edge(
                edges,
                seen,
                prior["id"],
                current["id"],
                "explicit_correlation",
                "strong",
                delta,
                True,
            )

    # 2. Sparse causal backbone: nearest previous alert only.
    last_pair: dict[tuple[str, str], dict[str, Any]] = {}
    last_source: dict[str, dict[str, Any]] = {}

    for current in nodes:
        timestamp = current["_ts"]
        if timestamp is None:
            continue

        src = current.get("src_ip")
        dst = current.get("dst_ip")
        pair = (src, dst)

        if src and dst:
            prior = last_pair.get(pair)
            if prior is not None:
                delta = timestamp - prior["_ts"]
                if 0 <= delta <= 600.0:
                    add_edge(
                        edges,
                        seen,
                        prior["id"],
                        current["id"],
                        "same_pair_temporal",
                        "medium",
                        delta,
                        True,
                    )
            last_pair[pair] = current

        if src:
            prior = last_source.get(src)
            if prior is not None:
                same_pair = prior.get("dst_ip") == dst
                delta = timestamp - prior["_ts"]
                if not same_pair and 0 <= delta <= 120.0:
                    add_edge(
                        edges,
                        seen,
                        prior["id"],
                        current["id"],
                        "same_source_temporal",
                        "weak",
                        delta,
                        False,
                    )
            last_source[src] = current

    return edges


def components(
    nodes: list[dict[str, Any]], edges: list[dict[str, Any]]
) -> list[list[str]]:
    parent = {node["id"]: node["id"] for node in nodes}

    def find(value: str) -> str:
        while parent[value] != value:
            parent[value] = parent[parent[value]]
            value = parent[value]
        return value

    def union(left: str, right: str) -> None:
        root_left = find(left)
        root_right = find(right)
        if root_left != root_right:
            parent[root_right] = root_left

    for edge in edges:
        if edge["component_edge"]:
            union(edge["source"], edge["target"])

    groups: dict[str, list[str]] = {}
    for node in nodes:
        groups.setdefault(find(node["id"]), []).append(node["id"])
    return list(groups.values())


def qoa_profile(
    component: list[str],
    node_map: dict[str, dict[str, Any]],
    edges: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compute the frozen deterministic Quality-of-Attribution profile.

    QoA tiers are ordinal evidence-quality labels, not probabilities.
    """
    ids = set(component)
    component_edges = [
        edge
        for edge in edges
        if edge["source"] in ids and edge["target"] in ids
    ]

    explicit = sum(
        edge["relation"] == "explicit_correlation" for edge in component_edges
    )
    pair = sum(
        edge["relation"] == "same_pair_temporal" for edge in component_edges
    )
    weak = sum(
        edge["relation"] == "same_source_temporal" for edge in component_edges
    )

    layers: set[str] = set()
    behaviors: set[str] = set()
    stages: set[str] = set()
    timestamps: list[float] = []

    for alert_id in component:
        node = node_map[alert_id]
        layers.update(node["evidence_layers"])
        if node.get("behavior"):
            behaviors.add(node["behavior"])
        if node.get("attack_stage"):
            stages.add(node["attack_stage"])
        if node["_ts"] is not None:
            timestamps.append(node["_ts"])

    span = (
        max(timestamps) - min(timestamps) if len(timestamps) >= 2 else 0.0
    )

    if explicit >= 1 and len(layers) >= 2:
        tier = "A"
    elif explicit >= 1 or (
        pair >= 1 and len(behaviors) >= 2 and len(layers) >= 2
    ):
        tier = "B"
    elif pair >= 1:
        tier = "C"
    else:
        tier = "D"

    return {
        "tier": tier,
        "explicit_edge_count": int(explicit),
        "pair_edge_count": int(pair),
        "weak_edge_count": int(weak),
        "evidence_layer_count": int(len(layers)),
        "evidence_layers": sorted(layers),
        "behavior_count": int(len(behaviors)),
        "behaviors": sorted(behaviors),
        "stage_count": int(len(stages)),
        "stages": sorted(stages),
        "temporal_span_seconds": round(float(span), 6),
    }


def build_graph(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    edges = build_edges(alerts)
    groups = components(alerts, edges)
    node_map = {node["id"]: node for node in alerts}

    chains: list[dict[str, Any]] = []
    for index, component in enumerate(groups, start=1):
        ordered = sorted(
            component,
            key=lambda alert_id: (
                node_map[alert_id]["_ts"] is None,
                node_map[alert_id]["_ts"] or 0.0,
            ),
        )
        chains.append(
            {
                "chain_id": "chain_%04d" % index,
                "alert_ids": ordered,
                "node_count": len(ordered),
                "qoa": qoa_profile(ordered, node_map, edges),
            }
        )

    export_nodes: list[dict[str, Any]] = []
    for node in alerts:
        value = dict(node)
        value.pop("_ts", None)
        export_nodes.append(value)

    return {
        "schema_version": "chainlens-qoa-v2",
        "node_count": len(export_nodes),
        "edge_count": len(edges),
        "chain_count": len(chains),
        "nodes": export_nodes,
        "edges": edges,
        "chains": chains,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build a sparse ChainLens-QoA attribution graph from alerts."
    )
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    alerts = load_alerts(args.input)
    graph = build_graph(alerts)

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    json.dump(
        graph,
        output.open("w", encoding="utf-8"),
        ensure_ascii=False,
        indent=2,
    )

    tiers: dict[str, int] = {}
    for chain in graph["chains"]:
        tier = chain["qoa"]["tier"]
        tiers[tier] = tiers.get(tier, 0) + 1

    print("ALERTS", graph["node_count"])
    print("EDGES", graph["edge_count"])
    print("CHAINS", graph["chain_count"])
    print("QOA_TIERS", tiers)
    print("CHAINLENS_QOA_V2_OK")


if __name__ == "__main__":
    main()
