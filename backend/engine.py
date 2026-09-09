#!/usr/bin/env python3
"""CipherGuard-AegisFusion evidence-fusion engine.

Portable public-core port of the final competition engine. The production path
keeps two evidence layers separate:

1. AegisFusion family inference from the leakage-controlled 78D flow contract.
2. Explainable V14.3 metadata-only packet / sequence behavior evidence.

The engine never decrypts TLS/SSH traffic and never uses payload text, marker
keywords, filenames, TLS plaintext, or SSH commands as attack evidence.
"""
from __future__ import annotations

import hashlib
import statistics
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

try:  # package import
    from .aegisfusion_bridge import predict_pcap
    from .packet_evidence import extract_packet_evidence
except ImportError:  # direct script/module import
    from aegisfusion_bridge import predict_pcap
    from packet_evidence import extract_packet_evidence


BEHAVIOR_STAGE = {
    "scan_short_connection": "discovery",
    "ssh_bruteforce": "credential_access",
    "credential_bruteforce": "credential_access",
    "abnormal_command_sequence": "execution",
    "tls_periodic_c2": "command_and_control",
    "botnet_activity": "command_and_control",
    "encrypted_tunnel": "defense_evasion",
    "data_exfiltration": "exfiltration",
    "dos_syn_flood": "impact",
    "ddos_activity": "impact",
    "dos_activity": "impact",
    "infiltration_activity": "post_compromise",
    "web_attack_activity": "initial_access",
    "bruteforce_post_action": "post_compromise",
}


FAMILY_BEHAVIOR: dict[str, tuple[str, str]] = {
    "Botnet": (
        "botnet_activity",
        "AegisFusion 检测到与 Botnet 家族一致的流量统计模式",
    ),
    "BruteForce": (
        "credential_bruteforce",
        "AegisFusion 检测到与 BruteForce 家族一致的流量统计模式",
    ),
    "DDoS": (
        "ddos_activity",
        "AegisFusion 检测到与 DDoS 家族一致的流量统计模式",
    ),
    "DoS": (
        "dos_activity",
        "AegisFusion 检测到与 DoS 家族一致的流量统计模式",
    ),
    "Infiltration": (
        "infiltration_activity",
        "AegisFusion 检测到与 Infiltration 家族一致的流量统计模式",
    ),
    "WebAttack": (
        "web_attack_activity",
        "AegisFusion 检测到与 WebAttack 家族一致的流量统计模式",
    ),
}


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def make_alert(
    alert_id: str,
    encrypted_protocol: str,
    service_class: str,
    behavior: str,
    risk_score: float,
    attack_probability: float,
    evidence: list[str],
    *,
    dst_port: Optional[int] = None,
    detection_source: str = "metadata_behavior_rule",
) -> dict[str, Any]:
    probability = float(max(0.0, min(1.0, attack_probability)))
    risk = float(max(0.0, min(100.0, risk_score)))
    return {
        "alert_id": alert_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": dst_port,
        "encrypted_protocol": encrypted_protocol,
        "service_class": service_class,
        "behavior": behavior,
        "attack_stage": BEHAVIOR_STAGE.get(behavior),
        "risk_score": round(risk, 2),
        "attack_probability": round(probability, 6),
        "anomaly_score": round(probability, 6),
        "rule_score": round(probability, 6),
        "detection_source": detection_source,
        "evidence": list(evidence),
        "rule_hits": [],
        "packet_evidence": [],
    }


def _attach_packet_evidence(
    alerts: list[dict[str, Any]],
    packet_result: dict[str, Any],
) -> list[dict[str, Any]]:
    if not packet_result.get("available"):
        return alerts

    hit_map: dict[str, list[dict[str, Any]]] = {}
    for hit in packet_result.get("rule_hits", []):
        behavior = str(hit.get("behavior") or "")
        if behavior:
            hit_map.setdefault(behavior, []).append(hit)

    for alert in alerts:
        matches = hit_map.get(str(alert.get("behavior") or ""), [])
        if not matches:
            continue
        alert["rule_hits"] = matches

        packet_evidence: list[dict[str, Any]] = []
        for hit in matches:
            packet_evidence.extend(hit.get("packets", []) or [])
        alert["packet_evidence"] = packet_evidence[:24]

        if alert["packet_evidence"]:
            first = alert["packet_evidence"][0]
            alert["src_ip"] = first.get("src_ip")
            alert["dst_ip"] = first.get("dst_ip")
            alert["src_port"] = first.get("src_port")
            alert["dst_port"] = first.get("dst_port") or alert.get("dst_port")
            alert["evidence"].append(
                "包级证据来自元数据规则 %s；未读取应用层载荷文本"
                % matches[0].get("rule_id")
            )
    return alerts


def _attach_aegisfusion_evidence(
    alerts: list[dict[str, Any]],
    model_result: dict[str, Any],
) -> list[dict[str, Any]]:
    if not model_result.get("success"):
        return alerts

    model_evidence = {
        "family": model_result.get("family"),
        "base_family": model_result.get("base_family"),
        "confidence": model_result.get("confidence"),
        "risk_score": model_result.get("risk_score"),
        "attack_probability": model_result.get("attack_probability"),
        "temporal_infiltration_probability": model_result.get(
            "temporal_infiltration_probability"
        ),
        "temporal_applied": model_result.get("temporal_applied"),
        "context_id": model_result.get("context_id"),
        "context_history_before_prediction": model_result.get(
            "context_history_before_prediction"
        ),
        "model_path": model_result.get("model_path"),
        "conditional_probabilities": model_result.get(
            "conditional_probabilities", {}
        ),
        "feature_extraction": model_result.get("feature_extraction", {}),
    }
    text = (
        "AegisFusion 模型证据：family=%s，attack_probability=%.4f，"
        "risk=%.2f，temporal=%s，causal_history_depth=%s"
        % (
            model_result.get("family"),
            float(model_result.get("attack_probability") or 0.0),
            float(model_result.get("risk_score") or 0.0),
            model_result.get("temporal_infiltration_probability"),
            model_result.get("context_history_before_prediction"),
        )
    )
    for alert in alerts:
        alert["model_evidence"] = dict(model_evidence)
        alert["evidence"].append(text)
    return alerts


def _has_packet_behavior(packet_result: dict[str, Any], behavior: str) -> bool:
    if not packet_result:
        return False
    return any(
        hit.get("behavior") == behavior
        for hit in packet_result.get("rule_hits", [])
    )


def _sequence_metrics(packet_result: dict[str, Any]) -> dict[str, float | int]:
    """Recover the final freeze's loopback-deduplicated request/response metrics."""
    raw_sequence = list((packet_result or {}).get("packet_sequence") or [])

    sequence: list[dict[str, Any]] = []
    last_by_key: dict[tuple[Any, int], float] = {}
    for item in raw_sequence:
        payload_len = float(
            item.get("tcp_payload_len") or item.get("payload_len") or 0.0
        )
        if payload_len <= 0:
            continue
        timestamp = float(item.get("relative_time") or 0.0)
        key = (item.get("direction"), int(payload_len))
        previous = last_by_key.get(key)
        if previous is not None and 0.0 <= timestamp - previous <= 0.006:
            continue
        last_by_key[key] = timestamp
        sequence.append(item)

    if not sequence:
        return {
            "count": 0,
            "switch_ratio": 0.0,
            "up_payload_mean": 0.0,
            "down_payload_mean": 0.0,
            "up_payload_median": 0.0,
            "down_payload_median": 0.0,
            "up_count": 0,
            "down_count": 0,
            "iat_mean": 0.0,
            "iat_cv": 0.0,
            "up_iat_cv": 0.0,
        }

    directions = [item.get("direction") for item in sequence]
    switches = sum(
        1
        for index in range(1, len(directions))
        if directions[index]
        and directions[index - 1]
        and directions[index] != directions[index - 1]
    )
    switch_ratio = switches / max(1.0, float(len(directions) - 1))

    up_payload = [
        float(item.get("tcp_payload_len") or 0.0)
        for item in sequence
        if item.get("direction") == "up"
        and float(item.get("tcp_payload_len") or 0.0) > 0
    ]
    down_payload = [
        float(item.get("tcp_payload_len") or 0.0)
        for item in sequence
        if item.get("direction") == "down"
        and float(item.get("tcp_payload_len") or 0.0) > 0
    ]
    iats = [
        float(item.get("iat_seconds") or 0.0)
        for item in sequence
        if float(item.get("iat_seconds") or 0.0) > 0
    ]
    up_times = [
        float(item.get("relative_time") or 0.0)
        for item in sequence
        if item.get("direction") == "up"
    ]
    up_iats = [
        max(0.0, up_times[index] - up_times[index - 1])
        for index in range(1, len(up_times))
        if up_times[index] > up_times[index - 1]
    ]

    iat_mean = statistics.fmean(iats) if iats else 0.0
    iat_std = statistics.pstdev(iats) if len(iats) > 1 else 0.0
    up_iat_mean = statistics.fmean(up_iats) if up_iats else 0.0
    up_iat_std = statistics.pstdev(up_iats) if len(up_iats) > 1 else 0.0

    return {
        "count": len(sequence),
        "switch_ratio": switch_ratio,
        "up_payload_mean": statistics.fmean(up_payload) if up_payload else 0.0,
        "down_payload_mean": (
            statistics.fmean(down_payload) if down_payload else 0.0
        ),
        "up_payload_median": (
            statistics.median(up_payload) if up_payload else 0.0
        ),
        "down_payload_median": (
            statistics.median(down_payload) if down_payload else 0.0
        ),
        "up_count": len(up_payload),
        "down_count": len(down_payload),
        "iat_mean": iat_mean,
        "iat_cv": iat_std / iat_mean if iat_mean > 0 else 0.0,
        "up_iat_cv": (
            up_iat_std / up_iat_mean if up_iat_mean > 0 else 0.0
        ),
    }


def _metadata_tunnel_score(
    packet_result: dict[str, Any],
    model_result: dict[str, Any],
) -> tuple[float, list[str]]:
    """Final freeze's conservative metadata/model support score for tunnels."""
    stats = (packet_result or {}).get("flow_stats") or {}
    extraction = (model_result or {}).get("feature_extraction") or {}
    packet_count = int(
        extraction.get("dominant_flow_packet_count")
        or stats.get("packet_count")
        or 0
    )
    duration = float(extraction.get("duration_seconds") or 0.0)
    up_bytes = float(
        extraction.get("forward_bytes") or stats.get("up_bytes") or 0.0
    )
    down_bytes = float(
        extraction.get("backward_bytes") or stats.get("down_bytes") or 0.0
    )
    avg_iat = float(stats.get("avg_iat_seconds") or 0.0)
    max_iat = float(stats.get("max_iat_seconds") or 0.0)

    score = 0.0
    reasons: list[str] = []
    if packet_count >= 20:
        score += 0.20
        reasons.append("持续会话包含不少于20个数据包")
    if duration >= 8.0:
        score += 0.20
        reasons.append("会话持续时间不少于8秒")
    if up_bytes > 0 and down_bytes > 0:
        ratio = down_bytes / max(1.0, up_bytes)
        if 0.15 <= ratio <= 6.0:
            score += 0.20
            reasons.append("上下行保持双向传输")
    if 0.05 <= avg_iat <= 5.0 and max_iat >= 0.5:
        score += 0.15
        reasons.append("存在持续心跳或代理转发节奏")
    family = (model_result or {}).get("family")
    if family in ("Botnet", "Infiltration"):
        score += 0.25
        reasons.append("AegisFusion 家族结果提供异常支持")
    return min(1.0, score), reasons


def _model_alert(
    model_result: dict[str, Any],
    traffic_classification: dict[str, Any],
) -> Optional[dict[str, Any]]:
    if not model_result or not model_result.get("success"):
        return None
    family = model_result.get("family")
    if family == "Benign" or family not in FAMILY_BEHAVIOR:
        return None

    behavior, summary = FAMILY_BEHAVIOR[str(family)]
    attack_probability = float(model_result.get("attack_probability") or 0.0)
    confidence = float(model_result.get("confidence") or 0.0)
    risk = float(model_result.get("risk_score") or 0.0)
    risk = max(risk, 45.0 + 50.0 * max(attack_probability, confidence))
    protocol = (
        (traffic_classification or {}).get("encrypted_protocol")
        or "Encrypted/TCP-UDP"
    )
    service = (
        (traffic_classification or {}).get("service_class")
        or "aegisfusion_family"
    )
    return make_alert(
        "flow_aegisfusion_family",
        str(protocol),
        str(service),
        behavior,
        risk,
        max(attack_probability, confidence),
        [
            summary,
            "模型使用78维去泄漏流统计特征，不读取明文载荷",
            "因果时间专家只使用当前流之前的上下文",
        ],
        dst_port=(model_result.get("feature_extraction") or {}).get("dst_port"),
        detection_source="aegisfusion_family_model",
    )


def _metadata_alerts(
    packet_result: dict[str, Any],
    model_result: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build metadata alerts with the final competition risk/probability values."""
    alerts: list[dict[str, Any]] = []

    if _has_packet_behavior(packet_result, "ssh_bruteforce"):
        alerts.append(
            make_alert(
                "flow_ssh_candidate",
                "SSH",
                "remote_management",
                "ssh_bruteforce",
                86.0,
                0.84,
                [
                    "22端口出现单目标高频SYN建连",
                    "判断仅使用连接频率、目标集中度与TCP标志",
                ],
                dst_port=22,
            )
        )

    if _has_packet_behavior(packet_result, "tls_periodic_c2"):
        alerts.append(
            make_alert(
                "flow_tls_candidate",
                "TLS",
                "encrypted_command_and_control",
                "tls_periodic_c2",
                76.0,
                0.72,
                [
                    "443端口出现稳定周期小包节奏",
                    "判断仅使用IAT、包长和方向，不读取TLS内容",
                ],
                dst_port=443,
            )
        )

    if _has_packet_behavior(packet_result, "scan_short_connection"):
        alerts.append(
            make_alert(
                "flow_scan_candidate",
                "TCP/UDP",
                "network_probe",
                "scan_short_connection",
                84.0,
                0.83,
                [
                    "短时间出现多目标或多端口SYN探测",
                    "判断仅使用五元组数量、时间跨度与TCP标志",
                ],
            )
        )

    tunnel_score, tunnel_reasons = _metadata_tunnel_score(
        packet_result, model_result
    )
    if (
        _has_packet_behavior(packet_result, "encrypted_tunnel")
        or tunnel_score >= 0.80
    ):
        alerts.append(
            make_alert(
                "flow_tunnel_candidate",
                "TLS/SSH/Proxy",
                "encrypted_tunnel",
                "encrypted_tunnel",
                max(74.0, tunnel_score * 100.0),
                max(0.70, tunnel_score),
                [
                    "检测到长时双向加密流与规律IAT/包长节奏",
                    *(tunnel_reasons or ["元数据隧道评分超过阈值"]),
                ],
            )
        )

    if _has_packet_behavior(packet_result, "data_exfiltration"):
        alerts.append(
            make_alert(
                "flow_exfil_candidate",
                "TLS/SSH",
                "bulk_transfer",
                "data_exfiltration",
                82.0,
                0.80,
                [
                    "累计上行流量显著高于下行",
                    "判断仅使用方向、字节量和持续时间",
                ],
            )
        )

    sequence = _sequence_metrics(packet_result)
    traffic_classification = packet_result.get("traffic_classification", {})
    is_ssh = traffic_classification.get("encrypted_protocol") == "SSH"
    model_family = model_result.get("family") if model_result else None
    command_asymmetry = (
        float(sequence["down_payload_median"])
        >= max(256.0, float(sequence["up_payload_median"]) * 8.0)
    )
    opaque_command_pattern = (
        float(sequence["up_payload_median"]) <= 24.0
        and float(sequence["down_payload_median"]) >= 256.0
        and int(sequence["up_count"]) >= 8
        and int(sequence["down_count"]) >= 8
    )
    packet_command_hit = _has_packet_behavior(
        packet_result, "abnormal_command_sequence"
    )
    if packet_command_hit or (
        (is_ssh or opaque_command_pattern)
        and int(sequence["count"]) >= 16
        and float(sequence["switch_ratio"]) >= 0.68
        and command_asymmetry
        and (
            model_family == "Infiltration"
            or float(sequence["up_iat_cv"]) <= 0.45
            or opaque_command_pattern
        )
    ):
        alerts.append(
            make_alert(
                "flow_command_sequence_candidate",
                "SSH",
                "encrypted_command_sequence",
                "abnormal_command_sequence",
                82.0 if model_family == "Infiltration" else 72.0,
                0.82 if model_family == "Infiltration" else 0.70,
                [
                    "加密会话呈现高频请求—响应方向切换",
                    "上行小命令与下行大响应形成自动化序列",
                    "命令内容未被解密，判断仅使用包长、方向与时间间隔",
                ],
                dst_port=22,
            )
        )

    return alerts


def _should_promote_family_alert(
    model_result: dict[str, Any],
    alerts: list[dict[str, Any]],
) -> bool:
    """Exact final gate: only Infiltration requires additional promotion proof."""
    family = (model_result or {}).get("family")
    if family != "Infiltration":
        return True

    attack_probability = float(
        (model_result or {}).get("attack_probability") or 0.0
    )
    corroborated = any(
        item.get("behavior")
        in (
            "abnormal_command_sequence",
            "encrypted_tunnel",
            "data_exfiltration",
        )
        for item in alerts
    )
    return attack_probability >= 0.55 or corroborated


def detect_file(
    path: str | Path,
    task_id: str,
    include_model: bool = True,
    context_id: Optional[str] = None,
    use_temporal: bool = True,
) -> dict[str, Any]:
    """Run the final-style offline PCAP evidence-fusion pipeline."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(path)

    size_bytes = path.stat().st_size
    file_hash = sha256_file(path)

    packet_result: dict[str, Any] = {
        "available": False,
        "reason": "packet_evidence_not_available",
        "packet_count": 0,
        "flow_stats": {},
        "packet_sequence": [],
        "rule_hits": [],
        "evidence_packets": [],
        "content_inspection": False,
        "decryption_performed": False,
        "traffic_classification": {
            "service_class": "unknown",
            "encrypted_protocol": "unknown",
            "traffic_role": "unknown",
            "confidence": 0.0,
            "reasons": [],
            "content_inspection": False,
        },
    }
    try:
        packet_result = extract_packet_evidence(path, max_packets=600)
    except Exception as exc:
        packet_result["reason"] = "%s: %s" % (type(exc).__name__, exc)

    model_result: dict[str, Any] = {
        "success": False,
        "attempted": False,
        "aegisfusion_inference": False,
        "model": "AegisFusion_NIDS",
        "reason": "disabled_or_bridge_unavailable",
    }
    if include_model:
        model_result = predict_pcap(
            path,
            context_id=context_id or ("offline:%s" % task_id),
            use_temporal=bool(use_temporal),
        )

    traffic_classification = packet_result.get("traffic_classification", {})
    alerts = _metadata_alerts(packet_result, model_result)

    family_alert = _model_alert(model_result, traffic_classification)
    if family_alert is not None and _should_promote_family_alert(
        model_result, alerts
    ):
        alerts.append(family_alert)

    deduplicated: list[dict[str, Any]] = []
    seen: set[tuple[Any, Any]] = set()
    for alert in alerts:
        key = (alert.get("behavior"), alert.get("detection_source"))
        if key not in seen:
            seen.add(key)
            deduplicated.append(alert)
    alerts = deduplicated

    alerts = _attach_packet_evidence(alerts, packet_result)
    alerts = _attach_aegisfusion_evidence(alerts, model_result)

    flow_count = int(
        (model_result.get("feature_extraction") or {}).get("pcap_flow_count")
        or (1 if packet_result.get("available") else 0)
    )
    normal_count = flow_count if not alerts else max(0, flow_count - 1)
    high_risk_count = sum(
        1
        for alert in alerts
        if float(alert.get("risk_score") or 0.0) >= 85.0
    )

    return {
        "task_id": str(task_id),
        "analysis_mode": "offline_dominant_flow_v1",
        "model_version": "aegisfusion-hierarchical-temporal-v1",
        "feature_version": "cic-flow-78+causal-context-8-32-128",
        "traffic_classification": traffic_classification,
        "summary": {
            "flow_count": flow_count,
            "normal_count": normal_count,
            "alert_count": len(alerts),
            "high_risk_count": high_risk_count,
            "aegisfusion_inference_success": bool(model_result.get("success")),
        },
        "alerts": alerts,
        "model_result": model_result,
        "evidence_contract": {
            "engine_mode": "aegisfusion_family+causal_temporal+behavior_rules",
            "content_inspection": False,
            "decryption_performed": False,
            "model_family": model_result.get("family"),
            "model_risk_score": model_result.get("risk_score"),
            "model_attack_probability": model_result.get("attack_probability"),
            "model_temporal_probability": model_result.get(
                "temporal_infiltration_probability"
            ),
            "causal_context_id": model_result.get("context_id"),
            "feature_extraction": model_result.get("feature_extraction", {}),
            "traffic_classification": traffic_classification,
            "packet_evidence": {
                "available": packet_result.get("available"),
                "reason": packet_result.get("reason"),
                "content_inspection": packet_result.get(
                    "content_inspection", False
                ),
                "decryption_performed": packet_result.get(
                    "decryption_performed", False
                ),
                "packet_count": packet_result.get("packet_count"),
                "flow_stats": packet_result.get("flow_stats", {}),
                "packet_sequence": packet_result.get("packet_sequence", []),
                "rule_hits": packet_result.get("rule_hits", []),
                "evidence_packets": packet_result.get(
                    "evidence_packets", []
                ),
            },
            "input_file": str(path),
            "input_sha256": file_hash,
            "input_size_bytes": int(size_bytes),
        },
    }


__all__ = [
    "BEHAVIOR_STAGE",
    "FAMILY_BEHAVIOR",
    "_metadata_tunnel_score",
    "_sequence_metrics",
    "_should_promote_family_alert",
    "detect_file",
    "make_alert",
    "sha256_file",
]
