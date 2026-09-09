#!/usr/bin/env python3
"""Metadata-only packet evidence extraction for CipherGuard-AegisFusion.

This GitHub-portable implementation is derived from the V14.3 competition
freeze.  It intentionally does **not** decode application payload bytes,
perform TLS/SSH decryption, search marker keywords, or use filenames as attack
evidence.

Allowed evidence is limited to packet/frame length, payload *length* only,
direction, inter-arrival time, TCP flags/windows, ports for metadata
correlation, flow duration, and up/down byte ratios.
"""
from __future__ import annotations

import math
import socket
import struct
from pathlib import Path
from typing import Any, Callable


def _ip(raw: bytes) -> str:
    return socket.inet_ntoa(raw)


def _read_pcap(path: str | Path, max_packets: int = 200) -> list[dict[str, Any]]:
    """Read classic PCAP Ethernet/IPv4 TCP/UDP metadata without payload decode."""
    raw = Path(path).read_bytes()
    if len(raw) < 24:
        return []

    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", False),
        b"\xa1\xb2\xc3\xd4": (">", False),
        b"\x4d\x3c\xb2\xa1": ("<", True),
        b"\xa1\xb2\x3c\x4d": (">", True),
    }
    if raw[:4] not in formats:
        return []

    endian, nanosecond = formats[raw[:4]]
    offset = 24
    packets: list[dict[str, Any]] = []
    first_timestamp: float | None = None
    previous_timestamp: float | None = None

    while offset + 16 <= len(raw) and len(packets) < max_packets:
        ts_sec, ts_fraction, captured_len, original_len = struct.unpack(
            endian + "IIII", raw[offset : offset + 16]
        )
        offset += 16
        if captured_len < 0 or offset + captured_len > len(raw):
            break

        frame = raw[offset : offset + captured_len]
        offset += captured_len
        timestamp = float(ts_sec) + float(ts_fraction) / (
            1_000_000_000.0 if nanosecond else 1_000_000.0
        )
        if first_timestamp is None:
            first_timestamp = timestamp
        relative_time = timestamp - first_timestamp
        iat = (
            0.0
            if previous_timestamp is None
            else max(0.0, timestamp - previous_timestamp)
        )
        previous_timestamp = timestamp

        packet: dict[str, Any] = {
            "frame_index": len(packets) + 1,
            "timestamp": timestamp,
            "relative_time": round(relative_time, 6),
            "iat_seconds": round(iat, 6),
            "frame_len": int(original_len),
            "captured_len": int(captured_len),
            "eth_type": None,
            "ip_proto": None,
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "tcp_flags": "",
            "tcp_window": 0,
            "ip_header_len": 0,
            "transport_header_len": 0,
            "payload_len": 0,
            "tcp_payload_len": 0,
            "udp_payload_len": 0,
            "direction": None,
        }

        # Ethernet + optional VLAN + IPv4. No application bytes are decoded.
        ip_offset: int | None = None
        if frame and frame[0] >> 4 == 4:
            ip_offset = 0
        elif len(frame) >= 14:
            ethertype = struct.unpack("!H", frame[12:14])[0]
            packet["eth_type"] = "0x%04x" % ethertype
            candidate: int | None = 14
            while ethertype in (0x8100, 0x88A8, 0x9100):
                if candidate is None or len(frame) < candidate + 4:
                    candidate = None
                    break
                ethertype = struct.unpack(
                    "!H", frame[candidate + 2 : candidate + 4]
                )[0]
                candidate += 4
            if candidate is not None and ethertype == 0x0800:
                ip_offset = candidate

        if ip_offset is not None and len(frame) >= ip_offset + 20:
            version_ihl = frame[ip_offset]
            ip_header_len = (version_ihl & 0x0F) * 4
            if (
                version_ihl >> 4 == 4
                and ip_header_len >= 20
                and len(frame) >= ip_offset + ip_header_len
            ):
                total_len = struct.unpack(
                    "!H", frame[ip_offset + 2 : ip_offset + 4]
                )[0]
                if total_len <= 0:
                    total_len = max(0, len(frame) - ip_offset)
                protocol = int(frame[ip_offset + 9])
                packet.update(
                    {
                        "ip_proto": {6: "TCP", 17: "UDP", 1: "ICMP"}.get(
                            protocol, str(protocol)
                        ),
                        "src_ip": _ip(frame[ip_offset + 12 : ip_offset + 16]),
                        "dst_ip": _ip(frame[ip_offset + 16 : ip_offset + 20]),
                        "ip_len": int(total_len),
                        "ip_header_len": int(ip_header_len),
                    }
                )
                l4_offset = ip_offset + ip_header_len

                if protocol == 6 and len(frame) >= l4_offset + 20:
                    src_port, dst_port = struct.unpack(
                        "!HH", frame[l4_offset : l4_offset + 4]
                    )
                    data_offset = (frame[l4_offset + 12] >> 4) * 4
                    if data_offset < 20:
                        data_offset = 20
                    flags = int(frame[l4_offset + 13])
                    window = struct.unpack(
                        "!H", frame[l4_offset + 14 : l4_offset + 16]
                    )[0]
                    names: list[str] = []
                    for mask, name in (
                        (0x02, "SYN"),
                        (0x10, "ACK"),
                        (0x08, "PSH"),
                        (0x01, "FIN"),
                        (0x04, "RST"),
                        (0x20, "URG"),
                        (0x40, "ECE"),
                        (0x80, "CWR"),
                    ):
                        if flags & mask:
                            names.append(name)
                    payload_len = max(
                        0, int(total_len) - ip_header_len - data_offset
                    )
                    packet.update(
                        {
                            "src_port": int(src_port),
                            "dst_port": int(dst_port),
                            "tcp_flags": ",".join(names),
                            "tcp_window": int(window),
                            "transport_header_len": int(data_offset),
                            "payload_len": int(payload_len),
                            "tcp_payload_len": int(payload_len),
                        }
                    )
                elif protocol == 17 and len(frame) >= l4_offset + 8:
                    src_port, dst_port = struct.unpack(
                        "!HH", frame[l4_offset : l4_offset + 4]
                    )
                    payload_len = max(0, int(total_len) - ip_header_len - 8)
                    packet.update(
                        {
                            "src_port": int(src_port),
                            "dst_port": int(dst_port),
                            "transport_header_len": 8,
                            "payload_len": int(payload_len),
                            "udp_payload_len": int(payload_len),
                        }
                    )

        packets.append(packet)

    return packets


def _safe_mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _safe_std(values: list[float]) -> float:
    if len(values) <= 1:
        return 0.0
    mean = _safe_mean(values)
    return math.sqrt(sum((value - mean) ** 2 for value in values) / len(values))


def _coefficient_of_variation(values: list[float]) -> float:
    if not values:
        return math.inf
    mean = abs(_safe_mean(values))
    if mean <= 1e-12:
        return math.inf
    return _safe_std(values) / mean


def _safe_median(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    midpoint = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[midpoint])
    return float((ordered[midpoint - 1] + ordered[midpoint]) / 2.0)


def _robust_jitter_ratio(values: list[float]) -> float:
    if len(values) < 2:
        return math.inf
    median = _safe_median(values)
    if abs(median) <= 1e-12:
        return math.inf
    mad = _safe_median([abs(value - median) for value in values])
    return mad / abs(median)


def _deduplicate_payload_events(
    packets: list[dict[str, Any]],
    epsilon: float = 0.006,
) -> list[dict[str, Any]]:
    """Remove near-duplicate loopback payload observations.

    Linux loopback capture can expose a payload frame more than once.  The
    V14.3 calibration therefore reasons over a de-duplicated application-event
    stream before calculating periodicity or request/response switching.
    """
    events = [
        packet
        for packet in packets
        if int(packet.get("payload_len") or 0) > 0
        and packet.get("direction") in ("up", "down")
    ]
    if not events:
        return []

    deduplicated: list[dict[str, Any]] = []
    for packet in events:
        if deduplicated:
            previous = deduplicated[-1]
            close_in_time = (
                abs(
                    float(packet.get("timestamp") or 0.0)
                    - float(previous.get("timestamp") or 0.0)
                )
                <= epsilon
            )
            same_signature = (
                packet.get("direction") == previous.get("direction")
                and packet.get("src_ip") == previous.get("src_ip")
                and packet.get("dst_ip") == previous.get("dst_ip")
                and packet.get("src_port") == previous.get("src_port")
                and packet.get("dst_port") == previous.get("dst_port")
                and int(packet.get("payload_len") or 0)
                == int(previous.get("payload_len") or 0)
            )
            if close_in_time and same_signature:
                continue
        deduplicated.append(packet)
    return deduplicated


def _packet_view(
    packet: dict[str, Any], reason: str | None = None
) -> dict[str, Any]:
    value = {
        "frame_index": packet.get("frame_index"),
        "relative_time": packet.get("relative_time"),
        "src_ip": packet.get("src_ip"),
        "dst_ip": packet.get("dst_ip"),
        "src_port": packet.get("src_port"),
        "dst_port": packet.get("dst_port"),
        "ip_proto": packet.get("ip_proto"),
        "tcp_flags": packet.get("tcp_flags"),
        "frame_len": packet.get("frame_len"),
        "payload_len": packet.get("payload_len"),
        "iat_seconds": packet.get("iat_seconds"),
        "direction": packet.get("direction"),
    }
    if reason:
        value["reason"] = reason
    return value


def _consecutive_iats(packets: list[dict[str, Any]]) -> list[float]:
    timestamps = [float(packet.get("timestamp") or 0.0) for packet in packets]
    return [
        max(0.0, timestamps[index] - timestamps[index - 1])
        for index in range(1, len(timestamps))
        if timestamps[index] > timestamps[index - 1]
    ]


def extract_packet_evidence(
    path: str | Path,
    max_packets: int = 200,
) -> dict[str, Any]:
    packets = _read_pcap(path, max_packets=max_packets)
    if not packets:
        return {
            "available": False,
            "reason": "pcap_parse_empty_or_unsupported",
            "packets": [],
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
                "reasons": ["无法解析经典PCAP帧或格式不支持"],
                "content_inspection": False,
            },
        }

    # Ports are part of endpoint identity because loopback captures can have the
    # same IP on both sides. IP-only direction inference is therefore unsafe.
    first_flow_packet = next(
        (
            packet
            for packet in packets
            if packet.get("src_ip")
            and packet.get("dst_ip")
            and packet.get("src_port") is not None
            and packet.get("dst_port") is not None
        ),
        None,
    )
    client_endpoint: tuple[str | None, int] | None = None
    server_endpoint: tuple[str | None, int] | None = None
    if first_flow_packet is not None:
        client_endpoint = (
            first_flow_packet.get("src_ip"),
            int(first_flow_packet.get("src_port")),
        )
        server_endpoint = (
            first_flow_packet.get("dst_ip"),
            int(first_flow_packet.get("dst_port")),
        )

    for packet in packets:
        src_endpoint = (
            packet.get("src_ip"),
            int(packet.get("src_port") or 0),
        )
        dst_endpoint = (
            packet.get("dst_ip"),
            int(packet.get("dst_port") or 0),
        )
        if client_endpoint and (
            src_endpoint == client_endpoint or dst_endpoint == server_endpoint
        ):
            packet["direction"] = "up"
        elif server_endpoint and (
            src_endpoint == server_endpoint or dst_endpoint == client_endpoint
        ):
            packet["direction"] = "down"
        else:
            packet["direction"] = "unknown"

    valid = [packet for packet in packets if packet.get("src_ip")]
    ports = {
        int(port)
        for packet in valid
        for port in (packet.get("src_port"), packet.get("dst_port"))
        if port is not None
    }
    dst_ips = {
        packet.get("dst_ip") for packet in valid if packet.get("dst_ip")
    }
    dst_ports = {
        int(packet["dst_port"])
        for packet in valid
        if packet.get("dst_port") is not None
    }
    timestamps = [float(packet["timestamp"]) for packet in valid]
    duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.0
    iats = [
        float(packet.get("iat_seconds") or 0.0)
        for packet in valid
        if float(packet.get("iat_seconds") or 0.0) > 0.0
    ]
    frame_lengths = [float(packet.get("frame_len") or 0.0) for packet in valid]
    up_packets = [packet for packet in valid if packet.get("direction") == "up"]
    down_packets = [packet for packet in valid if packet.get("direction") == "down"]
    up_bytes = sum(int(packet.get("frame_len") or 0) for packet in up_packets)
    down_bytes = sum(int(packet.get("frame_len") or 0) for packet in down_packets)
    bidirectional_ratio = min(len(up_packets), len(down_packets)) / max(
        1.0, float(max(len(up_packets), len(down_packets)))
    )
    syn_packets = sum(
        1 for packet in valid if "SYN" in (packet.get("tcp_flags") or "")
    )
    rst_packets = sum(
        1 for packet in valid if "RST" in (packet.get("tcp_flags") or "")
    )
    small_payload_packets = sum(
        1
        for packet in valid
        if 0 < int(packet.get("payload_len") or 0) <= 32
    )
    iat_cv = _coefficient_of_variation(iats)

    # V14.3 calibration: reason over de-duplicated application exchanges.
    behavior_payload_events = _deduplicate_payload_events(valid)
    behavior_up = [
        packet
        for packet in behavior_payload_events
        if packet.get("direction") == "up"
    ]
    behavior_down = [
        packet
        for packet in behavior_payload_events
        if packet.get("direction") == "down"
    ]
    up_payload_sizes = [
        float(packet.get("payload_len") or 0.0) for packet in behavior_up
    ]
    down_payload_sizes = [
        float(packet.get("payload_len") or 0.0) for packet in behavior_down
    ]
    up_iats = _consecutive_iats(behavior_up)
    payload_directions = [
        packet.get("direction") for packet in behavior_payload_events
    ]
    payload_switches = sum(
        1
        for index in range(1, len(payload_directions))
        if payload_directions[index]
        and payload_directions[index - 1]
        and payload_directions[index] != payload_directions[index - 1]
    )
    payload_switch_ratio = payload_switches / max(
        1.0, float(len(payload_directions) - 1)
    )
    up_iat_cv = _coefficient_of_variation(up_iats)
    up_iat_robust_jitter = _robust_jitter_ratio(up_iats)
    up_iat_median = _safe_median(up_iats)
    up_payload_size_cv = _coefficient_of_variation(up_payload_sizes)
    up_payload_median = _safe_median(up_payload_sizes)
    down_payload_median = _safe_median(down_payload_sizes)
    packet_length_cv = _coefficient_of_variation(frame_lengths)

    rule_hits: list[dict[str, Any]] = []

    def add_hit(
        rule_id: str,
        behavior: str,
        reason: str,
        predicate: Callable[[dict[str, Any]], bool],
    ) -> None:
        evidence: list[dict[str, Any]] = []
        for packet in valid:
            try:
                if predicate(packet):
                    evidence.append(_packet_view(packet, reason))
            except Exception:
                continue
        if evidence:
            rule_hits.append(
                {
                    "rule_id": rule_id,
                    "behavior": behavior,
                    "reason": reason,
                    "packets": evidence[:12],
                    "hit_count": len(evidence),
                    "content_inspection": False,
                }
            )

    # Conservative metadata-only rules: a service port alone is never enough.
    if (
        22 in ports
        and syn_packets >= 6
        and len(dst_ips) <= 2
        and duration <= 120.0
    ):
        add_hit(
            "ssh_connection_burst_metadata",
            "ssh_bruteforce",
            "22端口出现单目标高频SYN建连，未读取认证内容",
            lambda packet: (
                (packet.get("src_port") == 22 or packet.get("dst_port") == 22)
                and "SYN" in (packet.get("tcp_flags") or "")
            ),
        )

    if (
        len(behavior_up) >= 9
        and duration >= 4.5
        and 0.25 <= up_iat_median <= 2.0
        and up_iat_robust_jitter <= 0.22
        and up_payload_size_cv <= 0.22
        and up_payload_median <= 128.0
        and (443 in ports or not ports.intersection({22, 80, 443, 8443}))
    ):
        add_hit(
            "tls_periodicity_metadata_v143",
            "tls_periodic_c2",
            "加密会话呈稳定小包周期节奏，仅依据去重后的方向、包长和IAT",
            lambda packet: (
                0 < int(packet.get("payload_len") or 0) <= 128
                and packet.get("direction") == "up"
            ),
        )

    if (
        len(behavior_up) >= 8
        and len(behavior_down) >= 8
        and len(behavior_payload_events) >= 16
        and payload_switch_ratio >= 0.68
        and up_payload_median <= 24.0
        and down_payload_median >= 256.0
        and down_payload_median >= max(256.0, up_payload_median * 8.0)
        and duration <= 45.0
    ):
        add_hit(
            "opaque_command_sequence_metadata_v143",
            "abnormal_command_sequence",
            "加密会话持续出现小请求—大响应自动化序列，未解密命令内容",
            lambda packet: int(packet.get("payload_len") or 0) > 0,
        )

    if (
        duration >= 8.0
        and len(valid) >= 32
        and bidirectional_ratio >= 0.30
        and (up_iat_cv <= 0.35 or packet_length_cv <= 0.75)
        and (duration >= 60.0 or not ports.intersection({22, 80, 443, 8443}))
    ):
        add_hit(
            "encrypted_tunnel_metadata",
            "encrypted_tunnel",
            "长时双向加密流呈规律IAT或包长分布",
            lambda packet: packet.get("direction") in ("up", "down"),
        )

    if (
        len(valid) >= 80
        and up_bytes >= 96 * 1024
        and up_bytes >= max(64 * 1024, down_bytes * 6)
    ):
        add_hit(
            "outbound_bulk_asymmetry_metadata",
            "data_exfiltration",
            "累计上行流量显著高于下行，仅依据方向和字节量",
            lambda packet: packet.get("direction") == "up",
        )

    if (
        syn_packets >= 8
        and (len(dst_ips) >= 3 or len(dst_ports) >= 6)
        and duration <= 60.0
    ):
        add_hit(
            "multi_target_syn_scan_metadata",
            "scan_short_connection",
            "短时间多目标或多端口SYN探测",
            lambda packet: "SYN" in (packet.get("tcp_flags") or ""),
        )

    hit_behaviors = {hit["behavior"] for hit in rule_hits}

    service_class = "unknown"
    encrypted_protocol = "unknown"
    traffic_role = "unknown"
    confidence = 0.45
    reasons: list[str] = ["未发现可由元数据确认的特定加密服务或行为"]

    if "data_exfiltration" in hit_behaviors:
        service_class = "data_exfiltration"
        traffic_role = "exfiltration"
        confidence = 0.93
        reasons = ["上下行字节量呈显著外传不对称"]
    elif "encrypted_tunnel" in hit_behaviors:
        service_class = "encrypted_tunnel"
        traffic_role = "defense_evasion"
        confidence = 0.90
        reasons = ["长时双向流呈稳定的IAT或包长形态"]
    elif "tls_periodic_c2" in hit_behaviors:
        service_class = "encrypted_c2"
        encrypted_protocol = "TLS_or_encrypted"
        traffic_role = "command_and_control"
        confidence = 0.91
        reasons = ["去重后的上行小包具有稳定周期性"]
    elif "abnormal_command_sequence" in hit_behaviors:
        service_class = "encrypted_command_sequence"
        traffic_role = "execution"
        confidence = 0.90
        reasons = ["观察到小请求—大响应—高方向交替序列"]
    elif "ssh_bruteforce" in hit_behaviors:
        service_class = "remote_management"
        encrypted_protocol = "SSH"
        traffic_role = "credential_access"
        confidence = 0.88
        reasons = ["22端口出现单目标重复SYN建连行为"]
    elif 22 in ports:
        service_class = "remote_management"
        encrypted_protocol = "SSH"
        traffic_role = "administration"
        confidence = 0.70
        reasons = ["端口元数据与SSH远程管理服务一致；端口本身不触发攻击告警"]
    elif 443 in ports:
        service_class = "secure_web"
        encrypted_protocol = "TLS"
        traffic_role = "web"
        confidence = 0.65
        reasons = ["端口元数据与TLS/HTTPS服务一致；端口本身不触发攻击告警"]

    evidence_packets: list[dict[str, Any]] = []
    for hit in rule_hits:
        evidence_packets.extend(hit.get("packets", []))
    evidence_packets = evidence_packets[:24]

    flow_stats = {
        "packet_count": len(valid),
        "src_ip_count": len(
            {packet.get("src_ip") for packet in valid if packet.get("src_ip")}
        ),
        "dst_ip_count": len(dst_ips),
        "unique_dst_ports": sorted(dst_ports),
        "duration_seconds": round(duration, 6),
        "syn_packet_count": syn_packets,
        "rst_packet_count": rst_packets,
        "small_payload_packet_count": small_payload_packets,
        "up_packet_count": len(up_packets),
        "down_packet_count": len(down_packets),
        "up_bytes": up_bytes,
        "down_bytes": down_bytes,
        "up_down_byte_ratio": round(up_bytes / max(1.0, float(down_bytes)), 6),
        "bidirectional_packet_ratio": round(bidirectional_ratio, 6),
        "avg_iat_seconds": round(_safe_mean(iats), 6),
        "max_iat_seconds": round(max(iats) if iats else 0.0, 6),
        "iat_cv": round(iat_cv, 6) if math.isfinite(iat_cv) else None,
        "behavior_payload_event_count": len(behavior_payload_events),
        "payload_switch_ratio": round(payload_switch_ratio, 6),
        "up_iat_median": round(up_iat_median, 6),
        "up_iat_cv": round(up_iat_cv, 6) if math.isfinite(up_iat_cv) else None,
        "up_iat_robust_jitter": (
            round(up_iat_robust_jitter, 6)
            if math.isfinite(up_iat_robust_jitter)
            else None
        ),
        "up_payload_size_cv": (
            round(up_payload_size_cv, 6)
            if math.isfinite(up_payload_size_cv)
            else None
        ),
        "up_payload_median": round(up_payload_median, 6),
        "down_payload_median": round(down_payload_median, 6),
        "packet_length_cv": (
            round(packet_length_cv, 6)
            if math.isfinite(packet_length_cv)
            else None
        ),
    }

    return {
        "available": True,
        "reason": "metadata_only_packet_evidence",
        "packets": [_packet_view(packet) for packet in valid[:max_packets]],
        "packet_count": len(valid),
        "flow_stats": flow_stats,
        "packet_sequence": [
            {
                "frame_index": packet.get("frame_index"),
                "relative_time": packet.get("relative_time"),
                "direction": packet.get("direction"),
                "frame_len": packet.get("frame_len"),
                "payload_len": packet.get("payload_len"),
                "iat_seconds": packet.get("iat_seconds"),
                "tcp_flags": packet.get("tcp_flags"),
            }
            for packet in valid[:max_packets]
        ],
        "rule_hits": rule_hits,
        "evidence_packets": evidence_packets,
        "content_inspection": False,
        "decryption_performed": False,
        "traffic_classification": {
            "service_class": service_class,
            "encrypted_protocol": encrypted_protocol,
            "traffic_role": traffic_role,
            "confidence": round(confidence, 4),
            "reasons": reasons,
            "content_inspection": False,
        },
    }


__all__ = ["extract_packet_evidence"]
