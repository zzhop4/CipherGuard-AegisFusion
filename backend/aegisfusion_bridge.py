#!/usr/bin/env python3
"""PCAP-to-AegisFusion bridge for the portable CipherGuard repository.

This module is derived from the competition freeze and preserves the runtime
contract:

    PCAP/PCAPNG
        -> bidirectional five-tuple flow assembly
        -> dominant flow selection
        -> CIC-style 78D flow statistics
        -> model-service feature contract alignment
        -> hierarchical + causal temporal prediction

Only packet/flow metadata are used. Application payload bytes are never decoded,
searched, logged, or sent to the model service.
"""
from __future__ import annotations

import json
import math
import os
import statistics
import struct
import time
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional


AEGIS_URL = os.getenv("AEGISFUSION_MODEL_URL", "http://127.0.0.1:18083").rstrip("/")
_FEATURE_CACHE: Optional[dict[str, Any]] = None
_FEATURE_CACHE_AT = 0.0
_FEATURE_CACHE_TTL = float(os.getenv("AEGISFUSION_FEATURE_CACHE_TTL", "30"))


def _http_json(
    method: str,
    path: str,
    payload: Optional[dict[str, Any]] = None,
    timeout: float = 20.0,
) -> dict[str, Any]:
    url = AEGIS_URL + path
    body = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(
        url,
        data=body,
        headers=headers,
        method=method.upper(),
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            "AegisFusion service returned HTTP %s: %s"
            % (exc.code, detail[:800])
        ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError("AegisFusion service unavailable: %s" % exc) from exc

    if not raw:
        return {}
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("AegisFusion service returned non-object JSON")
    return value


def health() -> dict[str, Any]:
    return _http_json("GET", "/api/v1/aegisfusion/health", timeout=5.0)


def feature_contract(force: bool = False) -> dict[str, Any]:
    global _FEATURE_CACHE, _FEATURE_CACHE_AT

    now = time.time()
    if (
        not force
        and _FEATURE_CACHE is not None
        and now - _FEATURE_CACHE_AT < _FEATURE_CACHE_TTL
    ):
        return _FEATURE_CACHE

    value = _http_json("GET", "/api/v1/aegisfusion/features", timeout=8.0)
    feature_names = value.get("feature_names")
    if not isinstance(feature_names, list) or not feature_names:
        raise RuntimeError("Model service did not return feature_names")
    value["feature_names"] = [str(item) for item in feature_names]

    _FEATURE_CACHE = value
    _FEATURE_CACHE_AT = now
    return value


def _safe_mean(values: list[float]) -> float:
    return float(statistics.fmean(values)) if values else 0.0


def _safe_std(values: list[float]) -> float:
    return float(statistics.pstdev(values)) if len(values) > 1 else 0.0


def _safe_var(values: list[float]) -> float:
    return float(statistics.pvariance(values)) if len(values) > 1 else 0.0


def _safe_min(values: list[float]) -> float:
    return float(min(values)) if values else 0.0


def _safe_max(values: list[float]) -> float:
    return float(max(values)) if values else 0.0


def _finite(value: Any) -> float:
    try:
        number = float(value)
    except Exception:
        return 0.0
    return number if math.isfinite(number) else 0.0


def _normal_name(name: Any) -> str:
    return "".join(ch.lower() for ch in str(name) if ch.isalnum())


def _read_classic_pcap(path: str | Path) -> Iterator[tuple[float, bytes]]:
    raw = Path(path).read_bytes()
    if len(raw) < 24:
        raise ValueError("PCAP header is incomplete")

    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", False),
        b"\xa1\xb2\xc3\xd4": (">", False),
        b"\x4d\x3c\xb2\xa1": ("<", True),
        b"\xa1\xb2\x3c\x4d": (">", True),
    }
    if raw[:4] not in formats:
        raise ValueError(
            "classic PCAP required when Scapy is unavailable; "
            "install scapy for PCAPNG support"
        )

    endian, nanosecond = formats[raw[:4]]
    offset = 24
    while offset + 16 <= len(raw):
        ts_sec, ts_fraction, captured_len, _ = struct.unpack(
            endian + "IIII", raw[offset : offset + 16]
        )
        offset += 16
        if offset + captured_len > len(raw):
            break

        frame = raw[offset : offset + captured_len]
        offset += captured_len
        timestamp = float(ts_sec) + float(ts_fraction) / (
            1_000_000_000.0 if nanosecond else 1_000_000.0
        )
        yield timestamp, frame


def _scapy_packets(path: str | Path) -> Iterable[dict[str, Any]]:
    try:
        from scapy.all import IP, TCP, UDP, PcapReader
    except Exception:
        return []

    def _iter() -> Iterator[dict[str, Any]]:
        reader = PcapReader(str(path))
        try:
            for packet in reader:
                if IP not in packet:
                    continue
                ip = packet[IP]
                protocol = int(ip.proto)
                ip_header = int(getattr(ip, "ihl", 5) or 5) * 4
                total_len = int(getattr(ip, "len", 0) or len(bytes(ip)))

                if protocol == 6 and TCP in packet:
                    tcp = packet[TCP]
                    transport_header = int(
                        getattr(tcp, "dataofs", 5) or 5
                    ) * 4
                    yield {
                        "timestamp": float(packet.time),
                        "src_ip": str(ip.src),
                        "dst_ip": str(ip.dst),
                        "src_port": int(tcp.sport),
                        "dst_port": int(tcp.dport),
                        "protocol": 6,
                        "length": total_len,
                        "header_len": ip_header + transport_header,
                        "transport_header_len": transport_header,
                        "payload_len": max(
                            0, total_len - ip_header - transport_header
                        ),
                        "flags": int(tcp.flags),
                        "window": int(tcp.window),
                    }
                elif protocol == 17 and UDP in packet:
                    udp = packet[UDP]
                    yield {
                        "timestamp": float(packet.time),
                        "src_ip": str(ip.src),
                        "dst_ip": str(ip.dst),
                        "src_port": int(udp.sport),
                        "dst_port": int(udp.dport),
                        "protocol": 17,
                        "length": total_len,
                        "header_len": ip_header + 8,
                        "transport_header_len": 8,
                        "payload_len": max(0, total_len - ip_header - 8),
                        "flags": 0,
                        "window": 0,
                    }
        finally:
            reader.close()

    return _iter()


def _parse_frame(timestamp: float, raw: bytes) -> Optional[dict[str, Any]]:
    raw = bytes(raw)

    if raw and raw[0] >> 4 == 4:
        ip_offset = 0
    elif len(raw) >= 14:
        ip_offset = 14
        ethertype = struct.unpack("!H", raw[12:14])[0]
        while ethertype in (0x8100, 0x88A8, 0x9100):
            if len(raw) < ip_offset + 4:
                return None
            ethertype = struct.unpack(
                "!H", raw[ip_offset + 2 : ip_offset + 4]
            )[0]
            ip_offset += 4

        if ethertype != 0x0800:
            if len(raw) >= 17 and raw[14:16] == b"\x08\x00":
                ip_offset = 16
            elif len(raw) >= 21 and raw[0:2] == b"\x08\x00":
                ip_offset = 20
            else:
                return None
    else:
        return None

    if len(raw) < ip_offset + 20:
        return None

    version_ihl = raw[ip_offset]
    if version_ihl >> 4 != 4:
        return None
    ip_header = (version_ihl & 0x0F) * 4
    if ip_header < 20 or len(raw) < ip_offset + ip_header:
        return None

    total_len = struct.unpack(
        "!H", raw[ip_offset + 2 : ip_offset + 4]
    )[0]
    if not total_len:
        total_len = max(0, len(raw) - ip_offset)

    protocol = int(raw[ip_offset + 9])
    src_ip = ".".join(
        str(item) for item in raw[ip_offset + 12 : ip_offset + 16]
    )
    dst_ip = ".".join(
        str(item) for item in raw[ip_offset + 16 : ip_offset + 20]
    )
    l4_offset = ip_offset + ip_header

    if protocol == 6 and len(raw) >= l4_offset + 20:
        src_port, dst_port = struct.unpack(
            "!HH", raw[l4_offset : l4_offset + 4]
        )
        transport_header = (raw[l4_offset + 12] >> 4) * 4
        if transport_header < 20:
            transport_header = 20
        flags = int(raw[l4_offset + 13])
        window = struct.unpack(
            "!H", raw[l4_offset + 14 : l4_offset + 16]
        )[0]
        return {
            "timestamp": float(timestamp),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": int(src_port),
            "dst_port": int(dst_port),
            "protocol": 6,
            "length": int(total_len),
            "header_len": int(ip_header + transport_header),
            "transport_header_len": int(transport_header),
            "payload_len": max(
                0, int(total_len) - ip_header - transport_header
            ),
            "flags": flags,
            "window": int(window),
        }

    if protocol == 17 and len(raw) >= l4_offset + 8:
        src_port, dst_port = struct.unpack(
            "!HH", raw[l4_offset : l4_offset + 4]
        )
        return {
            "timestamp": float(timestamp),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": int(src_port),
            "dst_port": int(dst_port),
            "protocol": 17,
            "length": int(total_len),
            "header_len": int(ip_header + 8),
            "transport_header_len": 8,
            "payload_len": max(0, int(total_len) - ip_header - 8),
            "flags": 0,
            "window": 0,
        }

    return None


def _packet_records(path: str | Path) -> list[dict[str, Any]]:
    try:
        values = list(_scapy_packets(path))
        if values:
            return values
    except Exception:
        pass

    values: list[dict[str, Any]] = []
    for timestamp, raw in _read_classic_pcap(path):
        record = _parse_frame(timestamp, raw)
        if record is not None:
            values.append(record)
    return values


def _flow_key(packet: dict[str, Any]) -> tuple[int, tuple[tuple[str, int], ...]]:
    left = (str(packet["src_ip"]), int(packet["src_port"]))
    right = (str(packet["dst_ip"]), int(packet["dst_port"]))
    endpoints = tuple(sorted((left, right)))
    return int(packet["protocol"]), endpoints


def dominant_flow(
    path: str | Path,
) -> tuple[list[dict[str, Any]], tuple[str, int, str, int], int]:
    groups: dict[Any, list[dict[str, Any]]] = defaultdict(list)
    for packet in _packet_records(path):
        groups[_flow_key(packet)].append(packet)

    if not groups:
        raise ValueError("No IPv4 TCP/UDP flow could be extracted from PCAP")

    _, packets = max(
        groups.items(),
        key=lambda item: (
            len(item[1]),
            sum(int(packet["length"]) for packet in item[1]),
        ),
    )
    packets.sort(key=lambda item: float(item["timestamp"]))

    first = packets[0]
    forward = (
        str(first["src_ip"]),
        int(first["src_port"]),
        str(first["dst_ip"]),
        int(first["dst_port"]),
    )

    for packet in packets:
        packet["forward"] = (
            str(packet["src_ip"]) == forward[0]
            and int(packet["src_port"]) == forward[1]
        )

    return packets, forward, len(groups)


def _iats(packets: list[dict[str, Any]]) -> list[float]:
    return [
        max(
            0.0,
            (
                float(packets[index]["timestamp"])
                - float(packets[index - 1]["timestamp"])
            )
            * 1e6,
        )
        for index in range(1, len(packets))
    ]


def _active_idle(
    packets: list[dict[str, Any]],
    idle_threshold_us: float = 1_000_000.0,
) -> tuple[list[float], list[float]]:
    if len(packets) < 2:
        return [], []

    active: list[float] = []
    idle: list[float] = []
    active_start = float(packets[0]["timestamp"])
    previous = active_start

    for packet in packets[1:]:
        current = float(packet["timestamp"])
        gap_us = max(0.0, (current - previous) * 1e6)
        if gap_us > idle_threshold_us:
            active.append(max(0.0, (previous - active_start) * 1e6))
            idle.append(gap_us)
            active_start = current
        previous = current

    active.append(max(0.0, (previous - active_start) * 1e6))
    return active, idle


def _flag_count(packets: list[dict[str, Any]], mask: int) -> int:
    return sum(
        1
        for packet in packets
        if int(packet.get("flags") or 0) & mask
    )


def compute_cic_features(
    path: str | Path,
) -> tuple[dict[str, float], dict[str, Any]]:
    """Compute the CIC-style feature set used by the competition bridge."""
    packets, forward_tuple, flow_count = dominant_flow(path)
    forward_packets = [
        packet for packet in packets if bool(packet["forward"])
    ]
    backward_packets = [
        packet for packet in packets if not bool(packet["forward"])
    ]

    start = float(packets[0]["timestamp"])
    end = float(packets[-1]["timestamp"])
    duration_us = max(1.0, (end - start) * 1e6)
    duration_seconds = duration_us / 1e6

    all_lengths = [float(packet["length"]) for packet in packets]
    forward_lengths = [
        float(packet["length"]) for packet in forward_packets
    ]
    backward_lengths = [
        float(packet["length"]) for packet in backward_packets
    ]

    flow_iat = _iats(packets)
    forward_iat = _iats(forward_packets)
    backward_iat = _iats(backward_packets)
    active, idle = _active_idle(packets)

    total_forward = sum(forward_lengths)
    total_backward = sum(backward_lengths)
    total_packets = len(packets)
    total_bytes = total_forward + total_backward

    values: dict[str, float] = {
        "Dst Port": float(forward_tuple[3]),
        "Protocol": float(packets[0]["protocol"]),
        "Flow Duration": duration_us,
        "Tot Fwd Pkts": float(len(forward_packets)),
        "Tot Bwd Pkts": float(len(backward_packets)),
        "TotLen Fwd Pkts": total_forward,
        "TotLen Bwd Pkts": total_backward,
        "Fwd Pkt Len Max": _safe_max(forward_lengths),
        "Fwd Pkt Len Min": _safe_min(forward_lengths),
        "Fwd Pkt Len Mean": _safe_mean(forward_lengths),
        "Fwd Pkt Len Std": _safe_std(forward_lengths),
        "Bwd Pkt Len Max": _safe_max(backward_lengths),
        "Bwd Pkt Len Min": _safe_min(backward_lengths),
        "Bwd Pkt Len Mean": _safe_mean(backward_lengths),
        "Bwd Pkt Len Std": _safe_std(backward_lengths),
        "Flow Byts/s": (
            total_bytes / duration_seconds if duration_seconds > 0 else 0.0
        ),
        "Flow Pkts/s": (
            total_packets / duration_seconds if duration_seconds > 0 else 0.0
        ),
        "Flow IAT Mean": _safe_mean(flow_iat),
        "Flow IAT Std": _safe_std(flow_iat),
        "Flow IAT Max": _safe_max(flow_iat),
        "Flow IAT Min": _safe_min(flow_iat),
        "Fwd IAT Tot": sum(forward_iat),
        "Fwd IAT Mean": _safe_mean(forward_iat),
        "Fwd IAT Std": _safe_std(forward_iat),
        "Fwd IAT Max": _safe_max(forward_iat),
        "Fwd IAT Min": _safe_min(forward_iat),
        "Bwd IAT Tot": sum(backward_iat),
        "Bwd IAT Mean": _safe_mean(backward_iat),
        "Bwd IAT Std": _safe_std(backward_iat),
        "Bwd IAT Max": _safe_max(backward_iat),
        "Bwd IAT Min": _safe_min(backward_iat),
        "Fwd PSH Flags": float(_flag_count(forward_packets, 0x08)),
        "Bwd PSH Flags": float(_flag_count(backward_packets, 0x08)),
        "Fwd URG Flags": float(_flag_count(forward_packets, 0x20)),
        "Bwd URG Flags": float(_flag_count(backward_packets, 0x20)),
        "Fwd Header Len": float(
            sum(int(packet["header_len"]) for packet in forward_packets)
        ),
        "Bwd Header Len": float(
            sum(int(packet["header_len"]) for packet in backward_packets)
        ),
        "Fwd Pkts/s": (
            len(forward_packets) / duration_seconds
            if duration_seconds > 0
            else 0.0
        ),
        "Bwd Pkts/s": (
            len(backward_packets) / duration_seconds
            if duration_seconds > 0
            else 0.0
        ),
        "Pkt Len Min": _safe_min(all_lengths),
        "Pkt Len Max": _safe_max(all_lengths),
        "Pkt Len Mean": _safe_mean(all_lengths),
        "Pkt Len Std": _safe_std(all_lengths),
        "Pkt Len Var": _safe_var(all_lengths),
        "FIN Flag Cnt": float(_flag_count(packets, 0x01)),
        "SYN Flag Cnt": float(_flag_count(packets, 0x02)),
        "RST Flag Cnt": float(_flag_count(packets, 0x04)),
        "PSH Flag Cnt": float(_flag_count(packets, 0x08)),
        "ACK Flag Cnt": float(_flag_count(packets, 0x10)),
        "URG Flag Cnt": float(_flag_count(packets, 0x20)),
        "CWE Flag Count": float(_flag_count(packets, 0x80)),
        "CWR Flag Cnt": float(_flag_count(packets, 0x80)),
        "ECE Flag Cnt": float(_flag_count(packets, 0x40)),
        "Down/Up Ratio": (
            float(len(backward_packets))
            / max(1.0, float(len(forward_packets)))
        ),
        "Pkt Size Avg": total_bytes / max(1.0, float(total_packets)),
        "Fwd Seg Size Avg": _safe_mean(forward_lengths),
        "Bwd Seg Size Avg": _safe_mean(backward_lengths),
        "Fwd Byts/b Avg": 0.0,
        "Fwd Pkts/b Avg": 0.0,
        "Fwd Blk Rate Avg": 0.0,
        "Bwd Byts/b Avg": 0.0,
        "Bwd Pkts/b Avg": 0.0,
        "Bwd Blk Rate Avg": 0.0,
        "Subflow Fwd Pkts": float(len(forward_packets)),
        "Subflow Fwd Byts": total_forward,
        "Subflow Bwd Pkts": float(len(backward_packets)),
        "Subflow Bwd Byts": total_backward,
        "Init Fwd Win Byts": float(
            forward_packets[0]["window"] if forward_packets else 0
        ),
        "Init Bwd Win Byts": float(
            backward_packets[0]["window"] if backward_packets else 0
        ),
        "Fwd Act Data Pkts": float(
            sum(
                1
                for packet in forward_packets
                if int(packet["payload_len"]) > 0
            )
        ),
        "Fwd Seg Size Min": _safe_min(
            [
                float(packet["transport_header_len"])
                for packet in forward_packets
            ]
        ),
        "Active Mean": _safe_mean(active),
        "Active Std": _safe_std(active),
        "Active Max": _safe_max(active),
        "Active Min": _safe_min(active),
        "Idle Mean": _safe_mean(idle),
        "Idle Std": _safe_std(idle),
        "Idle Max": _safe_max(idle),
        "Idle Min": _safe_min(idle),
    }

    values.update(
        {
            "Fwd Header Length": values["Fwd Header Len"],
            "Bwd Header Length": values["Bwd Header Len"],
            "Average Packet Size": values["Pkt Size Avg"],
            "Avg Fwd Segment Size": values["Fwd Seg Size Avg"],
            "Avg Bwd Segment Size": values["Bwd Seg Size Avg"],
            "Min Seg Size Forward": values["Fwd Seg Size Min"],
            "Fwd Avg Bytes/Bulk": 0.0,
            "Fwd Avg Packets/Bulk": 0.0,
            "Fwd Avg Bulk Rate": 0.0,
            "Bwd Avg Bytes/Bulk": 0.0,
            "Bwd Avg Packets/Bulk": 0.0,
            "Bwd Avg Bulk Rate": 0.0,
        }
    )

    summary = {
        "dominant_flow_packet_count": total_packets,
        "pcap_flow_count": flow_count,
        "duration_seconds": duration_seconds,
        "forward_packets": len(forward_packets),
        "backward_packets": len(backward_packets),
        "forward_bytes": int(total_forward),
        "backward_bytes": int(total_backward),
        "protocol": "TCP" if int(packets[0]["protocol"]) == 6 else "UDP",
        "dst_port": int(forward_tuple[3]),
    }
    return values, summary


def contract_features(
    path: str | Path,
) -> tuple[dict[str, float], dict[str, Any]]:
    """Align extracted feature names to the live model-service contract."""
    contract = feature_contract()
    names = list(contract["feature_names"])
    raw, summary = compute_cic_features(path)
    normalized = {_normal_name(key): value for key, value in raw.items()}

    features: dict[str, float] = {}
    recognized = 0
    for name in names:
        key = _normal_name(name)
        if key in normalized:
            recognized += 1
            value = normalized[key]
        else:
            value = 0.0
        features[name] = _finite(value)

    summary["feature_count"] = len(features)
    summary["recognized_feature_count"] = recognized
    summary["recognized_feature_ratio"] = (
        recognized / max(1.0, float(len(features)))
    )
    return features, summary


def predict_pcap(
    path: str | Path,
    context_id: str,
    use_temporal: bool = True,
) -> dict[str, Any]:
    """Extract one dominant flow and submit it to AegisFusion."""
    started = time.perf_counter()
    result: dict[str, Any] = {
        "success": False,
        "attempted": True,
        "aegisfusion_inference": False,
        "model": "AegisFusion_NIDS",
        "reason": None,
    }

    try:
        service_health = health()
        if not service_health.get("model_ready"):
            raise RuntimeError(
                "AegisFusion model is not ready: %s"
                % service_health.get("model_error")
            )

        features, extraction = contract_features(path)
        response = _http_json(
            "POST",
            "/api/v1/aegisfusion/predict/flow",
            {
                "features": features,
                "context_id": str(context_id or "offline-flow")[:128],
                "use_temporal": bool(use_temporal),
            },
            timeout=30.0,
        )
        result.update(response)
        result.update(
            {
                "success": True,
                "attempted": True,
                "aegisfusion_inference": True,
                "model": "AegisFusion_NIDS",
                "model_service": AEGIS_URL,
                "feature_extraction": extraction,
            }
        )
    except Exception as exc:
        result["reason"] = "%s: %s" % (type(exc).__name__, exc)

    result["bridge_latency_ms"] = round(
        (time.perf_counter() - started) * 1000.0,
        3,
    )
    return result
