#!/usr/bin/env python3
"""Self-contained regression test for the metadata-only production path.

No dataset, model weight, Scapy installation, live network, or model service is
required. The test verifies:

- bidirectional packets are grouped into one flow;
- CIC-style statistics are produced;
- packet evidence reports metadata only;
- application payload text never appears in serialized evidence;
- final cross-flow thresholds still trigger scan, SSH burst and SYN flood;
- final sequence/tunnel/promotion logic remains aligned with the freeze.
"""
from __future__ import annotations

import json
import socket
import struct
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.aegisfusion_bridge import compute_cic_features, dominant_flow
from backend.engine import (
    _metadata_tunnel_score,
    _sequence_metrics,
    _should_promote_family_alert,
)
from backend.packet_evidence import extract_packet_evidence
from backend.realtime_monitor import CapturedPacket, RealtimeMonitor


def ipv4(address: str) -> bytes:
    return socket.inet_aton(address)


def tcp_frame(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    *,
    flags: int,
    payload: bytes = b"",
    window: int = 64240,
) -> bytes:
    ethernet = (
        b"\x02\x00\x00\x00\x00\x02"
        b"\x02\x00\x00\x00\x00\x01"
        b"\x08\x00"
    )

    ip_header_len = 20
    tcp_header_len = 20
    total_len = ip_header_len + tcp_header_len + len(payload)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        1,
        0x4000,
        64,
        6,
        0,
        ipv4(src_ip),
        ipv4(dst_ip),
    )
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        1,
        1,
        0x50,
        flags,
        window,
        0,
        0,
    )
    return ethernet + ip_header + tcp_header + payload


def write_classic_pcap(path: Path) -> None:
    output = bytearray(
        struct.pack(
            "<IHHIIII",
            0xA1B2C3D4,
            2,
            4,
            0,
            0,
            65535,
            1,
        )
    )

    client = ("10.0.0.10", 51000)
    server = ("10.0.0.20", 443)
    frames = [
        (1, 0, tcp_frame(client[0], server[0], client[1], server[1], flags=0x02)),
        (1, 1000, tcp_frame(server[0], client[0], server[1], client[1], flags=0x12)),
        (1, 2000, tcp_frame(client[0], server[0], client[1], server[1], flags=0x10)),
        (
            1,
            3000,
            tcp_frame(
                client[0],
                server[0],
                client[1],
                server[1],
                flags=0x18,
                payload=b"DO_NOT_LEAK_THIS_SECRET_MARKER",
            ),
        ),
        (
            1,
            5000,
            tcp_frame(
                server[0],
                client[0],
                server[1],
                client[1],
                flags=0x18,
                payload=b"opaque-response-bytes",
            ),
        ),
        (1, 6000, tcp_frame(client[0], server[0], client[1], server[1], flags=0x11)),
    ]

    for seconds, microseconds, frame in frames:
        output.extend(
            struct.pack(
                "<IIII",
                seconds,
                microseconds,
                len(frame),
                len(frame),
            )
        )
        output.extend(frame)

    path.write_bytes(bytes(output))


def alert_behaviors(monitor: RealtimeMonitor) -> set[str]:
    return {
        str(item.get("behavior"))
        for item in monitor.status(0, 100, 0)["alerts"]
    }


def feed_syn(
    monitor: RealtimeMonitor,
    *,
    timestamp: float,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
) -> None:
    frame = tcp_frame(
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        flags=0x02,
    )
    monitor._on_packet(CapturedPacket(frame, timestamp))


def test_cross_flow_thresholds(root: Path) -> None:
    scan = RealtimeMonitor(root / "scan")
    for index in range(8):
        feed_syn(
            scan,
            timestamp=100.0 + index * 0.1,
            src_ip="10.1.0.10",
            dst_ip="10.1.0.20",
            src_port=40000 + index,
            dst_port=10000 + index,
        )
    assert "scan_short_connection" in alert_behaviors(scan)

    ssh = RealtimeMonitor(root / "ssh")
    for index in range(7):
        feed_syn(
            ssh,
            timestamp=200.0 + index * 0.2,
            src_ip="10.2.0.10",
            dst_ip="10.2.0.20",
            src_port=41000 + index,
            dst_port=22,
        )
    assert "ssh_bruteforce" in alert_behaviors(ssh)

    dos = RealtimeMonitor(root / "dos")
    for index in range(30):
        feed_syn(
            dos,
            timestamp=300.0 + index * 0.02,
            src_ip="10.3.0.10",
            dst_ip="10.3.0.20",
            src_port=42000 + index,
            dst_port=8080,
        )
    assert "dos_syn_flood" in alert_behaviors(dos)


def test_engine_freeze_logic() -> None:
    sequence = []
    for index in range(8):
        up_time = index * 0.30
        down_time = up_time + 0.10
        sequence.append(
            {
                "direction": "up",
                "relative_time": up_time,
                "iat_seconds": 0.20 if index else 0.0,
                "payload_len": 8,
                "tcp_payload_len": 8,
            }
        )
        sequence.append(
            {
                "direction": "down",
                "relative_time": down_time,
                "iat_seconds": 0.10,
                "payload_len": 320,
                "tcp_payload_len": 320,
            }
        )

    metrics = _sequence_metrics({"packet_sequence": sequence})
    assert metrics["count"] == 16
    assert metrics["up_count"] == 8
    assert metrics["down_count"] == 8
    assert metrics["switch_ratio"] >= 0.68
    assert metrics["up_payload_median"] == 8.0
    assert metrics["down_payload_median"] == 320.0
    assert metrics["down_payload_median"] >= max(
        256.0, metrics["up_payload_median"] * 8.0
    )

    packet_result = {
        "flow_stats": {
            "packet_count": 24,
            "up_bytes": 5000,
            "down_bytes": 6000,
            "avg_iat_seconds": 0.40,
            "max_iat_seconds": 0.80,
        }
    }
    benign_score, _ = _metadata_tunnel_score(
        packet_result,
        {
            "family": "Benign",
            "feature_extraction": {"duration_seconds": 10.0},
        },
    )
    assert abs(benign_score - 0.75) < 1e-9

    infiltration_score, _ = _metadata_tunnel_score(
        packet_result,
        {
            "family": "Infiltration",
            "feature_extraction": {"duration_seconds": 10.0},
        },
    )
    assert abs(infiltration_score - 1.0) < 1e-9

    assert _should_promote_family_alert(
        {"family": "Botnet", "attack_probability": 0.01}, []
    )
    assert not _should_promote_family_alert(
        {"family": "Infiltration", "attack_probability": 0.54}, []
    )
    assert _should_promote_family_alert(
        {"family": "Infiltration", "attack_probability": 0.55}, []
    )
    assert _should_promote_family_alert(
        {"family": "Infiltration", "attack_probability": 0.10},
        [{"behavior": "abnormal_command_sequence"}],
    )
    assert not _should_promote_family_alert(
        {"family": "Infiltration", "attack_probability": 0.10},
        [{"behavior": "tls_periodic_c2"}],
    )


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="aegisfusion-metadata-") as directory:
        root = Path(directory)
        pcap = root / "synthetic.pcap"
        write_classic_pcap(pcap)

        packets, forward, flow_count = dominant_flow(pcap)
        assert flow_count == 1, flow_count
        assert len(packets) == 6, len(packets)
        assert forward == ("10.0.0.10", 51000, "10.0.0.20", 443), forward

        features, summary = compute_cic_features(pcap)
        assert features["Dst Port"] == 443.0
        assert features["Protocol"] == 6.0
        assert features["Tot Fwd Pkts"] == 4.0
        assert features["Tot Bwd Pkts"] == 2.0
        assert features["Flow Duration"] > 0.0
        assert summary["pcap_flow_count"] == 1
        assert summary["dominant_flow_packet_count"] == 6

        packet_result = extract_packet_evidence(pcap, max_packets=100)
        assert packet_result["available"] is True
        assert packet_result["content_inspection"] is False
        assert packet_result["decryption_performed"] is False
        assert packet_result["packet_count"] == 6

        rendered = json.dumps(packet_result, ensure_ascii=False)
        assert "DO_NOT_LEAK_THIS_SECRET_MARKER" not in rendered
        assert "opaque-response-bytes" not in rendered
        assert "payload_preview" not in rendered

        test_cross_flow_thresholds(root / "realtime-tests")
        test_engine_freeze_logic()

        print("[OK] one bidirectional flow assembled")
        print("[OK] CIC-style metadata features extracted")
        print("[OK] payload text absent from evidence output")
        print("[OK] scan / SSH burst / SYN-flood cross-flow thresholds")
        print("[OK] sequence / tunnel / family-promotion freeze logic")
        print("OFFLINE_METADATA_PIPELINE_OK")


if __name__ == "__main__":
    main()
