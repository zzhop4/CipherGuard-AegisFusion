#!/usr/bin/env python3
"""Passive realtime flow monitor for CipherGuard-AegisFusion.

Public-core port of the competition realtime monitor. It provides:

- passive live capture (Linux AF_PACKET; optional Scapy fallback elsewhere);
- classic-PCAP replay;
- bidirectional five-tuple flow assembly;
- bounded flow windows and asynchronous inspection through ``engine.detect_file``;
- metadata-only cross-flow rules for scan / SSH burst / SYN flood;
- ten-minute brute-force -> post-compromise correlation;
- operational metrics, sessions and JSONL event persistence.

No attack-generation code is included here. The monitor does not decrypt traffic
or inspect application payload text.
"""
from __future__ import annotations

import hashlib
import json
import os
import queue
import socket
import struct
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Deque, Iterable, Iterator, Optional

try:
    from .engine import BEHAVIOR_STAGE, detect_file
except ImportError:
    from engine import BEHAVIOR_STAGE, detect_file


try:
    from scapy.all import Ether, IP, get_if_list, sniff

    SCAPY_AVAILABLE = True
    SCAPY_ERROR = None
except Exception as exc:  # optional dependency
    Ether = IP = get_if_list = sniff = None
    SCAPY_AVAILABLE = False
    SCAPY_ERROR = "%s: %s" % (type(exc).__name__, exc)


def _ensure_ethernet_ipv4(raw: bytes) -> bytes:
    """Normalize common capture link headers to Ethernet + IPv4."""
    raw = bytes(raw)
    fake = b"\x00" * 12 + b"\x08\x00"

    if raw and raw[0] >> 4 == 4:  # raw IPv4
        return fake + raw

    if len(raw) >= 14:
        ethertype = struct.unpack("!H", raw[12:14])[0]
        if ethertype == 0x0800 or ethertype in (0x8100, 0x88A8, 0x9100):
            return raw

    # Linux cooked capture v1: protocol at 14:16, payload begins at 16.
    if len(raw) >= 17 and raw[14:16] == b"\x08\x00" and raw[16] >> 4 == 4:
        return fake + raw[16:]

    # Linux cooked capture v2: protocol at 0:2, payload begins at 20.
    if len(raw) >= 21 and raw[0:2] == b"\x08\x00" and raw[20] >> 4 == 4:
        return fake + raw[20:]

    # BSD/loopback NULL header followed by IPv4.
    if len(raw) >= 5 and raw[4] >> 4 == 4:
        return fake + raw[4:]

    return raw


class CapturedPacket:
    __slots__ = ("raw", "timestamp")

    def __init__(self, raw: bytes, timestamp: float):
        self.raw = _ensure_ethernet_ipv4(bytes(raw))
        self.timestamp = float(timestamp)

    def copy(self) -> "CapturedPacket":
        return CapturedPacket(bytes(self.raw), self.timestamp)


def _pcap_packets(path: str | Path) -> Iterator[CapturedPacket]:
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
        raise ValueError("replay currently requires classic PCAP")

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
        yield CapturedPacket(frame, timestamp)


def _write_pcap(path: str | Path, packets: Iterable[CapturedPacket]) -> None:
    """Write normalized Ethernet frames to classic little-endian PCAP."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(
            struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        )
        for packet in packets:
            raw = bytes(packet.raw)
            ts_sec = int(packet.timestamp)
            ts_usec = int(round((packet.timestamp - ts_sec) * 1_000_000.0))
            if ts_usec >= 1_000_000:
                ts_sec += 1
                ts_usec -= 1_000_000
            handle.write(
                struct.pack("<IIII", ts_sec, ts_usec, len(raw), len(raw))
            )
            handle.write(raw)


def _parse_frame(raw: bytes, timestamp: float) -> Optional[dict[str, Any]]:
    """Parse Ethernet/VLAN + IPv4 + TCP/UDP metadata only."""
    raw = _ensure_ethernet_ipv4(raw)
    if len(raw) < 14:
        return None

    offset = 14
    ethertype = struct.unpack("!H", raw[12:14])[0]
    while ethertype in (0x8100, 0x88A8, 0x9100):
        if len(raw) < offset + 4:
            return None
        ethertype = struct.unpack("!H", raw[offset + 2 : offset + 4])[0]
        offset += 4
    if ethertype != 0x0800 or len(raw) < offset + 20:
        return None

    version_ihl = raw[offset]
    if version_ihl >> 4 != 4:
        return None
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(raw) < offset + ihl:
        return None

    total_len = struct.unpack("!H", raw[offset + 2 : offset + 4])[0]
    protocol = int(raw[offset + 9])
    src_ip = socket.inet_ntoa(raw[offset + 12 : offset + 16])
    dst_ip = socket.inet_ntoa(raw[offset + 16 : offset + 20])
    l4 = offset + ihl

    if protocol == 6 and len(raw) >= l4 + 20:
        src_port, dst_port = struct.unpack("!HH", raw[l4 : l4 + 4])
        flags_value = int(raw[l4 + 13])
        flag_names = "".join(
            name
            for mask, name in (
                (0x02, "S"),
                (0x10, "A"),
                (0x08, "P"),
                (0x01, "F"),
                (0x04, "R"),
                (0x20, "U"),
                (0x40, "E"),
                (0x80, "C"),
            )
            if flags_value & mask
        )
        return {
            "timestamp": float(timestamp),
            "protocol": "TCP",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": int(src_port),
            "dst_port": int(dst_port),
            "flags": flag_names,
            "length": int(total_len or max(0, len(raw) - offset)),
        }

    if protocol == 17 and len(raw) >= l4 + 8:
        src_port, dst_port = struct.unpack("!HH", raw[l4 : l4 + 4])
        return {
            "timestamp": float(timestamp),
            "protocol": "UDP",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": int(src_port),
            "dst_port": int(dst_port),
            "flags": "",
            "length": int(total_len or max(0, len(raw) - offset)),
        }

    return None


class FlowState:
    def __init__(
        self,
        flow_id: str,
        protocol: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        ts: float,
        packet_window: int = 600,
    ) -> None:
        self.flow_id = flow_id
        self.protocol = protocol
        self.client_ip = src_ip
        self.client_port = int(src_port)
        self.server_ip = dst_ip
        self.server_port = int(dst_port)
        self.first_seen = float(ts)
        self.last_seen = float(ts)
        self.packet_count = 0
        self.byte_count = 0
        self.up_bytes = 0
        self.down_bytes = 0
        self.packets: Deque[CapturedPacket] = deque(maxlen=packet_window)
        self.first_packet: Optional[CapturedPacket] = None
        self.last_inspected_count = 0
        self.last_inspected_at = 0.0
        self.inspection_pending = False
        self.status = "collecting"
        self.latest_risk = 0.0
        self.latest_behavior = None
        self.latest_model_family = None
        self.latest_model_confidence = None
        self.latest_temporal_probability = None
        self.latest_context_depth = None

    def add(
        self,
        packet: CapturedPacket,
        ts: float,
        length: int,
        src_ip: str,
        src_port: int,
    ) -> None:
        self.last_seen = max(self.last_seen, float(ts))
        self.packet_count += 1
        self.byte_count += int(length)
        if src_ip == self.client_ip and int(src_port) == self.client_port:
            self.up_bytes += int(length)
        else:
            self.down_bytes += int(length)

        packet_copy = packet.copy()
        if self.first_packet is None:
            self.first_packet = packet_copy.copy()
        self.packets.append(packet_copy)

    def summary(self) -> dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "protocol": self.protocol,
            "src_ip": self.client_ip,
            "src_port": self.client_port,
            "dst_ip": self.server_ip,
            "dst_port": self.server_port,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_seconds": round(
                max(0.0, self.last_seen - self.first_seen), 6
            ),
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "up_bytes": self.up_bytes,
            "down_bytes": self.down_bytes,
            "status": self.status,
            "latest_risk": self.latest_risk,
            "latest_behavior": self.latest_behavior,
            "latest_model_family": self.latest_model_family,
            "latest_model_confidence": self.latest_model_confidence,
            "latest_temporal_probability": self.latest_temporal_probability,
            "latest_context_depth": self.latest_context_depth,
            "last_inspected_count": self.last_inspected_count,
        }


class RealtimeMonitor:
    def __init__(self, application_root: str | Path) -> None:
        self.application_root = Path(application_root).resolve()
        self.runtime_root = self.application_root / "runtime" / "realtime"
        self.runtime_root.mkdir(parents=True, exist_ok=True)
        self.session_root = self.runtime_root / "idle"

        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.capture_thread: Optional[threading.Thread] = None
        self.inspection_thread: Optional[threading.Thread] = None
        self.inspection_queue: queue.Queue[Any] = queue.Queue(maxsize=256)

        self.running = False
        self.mode = None
        self.interface = None
        self.sample = None
        self.started_at = None
        self.stopped_at = None
        self.last_error = None
        self.config = self._default_config()
        self.metrics = self._empty_metrics()

        self.flows: dict[Any, FlowState] = {}
        self.alerts: Deque[dict[str, Any]] = deque(maxlen=1000)
        self.sessions: Deque[dict[str, Any]] = deque(maxlen=300)
        self.alert_sequence = 0
        self.alert_dedup: dict[str, float] = {}

        self.source_syn_events: defaultdict[str, Deque[Any]] = defaultdict(deque)
        self.target_syn_events: defaultdict[Any, Deque[Any]] = defaultdict(deque)
        self.ssh_syn_events: defaultdict[Any, Deque[Any]] = defaultdict(deque)
        self.bruteforce_events: defaultdict[Any, Deque[Any]] = defaultdict(deque)

    @staticmethod
    def _default_config() -> dict[str, Any]:
        return {
            "min_flow_packets": 12,
            "flow_timeout_seconds": 2.0,
            "reinspect_packets": 30,
            "inactive_flow_seconds": 90.0,
            "max_capture_packets": 0,
            "replay_speed": 25.0,
            "bpf_filter": "tcp or udp",
            "use_temporal": True,
            "context_prefix": "realtime",
            "ssh_ports": [22],
        }

    @staticmethod
    def _empty_metrics() -> dict[str, Any]:
        return {
            "packets_seen": 0,
            "bytes_seen": 0,
            "flows_created": 0,
            "flows_inspected": 0,
            "normal_windows": 0,
            "alert_windows": 0,
            "alerts_emitted": 0,
            "high_risk_alerts": 0,
            "inspection_errors": 0,
            "queue_drops": 0,
            "detection_latency_ms_sum": 0.0,
            "detection_latency_count": 0,
        }

    def list_interfaces(self) -> list[str]:
        values: list[str] = []
        if SCAPY_AVAILABLE and get_if_list is not None:
            try:
                values.extend(str(value) for value in get_if_list())
            except Exception:
                pass
        try:
            values.extend(name for _, name in socket.if_nameindex())
        except Exception:
            pass
        return sorted(set(values))

    def start(
        self,
        mode: str = "live",
        interface: Optional[str] = None,
        sample: Optional[str] = None,
        **options: Any,
    ) -> dict[str, Any]:
        mode = str(mode or "live").lower()
        if mode not in {"live", "replay"}:
            raise ValueError("mode must be 'live' or 'replay'")
        replay_path = None
        if mode == "replay":
            if not sample:
                raise ValueError("replay mode requires sample=<pcap path>")
            replay_path = Path(sample).expanduser().resolve()
            if not replay_path.is_file():
                raise FileNotFoundError(replay_path)

        with self.lock:
            if self.running:
                raise RuntimeError("realtime monitor is already running")

            config = self._default_config()
            for key, value in options.items():
                if key in config and value is not None:
                    config[key] = value
            config["min_flow_packets"] = max(1, int(config["min_flow_packets"]))
            config["reinspect_packets"] = max(1, int(config["reinspect_packets"]))
            config["flow_timeout_seconds"] = max(
                0.1, float(config["flow_timeout_seconds"])
            )
            config["inactive_flow_seconds"] = max(
                config["flow_timeout_seconds"],
                float(config["inactive_flow_seconds"]),
            )
            config["replay_speed"] = max(0.01, float(config["replay_speed"]))
            config["ssh_ports"] = sorted(
                {int(value) for value in (config.get("ssh_ports") or [22])}
            )

            self.config = config
            self.mode = mode
            self.interface = interface
            self.sample = str(replay_path) if replay_path else None
            self.started_at = time.time()
            self.stopped_at = None
            self.last_error = None
            self.stop_event = threading.Event()
            self.inspection_queue = queue.Queue(maxsize=256)
            self.flows.clear()
            self.alerts.clear()
            self.sessions.clear()
            self.alert_dedup.clear()
            self.source_syn_events.clear()
            self.target_syn_events.clear()
            self.ssh_syn_events.clear()
            self.bruteforce_events.clear()
            self.alert_sequence = 0
            self.metrics = self._empty_metrics()
            session_name = time.strftime("session_%Y%m%d_%H%M%S")
            self.session_root = self.runtime_root / session_name
            self.session_root.mkdir(parents=True, exist_ok=True)
            self.running = True

            self.inspection_thread = threading.Thread(
                target=self._inspection_loop,
                name="aegisfusion-inspection",
                daemon=True,
            )
            self.capture_thread = threading.Thread(
                target=self._capture_loop,
                args=(replay_path,),
                name="aegisfusion-capture",
                daemon=True,
            )
            self.inspection_thread.start()
            self.capture_thread.start()

        return self.status()

    def stop(self) -> dict[str, Any]:
        self.stop_event.set()
        self._sweep(force=True)
        if self.capture_thread is not None:
            self.capture_thread.join(timeout=3.0)
        self.force_inspect_all(reason="monitor_stop", timeout=8.0)
        if self.inspection_thread is not None:
            self.inspection_thread.join(timeout=3.0)
        with self.lock:
            self.running = False
            self.stopped_at = time.time()
        return self.status()

    def _capture_loop(self, replay_path: Optional[Path]) -> None:
        try:
            if replay_path is not None:
                self._run_replay(replay_path)
            else:
                self._run_live()
        except Exception as exc:
            with self.lock:
                self.last_error = "%s: %s" % (type(exc).__name__, exc)
        finally:
            self._sweep(force=True)
            with self.lock:
                if self.mode == "replay":
                    self.running = False
                    self.stopped_at = time.time()

    def _run_live(self) -> None:
        if hasattr(socket, "AF_PACKET"):
            protocol = socket.ntohs(0x0003)
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, protocol)
            try:
                if self.interface:
                    sock.bind((self.interface, 0))
                sock.settimeout(0.5)
                while not self.stop_event.is_set():
                    if self._packet_limit_reached():
                        break
                    try:
                        raw, _ = sock.recvfrom(65535)
                    except socket.timeout:
                        self._sweep()
                        continue
                    self._on_packet(CapturedPacket(raw, time.time()))
                    self._sweep()
            finally:
                sock.close()
            return

        if not SCAPY_AVAILABLE or sniff is None:
            raise RuntimeError(
                "live capture requires Linux AF_PACKET or optional Scapy/Npcap"
            )

        def callback(packet: Any) -> None:
            if self.stop_event.is_set() or self._packet_limit_reached():
                return
            try:
                timestamp = float(packet.time)
                if IP is not None and packet.haslayer(IP):
                    raw = bytes(Ether() / packet[IP]) if Ether is not None else bytes(packet)
                else:
                    raw = bytes(packet)
                self._on_packet(CapturedPacket(raw, timestamp))
            except Exception:
                return

        sniff(
            iface=self.interface,
            filter=str(self.config.get("bpf_filter") or "tcp or udp"),
            prn=callback,
            store=False,
            stop_filter=lambda _: self.stop_event.is_set()
            or self._packet_limit_reached(),
        )

    def _run_replay(self, replay_path: Path) -> None:
        previous_timestamp = None
        speed = float(self.config.get("replay_speed") or 25.0)
        for packet in _pcap_packets(replay_path):
            if self.stop_event.is_set() or self._packet_limit_reached():
                break
            if previous_timestamp is not None:
                delay = max(0.0, packet.timestamp - previous_timestamp) / speed
                if delay > 0:
                    self.stop_event.wait(min(delay, 0.25))
            previous_timestamp = packet.timestamp
            self._on_packet(packet)
            self._sweep()
        self._sweep(force=True)

    def _packet_limit_reached(self) -> bool:
        limit = int(self.config.get("max_capture_packets") or 0)
        return limit > 0 and int(self.metrics["packets_seen"]) >= limit

    @staticmethod
    def _normalize_packet(packet: CapturedPacket) -> CapturedPacket:
        return CapturedPacket(packet.raw, packet.timestamp)

    @staticmethod
    def _packet_meta(packet: CapturedPacket) -> Optional[dict[str, Any]]:
        return _parse_frame(packet.raw, packet.timestamp)

    @staticmethod
    def _canonical_key(meta: dict[str, Any]) -> tuple[Any, ...]:
        left = (str(meta["src_ip"]), int(meta["src_port"]))
        right = (str(meta["dst_ip"]), int(meta["dst_port"]))
        return (str(meta["protocol"]),) + tuple(sorted((left, right)))

    @staticmethod
    def _flow_id(key: tuple[Any, ...]) -> str:
        digest = hashlib.sha1(repr(key).encode("utf-8")).hexdigest()[:16]
        return "flow_" + digest

    def _on_packet(self, packet: CapturedPacket) -> None:
        packet = self._normalize_packet(packet)
        meta = self._packet_meta(packet)
        if meta is None:
            return

        key = self._canonical_key(meta)
        now = float(meta["timestamp"])
        with self.lock:
            flow = self.flows.get(key)
            if flow is None:
                flow = FlowState(
                    self._flow_id(key),
                    meta["protocol"],
                    meta["src_ip"],
                    meta["src_port"],
                    meta["dst_ip"],
                    meta["dst_port"],
                    now,
                )
                self.flows[key] = flow
                self.metrics["flows_created"] += 1

            flow.add(
                packet,
                now,
                int(meta["length"]),
                meta["src_ip"],
                meta["src_port"],
            )
            self.metrics["packets_seen"] += 1
            self.metrics["bytes_seen"] += int(meta["length"])

        self._update_cross_flow_rules(meta, flow)

        with self.lock:
            initial_ready = (
                flow.last_inspected_count == 0
                and flow.packet_count >= int(self.config["min_flow_packets"])
            )
            periodic_ready = (
                flow.last_inspected_count > 0
                and flow.packet_count - flow.last_inspected_count
                >= int(self.config["reinspect_packets"])
            )
        if initial_ready:
            self._schedule_inspection(key, "minimum_flow_evidence")
        elif periodic_ready:
            self._schedule_inspection(key, "periodic_flow_update")

    @staticmethod
    def _prune(events: Deque[Any], now: float, horizon: float) -> None:
        while events and now - float(events[0][0]) > horizon:
            events.popleft()

    def _update_cross_flow_rules(
        self, meta: dict[str, Any], flow: FlowState
    ) -> None:
        if (
            meta["protocol"] != "TCP"
            or "S" not in meta["flags"]
            or "A" in meta["flags"]
        ):
            return

        ts = float(meta["timestamp"])
        src = str(meta["src_ip"])
        dst = str(meta["dst_ip"])
        dport = int(meta["dst_port"])

        with self.lock:
            source_events = self.source_syn_events[src]
            source_events.append((ts, dst, dport, flow.flow_id))
            self._prune(source_events, ts, 5.0)

            target_events = self.target_syn_events[(src, dst)]
            target_events.append((ts, dport, flow.flow_id))
            self._prune(target_events, ts, 2.0)

            if dport in set(self.config.get("ssh_ports") or [22]):
                ssh_events = self.ssh_syn_events[(src, dst)]
                ssh_events.append((ts, dport, flow.flow_id))
                self._prune(ssh_events, ts, 20.0)
            else:
                ssh_events = ()

            scan_targets = {(event[1], event[2]) for event in source_events}
            # Count unique flow IDs: loopback/libpcap may duplicate one SYN frame.
            scan_count = len({event[3] for event in source_events})
            target_count = len({event[2] for event in target_events})
            ssh_count = len({event[2] for event in ssh_events})

        if scan_count >= 8 and len(scan_targets) >= 6:
            self._emit_cross_flow_alert(
                behavior="scan_short_connection",
                src_ip=src,
                dst_ip=dst,
                dst_port=dport,
                flow_id=flow.flow_id,
                risk=88.0,
                probability=0.88,
                evidence=[
                    "5秒内观察到%d个唯一SYN Flow" % scan_count,
                    "触达%d个不同目标/端口组合" % len(scan_targets),
                    "跨Flow实时聚合规则，不依赖载荷解密",
                ],
                dedup_key="scan:%s" % src,
                cooldown=15.0,
            )

        if ssh_count >= 7:
            self._emit_cross_flow_alert(
                behavior="ssh_bruteforce",
                src_ip=src,
                dst_ip=dst,
                dst_port=dport,
                flow_id=flow.flow_id,
                risk=93.0,
                probability=0.93,
                evidence=[
                    "20秒内对同一目标认证服务端口发起%d个唯一SYN Flow" % ssh_count,
                    "符合SSH暴力破解的高频认证前置行为",
                    "IP和端口仅用于在线关联与告警展示",
                ],
                dedup_key="ssh:%s:%s" % (src, dst),
                cooldown=20.0,
            )

        if target_count >= 30:
            self._emit_cross_flow_alert(
                behavior="dos_syn_flood",
                src_ip=src,
                dst_ip=dst,
                dst_port=dport,
                flow_id=flow.flow_id,
                risk=96.0,
                probability=0.96,
                evidence=[
                    "2秒内同源到同目标出现%d个唯一SYN Flow" % target_count,
                    "连接建立速率超过实时SYN洪泛阈值",
                ],
                dedup_key="dos:%s:%s" % (src, dst),
                cooldown=10.0,
            )

    def _emit_cross_flow_alert(
        self,
        behavior: str,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        flow_id: str,
        risk: float,
        probability: float,
        evidence: list[str],
        dedup_key: str,
        cooldown: float,
    ) -> None:
        alert = {
            "flow_id": flow_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": None,
            "dst_port": dst_port,
            "encrypted_protocol": "TCP",
            "service_class": "realtime_behavior_aggregation",
            "behavior": behavior,
            "attack_stage": BEHAVIOR_STAGE.get(behavior),
            "risk_score": float(risk),
            "attack_probability": float(probability),
            "anomaly_score": float(probability),
            "rule_score": float(probability),
            "evidence": list(evidence),
            "rule_hits": [],
            "packet_evidence": [],
            "detection_source": "cross_flow_realtime_rule",
            "packets_used": None,
            "realtime": True,
        }
        self._append_alert(alert, dedup_key, cooldown)

    def _record_bruteforce_event(self, alert: dict[str, Any]) -> None:
        if alert.get("behavior") not in (
            "ssh_bruteforce",
            "credential_bruteforce",
        ):
            return
        src = alert.get("src_ip")
        dst = alert.get("dst_ip")
        if not src or not dst:
            return
        now = time.time()
        events = self.bruteforce_events[(src, dst)]
        events.append((now, alert.get("alert_id"), alert.get("flow_id")))
        self._prune(events, now, 600.0)

    def _post_bruteforce_alert(
        self, alert: dict[str, Any]
    ) -> Optional[dict[str, Any]]:
        if alert.get("behavior") not in (
            "infiltration_activity",
            "post_login_abnormal",
            "abnormal_command_sequence",
            "encrypted_tunnel",
            "data_exfiltration",
        ):
            return None
        src = alert.get("src_ip")
        dst = alert.get("dst_ip")
        if not src or not dst:
            return None
        now = time.time()
        events = self.bruteforce_events.get((src, dst))
        if not events:
            return None
        self._prune(events, now, 600.0)
        if not events:
            return None

        correlated = dict(alert)
        correlated.update(
            {
                "behavior": "bruteforce_post_action",
                "attack_stage": BEHAVIOR_STAGE["bruteforce_post_action"],
                "risk_score": max(
                    94.0, float(alert.get("risk_score") or 0.0)
                ),
                "attack_probability": max(
                    0.94, float(alert.get("attack_probability") or 0.0)
                ),
                "anomaly_score": max(
                    0.94, float(alert.get("anomaly_score") or 0.0)
                ),
                "rule_score": 0.94,
                "detection_source": "cross_flow_post_bruteforce_correlation",
                "evidence": list(alert.get("evidence") or [])
                + [
                    "同一源和目标在10分钟内先出现暴力破解活动",
                    "随后出现命令序列、渗透、隧道或外传行为",
                    "系统将其关联为暴力破解后的异常操作",
                ],
                "correlated_bruteforce_count": len(events),
                "correlated_bruteforce_alert_ids": [
                    item[1] for item in events
                ],
            }
        )
        return correlated

    def _append_alert(
        self,
        alert: dict[str, Any],
        dedup_key: str,
        cooldown: float = 10.0,
    ) -> bool:
        now = time.time()
        with self.lock:
            previous = self.alert_dedup.get(dedup_key, 0.0)
            if now - previous < cooldown:
                return False
            self.alert_dedup[dedup_key] = now
            self.alert_sequence += 1
            stored = dict(alert)
            stored["alert_id"] = "rt_alert_%08d" % self.alert_sequence
            stored["sequence"] = self.alert_sequence
            self.alerts.appendleft(stored)
            self.metrics["alerts_emitted"] += 1
            if float(stored.get("risk_score") or 0.0) >= 85.0:
                self.metrics["high_risk_alerts"] += 1

        self._persist_event("alert", stored)
        self._record_bruteforce_event(stored)
        correlated = self._post_bruteforce_alert(stored)
        if correlated is not None:
            self._append_alert(
                correlated,
                dedup_key="postbf:%s:%s"
                % (correlated.get("src_ip"), correlated.get("dst_ip")),
                cooldown=120.0,
            )
        return True

    def _schedule_inspection(self, key: Any, reason: str) -> None:
        with self.lock:
            flow = self.flows.get(key)
            if flow is None or flow.inspection_pending:
                return
            flow.inspection_pending = True
            flow.status = "queued"
        try:
            self.inspection_queue.put_nowait((key, reason))
        except queue.Full:
            with self.lock:
                flow = self.flows.get(key)
                if flow is not None:
                    flow.inspection_pending = False
                    flow.status = "queue_dropped"
                self.metrics["queue_drops"] += 1

    def _inspection_loop(self) -> None:
        while not self.stop_event.is_set() or not self.inspection_queue.empty():
            try:
                key, reason = self.inspection_queue.get(timeout=0.25)
            except queue.Empty:
                continue
            try:
                self._inspect_flow(key, reason)
            except Exception as exc:
                with self.lock:
                    flow = self.flows.get(key)
                    if flow is not None:
                        flow.inspection_pending = False
                        flow.status = "inspection_error"
                    self.metrics["inspection_errors"] += 1
                    self.last_error = "%s: %s" % (type(exc).__name__, exc)
            finally:
                self.inspection_queue.task_done()

    def _inspect_flow(self, key: Any, reason: str) -> None:
        started = time.perf_counter()
        with self.lock:
            flow = self.flows.get(key)
            if flow is None:
                return
            packets = list(flow.packets)
            if flow.first_packet is not None:
                first = flow.first_packet.copy()
                if not packets or (
                    packets[0].timestamp != first.timestamp
                    or packets[0].raw != first.raw
                ):
                    packets.insert(0, first)
            packet_count = flow.packet_count
            flow_id = flow.flow_id
            flow.status = "inspecting"
            flow_summary = flow.summary()

        if not packets:
            return

        task_id = "rt_%s_%06d" % (flow_id[5:13], packet_count)
        pcap_path = self.session_root / (task_id + ".pcap")
        _write_pcap(pcap_path, packets)

        result = detect_file(
            pcap_path,
            task_id,
            include_model=True,
            context_id="%s:%s"
            % (self.config.get("context_prefix") or "realtime", flow_id),
            use_temporal=bool(self.config.get("use_temporal", True)),
        )
        latency_ms = (time.perf_counter() - started) * 1000.0

        alerts = result.get("alerts", [])
        max_risk = 0.0
        latest_behavior = None
        for item in alerts:
            item["flow_id"] = flow_id
            item["src_ip"] = item.get("src_ip") or flow_summary["src_ip"]
            item["dst_ip"] = item.get("dst_ip") or flow_summary["dst_ip"]
            item["src_port"] = item.get("src_port") or flow_summary["src_port"]
            item["dst_port"] = item.get("dst_port") or flow_summary["dst_port"]
            item["detection_source"] = item.get(
                "detection_source"
            ) or "aegisfusion_flow_and_behavior"
            item["trigger_reason"] = reason
            item["packets_used"] = len(packets)
            item["detection_latency_ms"] = round(latency_ms, 3)
            item["realtime"] = True
            risk = float(item.get("risk_score") or 0.0)
            if risk >= max_risk:
                max_risk = risk
                latest_behavior = item.get("behavior")
            self._append_alert(
                item,
                dedup_key="flow:%s:%s" % (flow_id, item.get("behavior")),
                cooldown=30.0,
            )

        model_result = result.get("model_result") or {}
        session = {
            "session_id": task_id,
            "flow": flow_summary,
            "trigger_reason": reason,
            "packets_used": len(packets),
            "detection_latency_ms": round(latency_ms, 3),
            "result": result,
        }
        with self.lock:
            flow = self.flows.get(key)
            if flow is not None:
                flow.last_inspected_count = packet_count
                flow.last_inspected_at = time.time()
                flow.inspection_pending = False
                flow.status = "alert" if alerts else "normal"
                flow.latest_risk = max_risk
                flow.latest_behavior = latest_behavior
                flow.latest_model_family = model_result.get("family")
                flow.latest_model_confidence = model_result.get("confidence")
                flow.latest_temporal_probability = model_result.get(
                    "temporal_infiltration_probability"
                )
                flow.latest_context_depth = model_result.get(
                    "context_history_before_prediction"
                )

            self.sessions.appendleft(session)
            self.metrics["flows_inspected"] += 1
            if alerts:
                self.metrics["alert_windows"] += 1
            else:
                self.metrics["normal_windows"] += 1
            self.metrics["detection_latency_ms_sum"] += latency_ms
            self.metrics["detection_latency_count"] += 1

        self._persist_event("inspection", session)

    def _sweep(self, force: bool = False) -> None:
        now = time.time()
        pending: list[tuple[Any, str]] = []
        stale: list[Any] = []
        with self.lock:
            for key, flow in list(self.flows.items()):
                if flow.inspection_pending:
                    continue
                uninspected = flow.packet_count > flow.last_inspected_count
                timed_out = (
                    now - flow.last_seen
                    >= float(self.config["flow_timeout_seconds"])
                )
                if uninspected and (force or timed_out):
                    pending.append(
                        (key, "manual_flush" if force else "flow_timeout")
                    )

                inactive = (
                    now - flow.last_seen
                    >= float(self.config["inactive_flow_seconds"])
                )
                if inactive and not uninspected:
                    stale.append(key)

            for key in stale:
                flow = self.flows.get(key)
                if flow is not None and not flow.inspection_pending:
                    del self.flows[key]

        for key, reason in pending:
            self._schedule_inspection(key, reason)

    def force_inspect_all(
        self, reason: str = "manual_flush", timeout: float = 12.0
    ) -> dict[str, Any]:
        with self.lock:
            keys = list(self.flows.keys())
        for key in keys:
            self._schedule_inspection(key, reason)

        deadline = time.time() + float(timeout)
        while time.time() < deadline:
            with self.lock:
                pending = any(
                    flow.inspection_pending for flow in self.flows.values()
                )
            if self.inspection_queue.empty() and not pending:
                break
            time.sleep(0.05)
        return self.status(50, 200, 50)

    def _persist_event(self, event_type: str, payload: dict[str, Any]) -> None:
        try:
            path = self.runtime_root / "events.jsonl"
            record = {
                "event_type": event_type,
                "timestamp": time.time(),
                "payload": payload,
            }
            with path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception:
            return

    def status(
        self,
        flow_limit: int = 50,
        alert_limit: int = 100,
        session_limit: int = 20,
    ) -> dict[str, Any]:
        with self.lock:
            metrics = dict(self.metrics)
            count = int(metrics.get("detection_latency_count") or 0)
            metrics["average_detection_latency_ms"] = (
                round(
                    float(metrics.get("detection_latency_ms_sum") or 0.0)
                    / count,
                    3,
                )
                if count
                else 0.0
            )
            metrics["active_flows"] = len(self.flows)
            metrics["inspection_queue_depth"] = self.inspection_queue.qsize()

            flows = sorted(
                (flow.summary() for flow in self.flows.values()),
                key=lambda item: item["last_seen"],
                reverse=True,
            )[: max(0, int(flow_limit))]
            alerts = list(self.alerts)[: max(0, int(alert_limit))]
            sessions = list(self.sessions)[: max(0, int(session_limit))]

            return {
                "status": (
                    "running"
                    if self.running
                    else ("error" if self.last_error else "stopped")
                ),
                "running": self.running,
                "mode": self.mode,
                "interface": self.interface,
                "sample": self.sample,
                "started_at": self.started_at,
                "stopped_at": self.stopped_at,
                "uptime_seconds": (
                    round(max(0.0, time.time() - self.started_at), 3)
                    if self.started_at and self.running
                    else 0.0
                ),
                "last_error": self.last_error,
                "scapy_available": SCAPY_AVAILABLE,
                "scapy_error": SCAPY_ERROR,
                "config": dict(self.config),
                "metrics": metrics,
                "flows": flows,
                "alerts": alerts,
                "sessions": sessions,
                "capabilities": {
                    "live_capture": bool(
                        SCAPY_AVAILABLE or hasattr(socket, "AF_PACKET")
                    ),
                    "pcap_replay": True,
                    "flow_statistical_inference": True,
                    "cross_flow_rules": True,
                    "bruteforce_post_action_correlation": True,
                    "content_inspection": False,
                    "decryption_performed": False,
                    "minimum_flow_packets": self.config.get(
                        "min_flow_packets", 12
                    ),
                },
            }


__all__ = [
    "CapturedPacket",
    "FlowState",
    "RealtimeMonitor",
    "SCAPY_AVAILABLE",
]
