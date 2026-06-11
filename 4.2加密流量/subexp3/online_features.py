#!/usr/bin/env python3
"""Streaming feature extraction compatible with sub-experiment 2 models."""

from __future__ import annotations

import math
import statistics
from typing import Any


def mean(xs: list[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def std(xs: list[float]) -> float:
    return statistics.pstdev(xs) if len(xs) > 1 else 0.0


def compute_bursts(times: list[float], lengths: list[int], directions: list[int], gap: float = 1.0) -> tuple[int, float, int, float]:
    if not times:
        return 0, 0.0, 0, 0.0
    bursts = []
    cur_size = lengths[0]
    cur_start = times[0]
    cur_end = times[0]
    cur_dir = directions[0]
    for t, length, direction in zip(times[1:], lengths[1:], directions[1:]):
        if direction == cur_dir and t - cur_end <= gap:
            cur_size += length
            cur_end = t
        else:
            bursts.append((cur_size, cur_end - cur_start))
            cur_size = length
            cur_start = cur_end = t
            cur_dir = direction
    bursts.append((cur_size, cur_end - cur_start))
    sizes = [b[0] for b in bursts]
    durations = [b[1] for b in bursts]
    return len(bursts), mean(sizes), max(sizes) if sizes else 0, mean(durations)


def session_to_feature_row(session_snapshot: dict[str, Any], platform: str = "pc", environment: str = "direct") -> dict[str, Any]:
    times = [float(x) for x in session_snapshot.get("packet_times", [])]
    lengths = [int(x) for x in session_snapshot.get("packet_lengths", [])]
    dirs = [int(x) for x in session_snapshot.get("packet_directions", [])]
    iats = [max(0.0, b - a) for a, b in zip(times, times[1:])]
    up_lengths = [l for l, d in zip(lengths, dirs) if d == 1]
    down_lengths = [l for l, d in zip(lengths, dirs) if d == -1]
    burst_count, mean_burst_size, max_burst_size, mean_burst_duration = compute_bursts(times, lengths, dirs)
    protocol = session_snapshot.get("protocol", "")
    dst_port = int(float(session_snapshot.get("dst_port") or 0))
    stack = str(session_snapshot.get("protocol_stack", "")).lower()
    up_packets = len(up_lengths)
    down_packets = len(down_lengths)
    up_bytes = sum(up_lengths)
    down_bytes = sum(down_lengths)
    total_packets = len(lengths)
    total_bytes = sum(lengths)
    return {
        "flow_id": session_snapshot.get("flow_id", ""),
        "capture_file": "online",
        "label": "unknown",
        "platform": platform,
        "environment": environment,
        "app_name": "online",
        "src_ip": session_snapshot.get("src_ip", ""),
        "dst_ip": session_snapshot.get("dst_ip", ""),
        "dst_port": dst_port,
        "transport_protocol": protocol,
        "duration": float(session_snapshot.get("duration") or 0.0),
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "uplink_packets": up_packets,
        "downlink_packets": down_packets,
        "uplink_bytes": up_bytes,
        "downlink_bytes": down_bytes,
        "mean_packet_len": mean(lengths),
        "std_packet_len": std(lengths),
        "min_packet_len": min(lengths) if lengths else 0,
        "max_packet_len": max(lengths) if lengths else 0,
        "mean_iat": mean(iats),
        "std_iat": std(iats),
        "min_iat": min(iats) if iats else 0,
        "max_iat": max(iats) if iats else 0,
        "uplink_downlink_packet_ratio": up_packets / max(1, down_packets),
        "uplink_downlink_byte_ratio": up_bytes / max(1, down_bytes),
        "first_packet_direction": dirs[0] if dirs else 0,
        "packet_count_diff": up_packets - down_packets,
        "byte_count_diff": up_bytes - down_bytes,
        "burst_count": burst_count,
        "mean_burst_size": mean_burst_size,
        "max_burst_size": max_burst_size,
        "mean_burst_duration": mean_burst_duration,
        "tls_presence": 1 if "tls" in stack or dst_port == 443 else 0,
        "quic_presence": 1 if "quic" in stack or (protocol == "UDP" and dst_port == 443) else 0,
        "dns_related": 1 if "dns" in stack or dst_port == 53 else 0,
        "tcp_flag_syn": 0,
        "tcp_flag_ack": 0,
        "tcp_flag_fin": 0,
        "tcp_flag_rst": 0,
        "domain_present": 0,
        "observed_packet_count": total_packets,
        "observed_byte_count": total_bytes,
        "observed_duration": float(session_snapshot.get("duration") or 0.0),
        "first_n_packet_lengths": lengths,
        "first_n_iat": iats,
        "first_n_directions": dirs,
    }
