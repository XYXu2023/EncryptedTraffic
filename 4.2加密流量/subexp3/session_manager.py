#!/usr/bin/env python3
"""Five-tuple session state for online traffic detection."""

from __future__ import annotations

import hashlib
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any


def canonical_key(src_ip: str, dst_ip: str, src_port: str, dst_port: str, protocol: str) -> tuple[str, str, str, str, str]:
    a = (src_ip, str(src_port))
    b = (dst_ip, str(dst_port))
    return (src_ip, dst_ip, str(src_port), str(dst_port), protocol) if a <= b else (dst_ip, src_ip, str(dst_port), str(src_port), protocol)


@dataclass
class PacketEvent:
    ts: float
    src_ip: str
    dst_ip: str
    src_port: str
    dst_port: str
    protocol: str
    length: int
    protocol_stack: str = ""


@dataclass
class FlowSession:
    key: tuple[str, str, str, str, str]
    first_src_ip: str
    first_src_port: str
    max_packets: int = 20
    flow_id: str = ""
    start_time: float = 0.0
    last_time: float = 0.0
    packet_count: int = 0
    byte_count: int = 0
    packet_times: deque[float] = field(default_factory=deque)
    packet_lengths: deque[int] = field(default_factory=deque)
    packet_directions: deque[int] = field(default_factory=deque)
    protocol_stack: Counter = field(default_factory=Counter)
    predicted_label: str = "unknown"
    confidence: float = 0.0
    last_prediction_time: float = 0.0

    def add_packet(self, event: PacketEvent) -> None:
        if not self.flow_id:
            raw = "|".join(map(str, self.key)) + f"|{event.ts:.6f}"
            self.flow_id = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]
        if self.start_time <= 0:
            self.start_time = event.ts
        self.last_time = event.ts
        self.packet_count += 1
        self.byte_count += int(event.length)
        direction = 1 if event.src_ip == self.first_src_ip and str(event.src_port) == self.first_src_port else -1
        self.packet_times.append(event.ts)
        self.packet_lengths.append(int(event.length))
        self.packet_directions.append(direction)
        while len(self.packet_times) > self.max_packets:
            self.packet_times.popleft()
            self.packet_lengths.popleft()
            self.packet_directions.popleft()
        if event.protocol_stack:
            self.protocol_stack[event.protocol_stack.lower()] += 1

    @property
    def duration(self) -> float:
        return max(0.0, self.last_time - self.start_time)

    def snapshot(self) -> dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "src_ip": self.key[0],
            "dst_ip": self.key[1],
            "src_port": self.key[2],
            "dst_port": self.key[3],
            "protocol": self.key[4],
            "start_time": self.start_time,
            "last_time": self.last_time,
            "duration": self.duration,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "packet_times": list(self.packet_times),
            "packet_lengths": list(self.packet_lengths),
            "packet_directions": list(self.packet_directions),
            "protocol_stack": self.protocol_stack.most_common(1)[0][0] if self.protocol_stack else "",
            "predicted_label": self.predicted_label,
            "confidence": self.confidence,
        }


class SessionManager:
    """Thread-safe in-memory TCP/UDP session table."""

    def __init__(self, timeout_seconds: float = 30.0, max_packets: int = 20, max_sessions: int = 5000) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_packets = max_packets
        self.max_sessions = max_sessions
        self.sessions: dict[tuple[str, str, str, str, str], FlowSession] = {}
        self.lock = threading.RLock()

    def ingest(self, event: PacketEvent) -> FlowSession:
        key = canonical_key(event.src_ip, event.dst_ip, event.src_port, event.dst_port, event.protocol)
        with self.lock:
            session = self.sessions.get(key)
            if session is None:
                session = FlowSession(key=key, first_src_ip=event.src_ip, first_src_port=str(event.src_port), max_packets=self.max_packets)
                self.sessions[key] = session
            session.add_packet(event)
            if len(self.sessions) > self.max_sessions:
                self.expire_old(now=event.ts, force_count=len(self.sessions) - self.max_sessions)
            return session

    def expire_old(self, now: float | None = None, force_count: int = 0) -> list[FlowSession]:
        now = now or time.time()
        expired: list[FlowSession] = []
        with self.lock:
            keys = [k for k, s in self.sessions.items() if now - s.last_time > self.timeout_seconds]
            if force_count > 0:
                oldest = sorted(self.sessions.items(), key=lambda item: item[1].last_time)[:force_count]
                keys.extend(k for k, _ in oldest)
            for key in set(keys):
                session = self.sessions.pop(key, None)
                if session is not None:
                    expired.append(session)
        return expired

    def active_snapshots(self, limit: int = 200) -> list[dict[str, Any]]:
        with self.lock:
            sessions = sorted(self.sessions.values(), key=lambda s: s.last_time, reverse=True)[:limit]
            return [s.snapshot() for s in sessions]

    def reset(self) -> None:
        with self.lock:
            self.sessions.clear()
