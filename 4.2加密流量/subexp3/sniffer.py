#!/usr/bin/env python3
"""Live capture or offline replay controller."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Callable

from session_manager import PacketEvent, SessionManager


PredictionCallback = Callable[[dict, object], None]


class CaptureController:
    def __init__(
        self,
        session_manager: SessionManager,
        on_session_update: PredictionCallback | None = None,
        replay_file: Path | str | None = None,
        replay_speed: float = 0.02,
    ) -> None:
        self.session_manager = session_manager
        self.on_session_update = on_session_update
        self.replay_file = Path(replay_file) if replay_file else Path("../subexp2/outputs/parsed_flows.jsonl")
        self.replay_speed = replay_speed
        self.running = False
        self.mode = "stopped"
        self.interface = ""
        self.thread: threading.Thread | None = None
        self.packet_total = 0
        self.started_at = 0.0
        self.last_error = ""

    def start(self, interface: str = "", mode: str = "replay") -> dict:
        if self.running:
            return self.status()
        self.running = True
        self.mode = mode
        self.interface = interface
        self.packet_total = 0
        self.started_at = time.time()
        target = self._run_replay if mode != "live" else self._run_live
        self.thread = threading.Thread(target=target, daemon=True)
        self.thread.start()
        return self.status()

    def stop(self) -> dict:
        self.running = False
        return self.status()

    def status(self) -> dict:
        return {
            "running": self.running,
            "mode": self.mode,
            "interface": self.interface,
            "packet_total": self.packet_total,
            "started_at": self.started_at,
            "last_error": self.last_error,
        }

    def _emit(self, event: PacketEvent) -> None:
        session = self.session_manager.ingest(event)
        self.packet_total += 1
        if self.on_session_update:
            self.on_session_update(session.snapshot(), session)

    def _run_replay(self) -> None:
        try:
            if not self.replay_file.exists():
                self.last_error = f"Replay file not found: {self.replay_file}"
                self.running = False
                return
            while self.running:
                with self.replay_file.open("r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        if not self.running:
                            break
                        row = json.loads(line)
                        times = row.get("packet_times") or [time.time()]
                        lengths = row.get("packet_lengths") or [int(row.get("byte_count") or 60)]
                        directions = row.get("packet_directions") or [1] * len(lengths)
                        for idx, length in enumerate(lengths[:20]):
                            if not self.running:
                                break
                            direction = directions[idx] if idx < len(directions) else 1
                            if direction == 1:
                                src_ip, dst_ip = row.get("src_ip", ""), row.get("dst_ip", "")
                                src_port, dst_port = row.get("src_port", ""), row.get("dst_port", "")
                            else:
                                src_ip, dst_ip = row.get("dst_ip", ""), row.get("src_ip", "")
                                src_port, dst_port = row.get("dst_port", ""), row.get("src_port", "")
                            event = PacketEvent(
                                ts=time.time(),
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                src_port=str(src_port),
                                dst_port=str(dst_port),
                                protocol=row.get("protocol", "TCP"),
                                length=int(length),
                                protocol_stack=row.get("protocol_stack", ""),
                            )
                            self._emit(event)
                            time.sleep(self.replay_speed)
                        self.session_manager.expire_old()
                time.sleep(0.5)
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
        finally:
            self.running = False

    def _run_live(self) -> None:
        try:
            from scapy.all import IP, IPv6, TCP, UDP, sniff
        except Exception as exc:
            self.last_error = f"Live capture requires scapy: {exc}. Use replay mode for demo."
            self.running = False
            return

        def handle(pkt) -> None:
            if not self.running:
                return
            ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ip is None:
                return
            tcp = pkt.getlayer(TCP)
            udp = pkt.getlayer(UDP)
            if tcp is None and udp is None:
                return
            proto = "TCP" if tcp is not None else "UDP"
            l4 = tcp or udp
            stack = "ip:tcp" if proto == "TCP" else "ip:udp"
            if proto == "UDP" and int(l4.dport) == 443:
                stack += ":quic"
            event = PacketEvent(
                ts=time.time(),
                src_ip=str(ip.src),
                dst_ip=str(ip.dst),
                src_port=str(l4.sport),
                dst_port=str(l4.dport),
                protocol=proto,
                length=len(pkt),
                protocol_stack=stack,
            )
            self._emit(event)

        sniff(iface=self.interface or None, prn=handle, store=False, stop_filter=lambda _: not self.running)
