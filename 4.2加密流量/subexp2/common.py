#!/usr/bin/env python3
"""Shared utilities for sub-experiment 2 encrypted traffic classification.

This module intentionally uses only the Python standard library so the
experiment remains runnable on a clean lab machine without sklearn/scapy.
"""

from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import math
import os
import random
import statistics
import struct
import time
import zlib
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


SCENE_ALIASES = {
    "browse": "browser",
    "browser": "browser",
    "web": "browser",
    "browsing": "browser",
    "browse_without_vpn": "browser",
    "browse_no_proxy": "browser",
    "browse_proxy": "browser",
    "video": "video",
    "tiktok": "video",
    "qqmusic": "video",
    "rednotes": "social",
    "pinduoduo": "shopping",
    "shopping": "shopping",
    "map": "map",
    "cloud": "cloud",
    "netdisk": "cloud",
    "download": "download",
    "chat": "chat",
    "qq": "chat",
}

APP_ALIASES = {
    "browse": "browser",
    "browse_without_vpn": "browser",
    "browse_no_proxy": "browser",
    "browse_proxy": "browser_proxy",
    "pinduoduo": "pinduoduo",
    "qq": "qq",
    "qqmusic": "qqmusic",
    "rednotes": "rednotes",
    "tiktok": "tiktok",
    "chat": "chat",
    "cloud": "cloud",
    "download": "download",
    "video": "video",
}

BACKGROUND_DOMAINS = (
    "ecs.office.com",
    "office.com",
    "office.net",
    "teams.microsoft",
    "onedrive",
    "sharepoint.com",
    "windowsupdate",
    "msftconnecttest",
    "msftncsi",
)

PROXY_PORTS = {20067, 23000, 7890, 7891, 7897, 1080, 10808, 8080, 8888}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fields is None:
        fields = sorted({k for row in rows for k in row.keys()})
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def scalar(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        return scalar(value[0]) if value else None
    if isinstance(value, dict):
        return None
    return str(value)


def parse_timestamp(value: str | None) -> float:
    if not value:
        return 0.0
    try:
        return float(value)
    except ValueError:
        pass
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return 0.0


def recursive_values(obj: Any, names: set[str]) -> Iterable[str]:
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in names:
                if isinstance(value, list):
                    for item in value:
                        s = scalar(item)
                        if s:
                            yield s
                else:
                    s = scalar(value)
                    if s:
                        yield s
            if isinstance(value, (dict, list)):
                yield from recursive_values(value, names)
    elif isinstance(obj, list):
        for item in obj:
            yield from recursive_values(item, names)


def stream_packet_objects(path: Path) -> Iterable[dict[str, Any]]:
    decoder = json.JSONDecoder()
    buf = ""
    in_array = False
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            buf += chunk
            while True:
                buf = buf.lstrip()
                if not buf:
                    break
                if not in_array:
                    if buf[0] == "[":
                        buf = buf[1:]
                    elif buf[0] != "{":
                        raise ValueError(f"Unexpected JSON start in {path}: {buf[:40]!r}")
                    in_array = True
                    continue
                buf = buf.lstrip()
                if buf.startswith("]"):
                    return
                if buf.startswith(","):
                    buf = buf[1:]
                    continue
                try:
                    obj, idx = decoder.raw_decode(buf)
                except json.JSONDecodeError:
                    break
                yield obj
                buf = buf[idx:]


def infer_context(path: Path, root: Path) -> dict[str, str]:
    rel = path.relative_to(root)
    group = rel.parts[0] if len(rel.parts) > 1 else path.parent.name
    stem = path.stem.lower().replace("-", "_").replace(" ", "_")
    platform = "mobile" if group.lower() == "android" else "pc"
    environment = "direct"
    if "proxy" in stem or "代理" in group:
        environment = "proxy"
    if "no_proxy" in stem or "without_vpn" in stem:
        environment = "direct"
    if "vpn" in stem and "without_vpn" not in stem:
        environment = "vpn"
    scene = SCENE_ALIASES.get(stem)
    if scene is None:
        scene = next((v for k, v in SCENE_ALIASES.items() if k in stem), stem)
    app = APP_ALIASES.get(stem)
    if app is None:
        app = next((v for k, v in APP_ALIASES.items() if k in stem), stem)
    pcap = sorted(path.parent.glob(f"{path.stem}*.pcap*"))
    if not pcap and stem == "browse":
        pcap = sorted(path.parent.glob("browse*.pcap*"))
    return {
        "capture_file": pcap[0].name if pcap else path.name,
        "label": scene,
        "platform": platform,
        "environment": environment,
        "app_name": app,
        "source_group": group,
    }


def canonical_key(src: str, dst: str, sport: str, dport: str, proto: str) -> tuple[str, str, str, str, str]:
    return (src, dst, sport, dport, proto) if (src, sport) <= (dst, dport) else (dst, src, dport, sport, proto)


def private_or_control(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return bool(obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_multicast or obj.is_unspecified)


def packet_from_wireshark_json(packet: dict[str, Any]) -> dict[str, Any] | None:
    src = packet.get("_source", packet)
    layers = src.get("layers", src)
    frame = layers.get("frame", {})
    ip = layers.get("ip", {})
    ipv6 = layers.get("ipv6", {})
    tcp = layers.get("tcp", {})
    udp = layers.get("udp", {})
    src_ip = scalar(ip.get("ip.src")) or scalar(ipv6.get("ipv6.src"))
    dst_ip = scalar(ip.get("ip.dst")) or scalar(ipv6.get("ipv6.dst"))
    proto = None
    src_port = dst_port = None
    if tcp:
        proto = "TCP"
        src_port = scalar(tcp.get("tcp.srcport"))
        dst_port = scalar(tcp.get("tcp.dstport"))
    elif udp:
        proto = "UDP"
        src_port = scalar(udp.get("udp.srcport"))
        dst_port = scalar(udp.get("udp.dstport"))
    if not (src_ip and dst_ip and proto and src_port and dst_port):
        return None
    stack = (scalar(frame.get("frame.protocols")) or "").lower()
    domains = [
        d.strip(".").lower()
        for d in recursive_values(
            layers,
            {
                "dns.qry.name",
                "tls.handshake.extensions_server_name",
                "quic.tls.handshake.extensions_server_name",
                "http.host",
                "http2.header.authority",
            },
        )
    ]
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": str(src_port),
        "dst_port": str(dst_port),
        "protocol": proto,
        "time": parse_timestamp(scalar(frame.get("frame.time_epoch")) or scalar(frame.get("frame.time"))),
        "length": int(float(scalar(frame.get("frame.len")) or 0)),
        "protocol_stack": stack,
        "domains": [d for d in domains if d],
        "tcp_flags": scalar(tcp.get("tcp.flags")) if tcp else "",
    }


@dataclass
class FlowAgg:
    key: tuple[str, str, str, str, str]
    first_src: str
    first_dst: str
    first_sport: str
    first_dport: str
    protocol: str
    times: list[float] = field(default_factory=list)
    lengths: list[int] = field(default_factory=list)
    directions: list[int] = field(default_factory=list)
    stacks: Counter = field(default_factory=Counter)
    domains: Counter = field(default_factory=Counter)
    tcp_flags: Counter = field(default_factory=Counter)

    def add(self, pkt: dict[str, Any]) -> None:
        self.times.append(float(pkt["time"]))
        self.lengths.append(int(pkt["length"]))
        self.directions.append(1 if pkt["src_ip"] == self.first_src and pkt["src_port"] == self.first_sport else -1)
        if pkt.get("protocol_stack"):
            self.stacks[pkt["protocol_stack"]] += 1
        for d in pkt.get("domains", []):
            self.domains[d] += 1
        if pkt.get("tcp_flags"):
            self.tcp_flags[pkt["tcp_flags"]] += 1

    def to_record(self, context: dict[str, str], source_json: str) -> dict[str, Any]:
        order = sorted(range(len(self.times)), key=lambda i: self.times[i])
        times = [self.times[i] for i in order]
        lengths = [self.lengths[i] for i in order]
        directions = [self.directions[i] for i in order]
        start = times[0] if times else 0.0
        end = times[-1] if times else start
        token = f"{source_json}|{'|'.join(map(str, self.key))}"
        flow_id = hashlib.sha1(token.encode("utf-8")).hexdigest()[:16]
        return {
            "flow_id": flow_id,
            "capture_file": context["capture_file"],
            "source_json": source_json,
            "label": context["label"],
            "platform": context["platform"],
            "environment": context["environment"],
            "app_name": context["app_name"],
            "src_ip": self.first_src,
            "dst_ip": self.first_dst,
            "src_port": self.first_sport,
            "dst_port": self.first_dport,
            "protocol": self.protocol,
            "start_time": round(start, 6),
            "end_time": round(end, 6),
            "duration": round(max(0.0, end - start), 6),
            "packet_count": len(lengths),
            "byte_count": sum(lengths),
            "packet_times": times,
            "packet_lengths": lengths,
            "packet_directions": directions,
            "protocol_stack": self.stacks.most_common(1)[0][0] if self.stacks else "",
            "domain": self.domains.most_common(1)[0][0] if self.domains else "",
            "tcp_flags": dict(self.tcp_flags),
            "is_background_guess": background_guess(self, context),
        }


def background_guess(flow: FlowAgg, context: dict[str, str]) -> str:
    stack = " ".join(flow.stacks.keys())
    if any(x in stack for x in ("arp", "mdns", "llmnr", "nbns", "icmpv6", "igmp")):
        return "true"
    if private_or_control(flow.first_src) and private_or_control(flow.first_dst):
        return "true"
    domain = flow.domains.most_common(1)[0][0] if flow.domains else ""
    if any(h in domain for h in BACKGROUND_DOMAINS):
        return "true"
    ports = {int(p) for p in (flow.first_sport, flow.first_dport) if str(p).isdigit()}
    if context["environment"] == "proxy" and ports & PROXY_PORTS:
        return "false"
    return "false"


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value == "" or value is None:
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


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


def features_from_flow(row: dict[str, Any]) -> dict[str, Any]:
    times = [float(x) for x in row.get("packet_times", [])]
    lengths = [int(x) for x in row.get("packet_lengths", [])]
    dirs = [int(x) for x in row.get("packet_directions", [])]
    iats = [max(0.0, b - a) for a, b in zip(times, times[1:])]
    up_lengths = [l for l, d in zip(lengths, dirs) if d == 1]
    down_lengths = [l for l, d in zip(lengths, dirs) if d == -1]
    burst_count, mean_burst_size, max_burst_size, mean_burst_duration = compute_bursts(times, lengths, dirs)
    stack = str(row.get("protocol_stack", "")).lower()
    tcp_flags = row.get("tcp_flags") or {}
    if isinstance(tcp_flags, str):
        try:
            tcp_flags = json.loads(tcp_flags)
        except json.JSONDecodeError:
            tcp_flags = {}
    total_packets = len(lengths)
    total_bytes = sum(lengths)
    up_packets = len(up_lengths)
    down_packets = len(down_lengths)
    up_bytes = sum(up_lengths)
    down_bytes = sum(down_lengths)
    return {
        "flow_id": row.get("flow_id", ""),
        "capture_file": row.get("capture_file", ""),
        "label": row.get("label", ""),
        "platform": row.get("platform", ""),
        "environment": row.get("environment", ""),
        "app_name": row.get("app_name", ""),
        "src_ip": row.get("src_ip", ""),
        "dst_ip": row.get("dst_ip", ""),
        "dst_port": int(float(row.get("dst_port") or 0)),
        "transport_protocol": row.get("protocol", ""),
        "duration": safe_float(row.get("duration")),
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
        "tls_presence": 1 if "tls" in stack or int(float(row.get("dst_port") or 0)) == 443 else 0,
        "quic_presence": 1 if "quic" in stack or (row.get("protocol") == "UDP" and int(float(row.get("dst_port") or 0)) == 443) else 0,
        "dns_related": 1 if "dns" in stack or int(float(row.get("dst_port") or 0)) == 53 else 0,
        "tcp_flag_syn": sum(v for k, v in tcp_flags.items() if str(k).lower() in {"0x0002", "syn"}),
        "tcp_flag_ack": sum(v for k, v in tcp_flags.items() if str(k).lower() in {"0x0010", "ack"}),
        "tcp_flag_fin": sum(v for k, v in tcp_flags.items() if str(k).lower() in {"0x0001", "fin"}),
        "tcp_flag_rst": sum(v for k, v in tcp_flags.items() if str(k).lower() in {"0x0004", "rst"}),
        "domain_present": 1 if row.get("domain") else 0,
        "is_background_guess": row.get("is_background_guess", "false"),
    }


BASIC_FEATURES = [
    "duration",
    "total_packets",
    "total_bytes",
    "uplink_packets",
    "downlink_packets",
    "uplink_bytes",
    "downlink_bytes",
    "mean_packet_len",
    "std_packet_len",
    "min_packet_len",
    "max_packet_len",
]
TEMPORAL_FEATURES = ["mean_iat", "std_iat", "min_iat", "max_iat"]
DIRECTION_FEATURES = [
    "uplink_downlink_packet_ratio",
    "uplink_downlink_byte_ratio",
    "first_packet_direction",
    "packet_count_diff",
    "byte_count_diff",
]
BURST_FEATURES = ["burst_count", "mean_burst_size", "max_burst_size", "mean_burst_duration"]
CONTEXT_FEATURES = [
    "dst_port",
    "tls_presence",
    "quic_presence",
    "dns_related",
    "tcp_flag_syn",
    "tcp_flag_ack",
    "tcp_flag_fin",
    "tcp_flag_rst",
    "domain_present",
]
CATEGORICAL_FEATURES = ["transport_protocol", "platform", "environment"]
ALL_NUMERIC_FEATURES = BASIC_FEATURES + TEMPORAL_FEATURES + DIRECTION_FEATURES + BURST_FEATURES + CONTEXT_FEATURES
ALL_FEATURES = ALL_NUMERIC_FEATURES + CATEGORICAL_FEATURES


class Preprocessor:
    def __init__(self, numeric_features: list[str], categorical_features: list[str]):
        self.numeric_features = numeric_features
        self.categorical_features = categorical_features
        self.means: dict[str, float] = {}
        self.stds: dict[str, float] = {}
        self.categories: dict[str, list[str]] = {}
        self.feature_names: list[str] = []

    def fit(self, rows: list[dict[str, Any]]) -> "Preprocessor":
        self.feature_names = []
        for feat in self.numeric_features:
            vals = [safe_float(r.get(feat)) for r in rows]
            self.means[feat] = mean(vals)
            self.stds[feat] = std(vals) or 1.0
            self.feature_names.append(feat)
        for feat in self.categorical_features:
            cats = sorted({str(r.get(feat, "")) for r in rows})
            self.categories[feat] = cats
            self.feature_names.extend([f"{feat}={c}" for c in cats])
        return self

    def transform_one(self, row: dict[str, Any]) -> list[float]:
        xs = []
        for feat in self.numeric_features:
            xs.append((safe_float(row.get(feat)) - self.means.get(feat, 0.0)) / self.stds.get(feat, 1.0))
        for feat in self.categorical_features:
            value = str(row.get(feat, ""))
            xs.extend([1.0 if value == c else 0.0 for c in self.categories.get(feat, [])])
        return xs

    def transform(self, rows: list[dict[str, Any]]) -> list[list[float]]:
        return [self.transform_one(r) for r in rows]


class LabelEncoder:
    def __init__(self) -> None:
        self.classes: list[str] = []

    def fit(self, labels: list[str]) -> "LabelEncoder":
        self.classes = sorted(set(labels))
        return self

    def transform(self, labels: list[str]) -> list[int]:
        mapping = {c: i for i, c in enumerate(self.classes)}
        return [mapping[x] for x in labels]

    def inverse(self, ids: list[int]) -> list[str]:
        return [self.classes[i] for i in ids]


class SoftmaxLogisticRegression:
    name = "logistic_regression"

    def __init__(self, lr: float = 0.05, epochs: int = 220, l2: float = 0.001, seed: int = 42):
        self.lr = lr
        self.epochs = epochs
        self.l2 = l2
        self.seed = seed
        self.weights: list[list[float]] = []
        self.bias: list[float] = []

    def fit(self, x: list[list[float]], y: list[int], n_classes: int) -> None:
        random.seed(self.seed)
        if not x:
            return
        n_features = len(x[0])
        self.weights = [[random.uniform(-0.01, 0.01) for _ in range(n_features)] for _ in range(n_classes)]
        self.bias = [0.0 for _ in range(n_classes)]
        n = len(x)
        for _ in range(self.epochs):
            grad_w = [[0.0] * n_features for _ in range(n_classes)]
            grad_b = [0.0] * n_classes
            for xi, yi in zip(x, y):
                probs = self.predict_proba_one(xi)
                for c in range(n_classes):
                    diff = probs[c] - (1.0 if c == yi else 0.0)
                    grad_b[c] += diff
                    for j, val in enumerate(xi):
                        grad_w[c][j] += diff * val
            for c in range(n_classes):
                self.bias[c] -= self.lr * grad_b[c] / n
                for j in range(n_features):
                    grad = grad_w[c][j] / n + self.l2 * self.weights[c][j]
                    self.weights[c][j] -= self.lr * grad

    def predict_proba_one(self, xi: list[float]) -> list[float]:
        scores = [b + sum(wj * xj for wj, xj in zip(w, xi)) for w, b in zip(self.weights, self.bias)]
        m = max(scores) if scores else 0.0
        exps = [math.exp(s - m) for s in scores]
        total = sum(exps) or 1.0
        return [e / total for e in exps]

    def predict(self, x: list[list[float]]) -> list[int]:
        return [max(range(len(self.bias)), key=lambda c: self.predict_proba_one(xi)[c]) for xi in x]


def gini(labels: list[int]) -> float:
    if not labels:
        return 0.0
    counts = Counter(labels)
    n = len(labels)
    return 1.0 - sum((c / n) ** 2 for c in counts.values())


class DecisionTree:
    def __init__(self, max_depth: int = 9, min_samples_split: int = 4, max_features: int | None = None, seed: int = 42):
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.max_features = max_features
        self.seed = seed
        self.tree: Any = None

    def fit(self, x: list[list[float]], y: list[int]) -> None:
        rnd = random.Random(self.seed)
        self.tree = self._build(x, y, 0, rnd)

    def _build(self, x: list[list[float]], y: list[int], depth: int, rnd: random.Random) -> Any:
        majority = Counter(y).most_common(1)[0][0]
        if depth >= self.max_depth or len(set(y)) == 1 or len(y) < self.min_samples_split:
            return ("leaf", majority)
        n_features = len(x[0])
        features = list(range(n_features))
        if self.max_features:
            features = rnd.sample(features, min(self.max_features, n_features))
        best = None
        parent = gini(y)
        for feat in features:
            values = sorted({row[feat] for row in x})
            if len(values) <= 1:
                continue
            thresholds = [(a + b) / 2 for a, b in zip(values, values[1:])]
            if len(thresholds) > 16:
                step = max(1, len(thresholds) // 16)
                thresholds = thresholds[::step]
            for thr in thresholds:
                left_y = [yi for row, yi in zip(x, y) if row[feat] <= thr]
                right_y = [yi for row, yi in zip(x, y) if row[feat] > thr]
                if not left_y or not right_y:
                    continue
                score = (len(left_y) * gini(left_y) + len(right_y) * gini(right_y)) / len(y)
                gain = parent - score
                if best is None or gain > best[0]:
                    best = (gain, feat, thr)
        if best is None or best[0] <= 1e-9:
            return ("leaf", majority)
        _, feat, thr = best
        left_x, left_y, right_x, right_y = [], [], [], []
        for row, yi in zip(x, y):
            if row[feat] <= thr:
                left_x.append(row)
                left_y.append(yi)
            else:
                right_x.append(row)
                right_y.append(yi)
        return ("node", feat, thr, self._build(left_x, left_y, depth + 1, rnd), self._build(right_x, right_y, depth + 1, rnd))

    def predict_one(self, row: list[float]) -> int:
        node = self.tree
        while node[0] != "leaf":
            _, feat, thr, left, right = node
            node = left if row[feat] <= thr else right
        return node[1]


class RandomForest:
    name = "random_forest"

    def __init__(self, n_estimators: int = 35, max_depth: int = 9, seed: int = 42):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.seed = seed
        self.trees: list[DecisionTree] = []

    def fit(self, x: list[list[float]], y: list[int], n_classes: int | None = None) -> None:
        rnd = random.Random(self.seed)
        self.trees = []
        n = len(x)
        max_features = max(1, int(math.sqrt(len(x[0])))) if x else None
        for i in range(self.n_estimators):
            idxs = [rnd.randrange(n) for _ in range(n)]
            bx = [x[j] for j in idxs]
            by = [y[j] for j in idxs]
            tree = DecisionTree(max_depth=self.max_depth, max_features=max_features, seed=self.seed + i)
            tree.fit(bx, by)
            self.trees.append(tree)

    def predict(self, x: list[list[float]]) -> list[int]:
        preds = []
        for row in x:
            votes = Counter(t.predict_one(row) for t in self.trees)
            preds.append(votes.most_common(1)[0][0])
        return preds


def evaluate_predictions(y_true: list[str], y_pred: list[str], labels: list[str]) -> dict[str, Any]:
    total = len(y_true)
    accuracy = sum(a == b for a, b in zip(y_true, y_pred)) / total if total else 0.0
    per = []
    for label in labels:
        tp = sum(t == label and p == label for t, p in zip(y_true, y_pred))
        fp = sum(t != label and p == label for t, p in zip(y_true, y_pred))
        fn = sum(t == label and p != label for t, p in zip(y_true, y_pred))
        support = sum(t == label for t in y_true)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        per.append({"label": label, "precision": precision, "recall": recall, "f1": f1, "support": support})
    macro = {k: mean([r[k] for r in per]) for k in ("precision", "recall", "f1")}
    weighted = {
        k: sum(r[k] * r["support"] for r in per) / max(1, sum(r["support"] for r in per))
        for k in ("precision", "recall", "f1")
    }
    matrix = [[sum(t == a and p == b for t, p in zip(y_true, y_pred)) for b in labels] for a in labels]
    return {"accuracy": accuracy, "macro": macro, "weighted": weighted, "per_label": per, "confusion_matrix": matrix}


def save_simple_bar_png(path: Path, labels: list[str], values: list[float], title: str, width: int = 900, height: int = 520) -> None:
    try:
        import matplotlib.pyplot as plt

        path.parent.mkdir(parents=True, exist_ok=True)
        fig_w = max(8.5, len(labels) * 1.8)
        fig, ax = plt.subplots(figsize=(fig_w, 5.5), dpi=140)
        bars = ax.bar(labels, values, color="#3f77b6")
        ax.set_title(title)
        ax.set_ylabel("Weighted F1")
        ax.set_ylim(0, max(1.0, max(values) * 1.18 if values else 1.0))
        ax.grid(axis="y", linestyle="--", alpha=0.35)
        ax.tick_params(axis="x", rotation=18)
        for bar, value in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), f"{value:.3f}", ha="center", va="bottom", fontsize=9)
        fig.tight_layout()
        fig.savefig(path)
        plt.close(fig)
        return
    except Exception:
        pass

    img = [[(255, 255, 255) for _ in range(width)] for _ in range(height)]
    def rect(x0: int, y0: int, x1: int, y1: int, color: tuple[int, int, int]) -> None:
        for y in range(max(0, y0), min(height, y1)):
            for x in range(max(0, x0), min(width, x1)):
                img[y][x] = color
    margin = 70
    plot_h = height - 2 * margin
    plot_w = width - 2 * margin
    max_v = max(values) if values else 1.0
    bar_w = max(8, plot_w // max(1, len(values) * 2))
    for i, v in enumerate(values):
        x0 = margin + int((i + 0.5) * plot_w / max(1, len(values))) - bar_w // 2
        h = int((v / max_v) * (plot_h - 20))
        rect(x0, height - margin - h, x0 + bar_w, height - margin, (64, 119, 182))
    rect(margin, height - margin, width - margin, height - margin + 2, (0, 0, 0))
    rect(margin, margin, margin + 2, height - margin, (0, 0, 0))
    write_png(path, img)


def save_confusion_png(path: Path, matrix: list[list[int]], labels: list[str], width: int = 700, height: int = 700) -> None:
    try:
        import matplotlib.pyplot as plt

        path.parent.mkdir(parents=True, exist_ok=True)
        fig_size = max(7.0, len(labels) * 0.8)
        fig, ax = plt.subplots(figsize=(fig_size, fig_size), dpi=140)
        im = ax.imshow(matrix, cmap="Blues")
        ax.set_title("Confusion Matrix")
        ax.set_xlabel("Predicted label")
        ax.set_ylabel("True label")
        ax.set_xticks(range(len(labels)))
        ax.set_yticks(range(len(labels)))
        ax.set_xticklabels(labels, rotation=35, ha="right")
        ax.set_yticklabels(labels)
        max_v = max([max(row) for row in matrix] or [1]) or 1
        for i, row in enumerate(matrix):
            for j, value in enumerate(row):
                color = "white" if value > max_v * 0.55 else "black"
                ax.text(j, i, str(value), ha="center", va="center", color=color, fontsize=8)
        fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
        fig.tight_layout()
        fig.savefig(path)
        plt.close(fig)
        return
    except Exception:
        pass

    img = [[(255, 255, 255) for _ in range(width)] for _ in range(height)]
    n = max(1, len(labels))
    margin = 80
    cell = min((width - 2 * margin) // n, (height - 2 * margin) // n)
    max_v = max([max(row) for row in matrix] or [1]) or 1
    for i in range(n):
        for j in range(n):
            val = matrix[i][j] if i < len(matrix) and j < len(matrix[i]) else 0
            shade = 255 - int(210 * val / max_v)
            color = (shade, shade, 255)
            for y in range(margin + i * cell, margin + (i + 1) * cell):
                for x in range(margin + j * cell, margin + (j + 1) * cell):
                    if 0 <= y < height and 0 <= x < width:
                        img[y][x] = color
    write_png(path, img)


def write_png(path: Path, pixels: list[list[tuple[int, int, int]]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    height = len(pixels)
    width = len(pixels[0]) if height else 0
    raw = b"".join(b"\x00" + b"".join(bytes(px) for px in row) for row in pixels)
    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(raw, 9))
    png += chunk(b"IEND", b"")
    path.write_bytes(png)


def now() -> float:
    return time.perf_counter()
