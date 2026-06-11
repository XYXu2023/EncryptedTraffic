#!/usr/bin/env python3
"""Build cleaned flow/session datasets from Wireshark JSON exports.

The input JSON files are large pretty-printed arrays exported by Wireshark or
TShark. This script streams one packet object at a time, aggregates bidirectional
5-tuples into flow records, applies conservative background filtering, and emits
datasets for later classification and traffic analysis experiments.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import re
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
    "browser_access": "browser",
    "browse_without_vpn": "browser",
    "browse_no_proxy": "browser",
    "browse_proxy": "browser",
    "video": "video",
    "tiktok": "video",
    "qqmusic": "video",
    "music": "video",
    "rednotes": "social",
    "xiaohongshu": "social",
    "social": "social",
    "pinduoduo": "shopping",
    "shopping": "shopping",
    "map": "map",
    "cloud": "cloud",
    "cloud_service": "cloud",
    "netdisk": "cloud",
    "download": "download",
    "chat": "chat",
    "im": "chat",
    "instant_message": "chat",
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

TARGET_DOMAIN_HINTS = {
    "pinduoduo": ("pinduoduo", "yangkeduo", "pdd", "pddpic", "pddcdn"),
    "qq": ("qq.com", "tencent", "qlogo", "gtimg", "myqcloud"),
    "qqmusic": ("music.qq", "y.qq", "qqmusic", "tencentmusic", "gtimg", "qq.com"),
    "rednotes": ("xiaohongshu", "xhscdn", "xhs", "rednote"),
    "tiktok": ("tiktok", "byteoversea", "bytecdn", "ibytedtos", "muscdn", "ttwstatic"),
    "browser": (
        "baidu",
        "bing",
        "google",
        "sogou",
        "edge",
        "msn",
        "github",
        "wikipedia",
    ),
    "browser_proxy": (
        "baidu",
        "bing",
        "google",
        "sogou",
        "edge",
        "msn",
        "github",
        "wikipedia",
    ),
    "chat": ("qq.com", "weixin", "wechat", "tencent", "wx.", "wxapp"),
    "cloud": ("aliyun", "baidu", "pan.baidu", "cloud", "onedrive", "sharepoint"),
    "download": ("download", "dl.", "cdn", "update", "mirror", "pkg", "steam", "microsoft"),
    "video": ("video", "bilibili", "douyin", "iqiyi", "youku", "qq.com", "tencentvideo"),
}

BACKGROUND_DOMAIN_HINTS = (
    "ecs.office.com",
    "office.com",
    "office.net",
    "microsoft.com",
    "windowsupdate",
    "update.microsoft",
    "teams.microsoft",
    "onedrive",
    "sharepoint.com",
    "msftconnecttest",
    "msftncsi",
    "live.com",
    "bingapis.com",
    "apple.com",
    "icloud.com",
    "push.apple.com",
    "gvt1.com",
    "googleapis.com",
    "gstatic.com",
    "mozilla.com",
    "firefox.com",
)

CONTROL_PROTOCOLS = {"arp", "mdns", "llmnr", "nbns", "icmpv6", "igmp"}
PROXY_PORTS = {20067, 23000, 7890, 7891, 7897, 1080, 10808, 8080, 8888}


@dataclass
class CaptureContext:
    json_path: Path
    capture_file: str
    platform: str
    environment: str
    scene: str
    app_name: str
    label: str
    source_group: str


@dataclass
class Flow:
    key: tuple[str, str, str, str, str]
    first_src: str
    first_dst: str
    first_sport: str
    first_dport: str
    protocol: str
    first_ts: float | None = None
    last_ts: float | None = None
    packet_count: int = 0
    byte_count: int = 0
    domains: Counter = field(default_factory=Counter)
    src_ips: Counter = field(default_factory=Counter)
    dst_ips: Counter = field(default_factory=Counter)
    ports: Counter = field(default_factory=Counter)
    protocol_stack: Counter = field(default_factory=Counter)
    notes: set[str] = field(default_factory=set)
    filter_reasons: set[str] = field(default_factory=set)


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
                        in_array = True
                        continue
                    if buf[0] == "{":
                        in_array = True
                    else:
                        raise ValueError(f"Unexpected JSON start in {path}: {buf[:40]!r}")
                buf = buf.lstrip()
                if buf.startswith("]"):
                    return
                if buf.startswith(","):
                    buf = buf[1:]
                    continue
                try:
                    obj, idx = decoder.raw_decode(buf)
                except json.JSONDecodeError:
                    if len(buf) > 256 * 1024 * 1024:
                        raise RuntimeError(f"Parser buffer grew too large while reading {path}")
                    break
                yield obj
                buf = buf[idx:]


def infer_context(json_path: Path, root: Path) -> CaptureContext:
    rel_parts = json_path.relative_to(root).parts
    source_group = rel_parts[0]
    stem = json_path.stem.lower()
    normalized = stem.replace("-", "_").replace(" ", "_")

    platform = "mobile" if source_group.lower() == "android" else "pc"
    environment = "direct"
    if "proxy" in normalized or "代理" in source_group:
        environment = "proxy"
    if "no_proxy" in normalized or "without_vpn" in normalized:
        environment = "direct"
    if "vpn" in normalized and "without_vpn" not in normalized:
        environment = "vpn"

    scene = SCENE_ALIASES.get(normalized)
    if scene is None:
        scene = next((v for k, v in SCENE_ALIASES.items() if k in normalized), normalized)
    app_name = APP_ALIASES.get(normalized)
    if app_name is None:
        app_name = next((v for k, v in APP_ALIASES.items() if k in normalized), normalized)
    label = scene

    pcap_candidates = sorted(json_path.parent.glob(f"{json_path.stem}*.pcap*"))
    if not pcap_candidates and normalized == "browse":
        pcap_candidates = sorted(json_path.parent.glob("browse*.pcap*"))
    capture_file = pcap_candidates[0].name if pcap_candidates else ""

    return CaptureContext(
        json_path=json_path,
        capture_file=capture_file,
        platform=platform,
        environment=environment,
        scene=scene,
        app_name=app_name,
        label=label,
        source_group=source_group,
    )


def is_private_or_control(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return bool(addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified)


def canonical_key(src: str, dst: str, sport: str, dport: str, proto: str) -> tuple[str, str, str, str, str]:
    a = (src, sport)
    b = (dst, dport)
    if a <= b:
        return (src, dst, sport, dport, proto)
    return (dst, src, dport, sport, proto)


def get_layer(packet: dict[str, Any]) -> dict[str, Any]:
    src = packet.get("_source", packet)
    return src.get("layers", src)


def parse_packet(packet: dict[str, Any]) -> dict[str, Any]:
    layers = get_layer(packet)
    frame = layers.get("frame", {}) if isinstance(layers, dict) else {}
    ip = layers.get("ip", {}) if isinstance(layers, dict) else {}
    ipv6 = layers.get("ipv6", {}) if isinstance(layers, dict) else {}
    tcp = layers.get("tcp", {}) if isinstance(layers, dict) else {}
    udp = layers.get("udp", {}) if isinstance(layers, dict) else {}

    proto_stack = scalar(frame.get("frame.protocols")) or ""
    src = scalar(ip.get("ip.src")) or scalar(ipv6.get("ipv6.src"))
    dst = scalar(ip.get("ip.dst")) or scalar(ipv6.get("ipv6.dst"))
    sport = dport = None
    transport = None
    if tcp:
        transport = "TCP"
        sport = scalar(tcp.get("tcp.srcport"))
        dport = scalar(tcp.get("tcp.dstport"))
    elif udp:
        transport = "UDP"
        sport = scalar(udp.get("udp.srcport"))
        dport = scalar(udp.get("udp.dstport"))

    domains = set()
    for name in recursive_values(layers, {"dns.qry.name", "tls.handshake.extensions_server_name", "http.host", "http2.header.authority", "quic.tls.handshake.extensions_server_name"}):
        name = name.strip(".").lower()
        if name and not re.fullmatch(r"[0-9a-f:.]+", name):
            domains.add(name)

    answers = set(recursive_values(layers, {"dns.a", "dns.aaaa"}))
    return {
        "src": src,
        "dst": dst,
        "sport": sport,
        "dport": dport,
        "transport": transport,
        "length": int(float(scalar(frame.get("frame.len")) or 0)),
        "ts": parse_timestamp(scalar(frame.get("frame.time_epoch")) or scalar(frame.get("frame.time"))),
        "proto_stack": proto_stack,
        "domains": domains,
        "answers": answers,
    }


def domain_matches(domain: str, hints: Iterable[str]) -> bool:
    d = domain.lower()
    return any(h in d for h in hints)


def classify_flow(flow: Flow, ctx: CaptureContext, ip_domains: dict[str, Counter]) -> tuple[str, str, str]:
    domains = Counter(flow.domains)
    for ip in [flow.first_dst, flow.first_src, *flow.dst_ips.keys(), *flow.src_ips.keys()]:
        domains.update(ip_domains.get(ip, {}))
    domain = domains.most_common(1)[0][0] if domains else ""
    reasons: list[str] = []

    stack = ":".join(flow.protocol_stack.keys()).lower()
    if any(p in stack for p in CONTROL_PROTOCOLS):
        reasons.append("local_control_protocol")
    if flow.protocol not in {"TCP", "UDP"}:
        reasons.append("non_tcp_udp")
    if is_private_or_control(flow.first_src) and is_private_or_control(flow.first_dst):
        reasons.append("local_or_private_only")
    if domain and domain_matches(domain, BACKGROUND_DOMAIN_HINTS):
        reasons.append("known_system_or_office_background_domain")

    ports = {int(p) for p in flow.ports if str(p).isdigit()}
    if ctx.environment == "proxy" and ports & PROXY_PORTS:
        return "false", "proxy_link_or_proxy_control_connection", domain
    if ctx.environment == "vpn" and (1194 in ports or 51820 in ports or 500 in ports or 4500 in ports):
        return "false", "vpn_tunnel_connection", domain

    app_hints = TARGET_DOMAIN_HINTS.get(ctx.app_name, ()) + TARGET_DOMAIN_HINTS.get(ctx.scene, ())
    if domain and app_hints and domain_matches(domain, app_hints):
        return "false", "target_domain_or_tls_dns_related", domain

    if reasons:
        return "true", ";".join(sorted(set(reasons))), domain

    if not domain and flow.packet_count >= 3 and not (is_private_or_control(flow.first_src) and is_private_or_control(flow.first_dst)):
        return "unknown", "encrypted_or_ip_only_flow_no_domain_observed", domain

    if domain:
        return "unknown", "domain_not_in_target_or_background_rules", domain
    return "true", "insufficient_signal_or_single_local_flow", domain


def packet_to_flow(packet: dict[str, Any], ctx: CaptureContext, flows: dict, ip_domains: dict[str, Counter], counters: Counter) -> None:
    parsed = parse_packet(packet)
    counters["raw_packets"] += 1
    src, dst = parsed["src"], parsed["dst"]
    if not src or not dst or not parsed["transport"] or not parsed["sport"] or not parsed["dport"]:
        counters["non_flow_packets"] += 1
        return

    for domain in parsed["domains"]:
        for answer in parsed["answers"]:
            ip_domains[answer][domain] += 1

    key = canonical_key(src, dst, parsed["sport"], parsed["dport"], parsed["transport"])
    flow = flows.get(key)
    if not flow:
        flow = Flow(key, src, dst, parsed["sport"], parsed["dport"], parsed["transport"], parsed["ts"], parsed["ts"])
        flows[key] = flow
    flow.packet_count += 1
    flow.byte_count += parsed["length"]
    flow.first_ts = parsed["ts"] if flow.first_ts is None else min(flow.first_ts, parsed["ts"])
    flow.last_ts = parsed["ts"] if flow.last_ts is None else max(flow.last_ts, parsed["ts"])
    flow.src_ips[src] += 1
    flow.dst_ips[dst] += 1
    flow.ports[parsed["sport"]] += 1
    flow.ports[parsed["dport"]] += 1
    if parsed["proto_stack"]:
        flow.protocol_stack[parsed["proto_stack"]] += 1
    for domain in parsed["domains"]:
        flow.domains[domain] += 1


def record_from_flow(flow: Flow, ctx: CaptureContext, ip_domains: dict[str, Counter], seq: int) -> dict[str, Any]:
    is_bg, reason, domain = classify_flow(flow, ctx, ip_domains)
    duration = 0.0
    if flow.first_ts is not None and flow.last_ts is not None:
        duration = max(0.0, flow.last_ts - flow.first_ts)
    flow_token = "|".join(map(str, flow.key))
    flow_id = hashlib.sha1(f"{ctx.json_path.name}|{flow_token}".encode("utf-8")).hexdigest()[:16]
    dst_port = flow.first_dport
    return {
        "sample_id": f"{ctx.source_group}_{ctx.json_path.stem}_{seq:06d}",
        "platform": ctx.platform,
        "environment": ctx.environment,
        "scene": ctx.scene,
        "app_name": ctx.app_name,
        "capture_file": ctx.capture_file,
        "label": ctx.label,
        "notes": "retained_uncertain_for_review" if is_bg == "unknown" else "",
        "source_ip": flow.first_src,
        "destination_ip": flow.first_dst,
        "transport_protocol": flow.protocol,
        "destination_port": dst_port,
        "protocol": flow.protocol,
        "dst_port": dst_port,
        "domain": domain,
        "flow_id": flow_id,
        "packet_count": flow.packet_count,
        "byte_count": flow.byte_count,
        "duration": round(duration, 6),
        "is_background": is_bg,
        "filter_reason": reason,
        "source_group": ctx.source_group,
    }


CSV_FIELDS = [
    "sample_id",
    "platform",
    "environment",
    "scene",
    "app_name",
    "capture_file",
    "label",
    "notes",
    "source_ip",
    "destination_ip",
    "transport_protocol",
    "destination_port",
    "protocol",
    "dst_port",
    "domain",
    "flow_id",
    "packet_count",
    "byte_count",
    "duration",
    "is_background",
    "filter_reason",
    "source_group",
]


def process_capture(ctx: CaptureContext) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    flows: dict[tuple[str, str, str, str, str], Flow] = {}
    ip_domains: dict[str, Counter] = defaultdict(Counter)
    counters: Counter = Counter()
    for packet in stream_packet_objects(ctx.json_path):
        packet_to_flow(packet, ctx, flows, ip_domains, counters)

    rows = [record_from_flow(flow, ctx, ip_domains, i + 1) for i, flow in enumerate(flows.values())]
    total_flows = len(rows)
    valid_flows = sum(1 for r in rows if r["is_background"] in {"false", "unknown"})
    filtered_flows = sum(1 for r in rows if r["is_background"] == "true")
    domain_counts = Counter(r["domain"] for r in rows if r["domain"] and r["is_background"] != "true")
    port_counts = Counter(str(r["dst_port"]) for r in rows if r["dst_port"] and r["is_background"] != "true")
    unknown_flows = sum(1 for r in rows if r["is_background"] == "unknown")
    summary = {
        "capture_file": ctx.capture_file or ctx.json_path.name,
        "json_file": str(ctx.json_path),
        "platform": ctx.platform,
        "environment": ctx.environment,
        "scene": ctx.scene,
        "app_name": ctx.app_name,
        "total_packets": counters["raw_packets"],
        "non_flow_packets": counters["non_flow_packets"],
        "total_flows": total_flows,
        "valid_flows": valid_flows,
        "filtered_flows": filtered_flows,
        "unknown_flows": unknown_flows,
        "dominant_domains": ";".join(f"{d}:{c}" for d, c in domain_counts.most_common(10)),
        "dominant_ports": ";".join(f"{p}:{c}" for p, c in port_counts.most_common(10)),
        "notes": "target_traffic_sparse_or_noisy" if total_flows and valid_flows / total_flows < 0.25 else "",
    }
    return rows, summary


def write_outputs(all_rows: list[dict[str, Any]], summaries: list[dict[str, Any]], out_dir: Path, contexts: list[CaptureContext]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    clean_rows = [r for r in all_rows if r["is_background"] in {"false", "unknown"}]

    with (out_dir / "cleaned_flow_dataset.jsonl").open("w", encoding="utf-8", newline="") as fh:
        for row in clean_rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    with (out_dir / "cleaned_flow_dataset.csv").open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(clean_rows)

    summary_fields = [
        "capture_file",
        "json_file",
        "platform",
        "environment",
        "scene",
        "app_name",
        "total_packets",
        "non_flow_packets",
        "total_flows",
        "valid_flows",
        "filtered_flows",
        "unknown_flows",
        "dominant_domains",
        "dominant_ports",
        "notes",
    ]
    with (out_dir / "capture_summary.csv").open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=summary_fields)
        writer.writeheader()
        writer.writerows(summaries)

    mapping = {
        "scene_aliases": SCENE_ALIASES,
        "app_aliases": APP_ALIASES,
        "label_space": sorted({c.label for c in contexts}),
        "environment_values": ["direct", "proxy", "vpn"],
        "platform_values": ["mobile", "pc"],
        "background_domain_hints": list(BACKGROUND_DOMAIN_HINTS),
        "target_domain_hints": {k: list(v) for k, v in TARGET_DOMAIN_HINTS.items()},
    }
    (out_dir / "label_mapping.json").write_text(json.dumps(mapping, ensure_ascii=False, indent=2), encoding="utf-8")

    label_counts = Counter(r["label"] for r in clean_rows)
    env_counts = Counter(r["environment"] for r in clean_rows)
    bg_counts = Counter(r["is_background"] for r in all_rows)
    reason_counts = Counter(r["filter_reason"] for r in all_rows if r["is_background"] == "true")
    uncertain = [r for r in clean_rows if r["is_background"] == "unknown"]
    sparse = [s for s in summaries if s["notes"]]

    report = []
    report.append("# Cleaning Report\n")
    report.append("## Overview\n")
    report.append(f"- Raw capture JSON files processed: {len(contexts)}")
    report.append(f"- Raw flow records before filtering: {len(all_rows)}")
    report.append(f"- Clean/retained flow records written: {len(clean_rows)}")
    report.append(f"- Filtered background flow records: {bg_counts.get('true', 0)}")
    report.append(f"- Retained uncertain flow records: {bg_counts.get('unknown', 0)}")
    report.append("\n## Retained Flow Counts By Label\n")
    for label, count in sorted(label_counts.items()):
        report.append(f"- {label}: {count}")
    report.append("\n## Retained Flow Counts By Environment\n")
    for env, count in sorted(env_counts.items()):
        report.append(f"- {env}: {count}")
    report.append("\n## Filtered Background Types\n")
    for reason, count in reason_counts.most_common(20):
        report.append(f"- {reason}: {count}")
    report.append("\n## Cleaning Rules\n")
    report.append("- Flow construction: bidirectional five-tuple `(src_ip, dst_ip, src_port, dst_port, protocol)` from packet-level Wireshark JSON.")
    report.append("- Label normalization: filenames and source folders were mapped to stable `scene`, `app_name`, `platform`, and `environment` values.")
    report.append("- DNS/TLS/HTTP/QUIC domain hints were retained when they matched the target app/scene or proxy/VPN path.")
    report.append("- Local control traffic such as ARP, mDNS, LLMNR, NBNS, ICMPv6, multicast/local-only flows, and non TCP/UDP packets were treated as background.")
    report.append("- Known system/background domains including Office, Teams, OneDrive, Windows update/connectivity checks, Apple/iCloud, and browser telemetry/update endpoints were filtered unless they were explicitly part of the labeled target class.")
    report.append("- Proxy/VPN transport links were retained as valid environment-path flows when proxy/VPN ports were observed.")
    report.append("- Encrypted flows with no visible domain but enough packet evidence were retained as `is_background=unknown` for conservative downstream review.")
    report.append("\n## Uncertain Retained Samples\n")
    if uncertain:
        report.append(f"- Total uncertain retained flows: {len(uncertain)}")
        for row in uncertain[:50]:
            report.append(f"- {row['sample_id']} {row['source_ip']} -> {row['destination_ip']}:{row['destination_port']} ({row['label']}, {row['environment']}): {row['filter_reason']}")
        if len(uncertain) > 50:
            report.append(f"- Additional uncertain flows omitted from report: {len(uncertain) - 50}")
    else:
        report.append("- None.")
    report.append("\n## Sparse Or Noisy Captures\n")
    if sparse:
        for item in sparse:
            report.append(f"- {item['capture_file']}: valid_flows={item['valid_flows']}, filtered_flows={item['filtered_flows']}, notes={item['notes']}")
    else:
        report.append("- None flagged by the valid-flow ratio rule.")
    report.append("\n## Capture Summary\n")
    for item in summaries:
        report.append(f"- {item['capture_file']}: platform={item['platform']}, environment={item['environment']}, scene={item['scene']}, total_flows={item['total_flows']}, valid={item['valid_flows']}, filtered={item['filtered_flows']}, unknown={item['unknown_flows']}")
    (out_dir / "cleaning_report.md").write_text("\n".join(report) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()

    root = args.root.resolve()
    out_dir = (args.out or root / "cleaned_dataset").resolve()
    json_files = sorted(p for p in root.rglob("*.json") if "cleaned_dataset" not in p.parts and p.name != "label_mapping.json")
    contexts = [infer_context(path, root) for path in json_files]

    all_rows: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    for idx, ctx in enumerate(contexts, 1):
        print(f"[{idx}/{len(contexts)}] processing {ctx.json_path}", flush=True)
        rows, summary = process_capture(ctx)
        all_rows.extend(rows)
        summaries.append(summary)
        print(
            f"  flows={summary['total_flows']} retained={summary['valid_flows']} filtered={summary['filtered_flows']} unknown={summary['unknown_flows']}",
            flush=True,
        )

    write_outputs(all_rows, summaries, out_dir, contexts)
    print(f"wrote outputs to {out_dir}", flush=True)


if __name__ == "__main__":
    main()
