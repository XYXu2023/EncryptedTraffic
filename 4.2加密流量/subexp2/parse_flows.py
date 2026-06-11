#!/usr/bin/env python3
"""Parse Wireshark JSON/PCAP metadata into bidirectional five-tuple flows."""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from common import FlowAgg, canonical_key, infer_context, packet_from_wireshark_json, stream_packet_objects, write_csv, write_jsonl


SUMMARY_FIELDS = [
    "capture_file",
    "source_json",
    "label",
    "platform",
    "environment",
    "total_flows",
    "valid_flows",
    "background_guess_flows",
    "total_packets",
    "flow_packets",
    "non_flow_packets",
]


def parse_json_file(path: Path, root: Path) -> tuple[list[dict], dict]:
    context = infer_context(path, root)
    flows: dict[tuple[str, str, str, str, str], FlowAgg] = {}
    total_packets = flow_packets = non_flow_packets = 0
    for obj in stream_packet_objects(path):
        total_packets += 1
        pkt = packet_from_wireshark_json(obj)
        if pkt is None:
            non_flow_packets += 1
            continue
        flow_packets += 1
        key = canonical_key(pkt["src_ip"], pkt["dst_ip"], pkt["src_port"], pkt["dst_port"], pkt["protocol"])
        flow = flows.get(key)
        if flow is None:
            flow = FlowAgg(key, pkt["src_ip"], pkt["dst_ip"], pkt["src_port"], pkt["dst_port"], pkt["protocol"])
            flows[key] = flow
        flow.add(pkt)
    rows = [flow.to_record(context, str(path)) for flow in flows.values()]
    bg = Counter(row["is_background_guess"] for row in rows)
    summary = {
        "capture_file": context["capture_file"],
        "source_json": str(path),
        "label": context["label"],
        "platform": context["platform"],
        "environment": context["environment"],
        "total_flows": len(rows),
        "valid_flows": bg.get("false", 0),
        "background_guess_flows": bg.get("true", 0),
        "total_packets": total_packets,
        "flow_packets": flow_packets,
        "non_flow_packets": non_flow_packets,
    }
    return rows, summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Parse packet-level JSON into flow records.")
    parser.add_argument("--input-root", type=Path, default=Path(".."))
    parser.add_argument("--output-dir", type=Path, default=Path("outputs"))
    parser.add_argument("--include-background", action="store_true", help="Keep flows guessed as background.")
    args = parser.parse_args()

    root = args.input_root.resolve()
    out = args.output_dir.resolve()
    json_files = sorted(
        p
        for p in root.rglob("*.json")
        if "cleaned_dataset" not in p.parts and "subexp2" not in p.parts and p.name != "label_mapping.json"
    )
    if not json_files:
        raise SystemExit(f"No packet JSON files found under {root}")

    all_rows = []
    summaries = []
    for i, path in enumerate(json_files, 1):
        print(f"[{i}/{len(json_files)}] parsing {path}", flush=True)
        rows, summary = parse_json_file(path, root)
        summaries.append(summary)
        kept = rows if args.include_background else [r for r in rows if r["is_background_guess"] != "true"]
        all_rows.extend(kept)
        print(
            f"  flows={summary['total_flows']} kept={len(kept)} background_guess={summary['background_guess_flows']}",
            flush=True,
        )

    write_jsonl(out / "parsed_flows.jsonl", all_rows)
    write_csv(out / "parsed_flows_summary.csv", summaries, SUMMARY_FIELDS)
    print(f"Wrote {len(all_rows)} flows to {out / 'parsed_flows.jsonl'}")


if __name__ == "__main__":
    main()
