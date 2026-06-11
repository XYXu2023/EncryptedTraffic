#!/usr/bin/env python3
"""Extract encrypted-traffic statistical and behavioral flow features."""

from __future__ import annotations

import argparse
from pathlib import Path

from common import ALL_FEATURES, features_from_flow, now, read_jsonl, write_csv, write_jsonl


META_FIELDS = ["flow_id", "capture_file", "label", "platform", "environment", "app_name", "src_ip", "dst_ip"]


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract flow-level ML features.")
    parser.add_argument("--input", type=Path, default=Path("outputs/parsed_flows.jsonl"))
    parser.add_argument("--output-dir", type=Path, default=Path("outputs"))
    args = parser.parse_args()

    rows = read_jsonl(args.input)
    start = now()
    features = [features_from_flow(row) for row in rows if row.get("label")]
    elapsed = now() - start
    per_flow_ms = elapsed * 1000 / max(1, len(features))
    fields = META_FIELDS + ALL_FEATURES + ["is_background_guess"]
    write_csv(args.output_dir / "flow_features.csv", features, fields)
    write_jsonl(args.output_dir / "flow_features.jsonl", features)
    (args.output_dir / "feature_extraction_log.txt").write_text(
        f"flows={len(features)}\nfeature_extraction_seconds={elapsed:.6f}\nper_flow_ms={per_flow_ms:.6f}\n",
        encoding="utf-8",
    )
    print(f"Extracted features for {len(features)} flows in {elapsed:.3f}s ({per_flow_ms:.4f} ms/flow)")


if __name__ == "__main__":
    main()
