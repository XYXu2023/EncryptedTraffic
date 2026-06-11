#!/usr/bin/env python3
"""Create train/val/test splits for encrypted traffic classification."""

from __future__ import annotations

import argparse
import random
from collections import Counter, defaultdict
from pathlib import Path

from common import read_csv, write_csv


def split_label_rows(rows: list[dict], seed: int) -> tuple[list[dict], list[dict], list[dict], str]:
    by_capture = defaultdict(list)
    for row in rows:
        by_capture[row["capture_file"]].append(row)
    groups = list(by_capture.values())
    rnd = random.Random(seed)
    rnd.shuffle(groups)
    if len(groups) >= 3:
        train, val, test = [], [], []
        for group in groups:
            sizes = (len(train), len(val), len(test))
            total = sum(sizes) + 1
            ratios = (sizes[0] / total, sizes[1] / total, sizes[2] / total)
            target = (0.7, 0.1, 0.2)
            bucket = min(range(3), key=lambda i: ratios[i] - target[i])
            [train, val, test][bucket].extend(group)
        return train, val, test, "grouped_by_capture"
    rnd.shuffle(rows)
    n = len(rows)
    n_train = max(1, int(n * 0.7))
    n_val = max(1, int(n * 0.1)) if n >= 10 else 0
    return rows[:n_train], rows[n_train : n_train + n_val], rows[n_train + n_val :], "flow_stratified_capture_group_insufficient"


def main() -> None:
    parser = argparse.ArgumentParser(description="Split flow feature table.")
    parser.add_argument("--input", type=Path, default=Path("outputs/flow_features.csv"))
    parser.add_argument("--output-dir", type=Path, default=Path("outputs"))
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    rows = [r for r in read_csv(args.input) if r.get("label")]
    label_groups = defaultdict(list)
    for row in rows:
        label_groups[row["label"]].append(row)
    train, val, test = [], [], []
    notes = []
    for label, label_rows in sorted(label_groups.items()):
        a, b, c, note = split_label_rows(label_rows, args.seed)
        train.extend(a)
        val.extend(b)
        test.extend(c)
        notes.append(f"- {label}: {note}, train={len(a)}, val={len(b)}, test={len(c)}")
    fields = list(rows[0].keys()) if rows else []
    write_csv(args.output_dir / "train.csv", train, fields)
    write_csv(args.output_dir / "val.csv", val, fields)
    write_csv(args.output_dir / "test.csv", test, fields)
    report = [
        "# Split Summary",
        "",
        f"- Total flows: {len(rows)}",
        f"- Train flows: {len(train)}",
        f"- Val flows: {len(val)}",
        f"- Test flows: {len(test)}",
        "",
        "## Label Distribution",
        f"- Train: {dict(Counter(r['label'] for r in train))}",
        f"- Val: {dict(Counter(r['label'] for r in val))}",
        f"- Test: {dict(Counter(r['label'] for r in test))}",
        "",
        "## Leakage Control Notes",
        "The splitter groups by `capture_file` when a label has at least three captures. For labels with fewer captures, it falls back to stratified flow-level splitting and records this limitation.",
        "",
        "## Per Label Strategy",
        *notes,
    ]
    (args.output_dir / "split_summary.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    print(f"Split complete: train={len(train)}, val={len(val)}, test={len(test)}")


if __name__ == "__main__":
    main()
