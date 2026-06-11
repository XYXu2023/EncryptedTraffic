#!/usr/bin/env python3
"""Evaluate online first-N-packet inference with labeled replay flows."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

from model_service import ModelService
from online_features import session_to_feature_row
from session_manager import PacketEvent, SessionManager


def metrics(y_true: list[str], y_pred: list[str]) -> tuple[dict, list[dict]]:
    labels = sorted(set(y_true) | set(y_pred))
    total = len(y_true)
    accuracy = sum(a == b for a, b in zip(y_true, y_pred)) / total if total else 0.0
    rows = []
    for label in labels:
        tp = sum(t == label and p == label for t, p in zip(y_true, y_pred))
        fp = sum(t != label and p == label for t, p in zip(y_true, y_pred))
        fn = sum(t == label and p != label for t, p in zip(y_true, y_pred))
        support = sum(t == label for t in y_true)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        rows.append({"label": label, "precision": precision, "recall": recall, "f1": f1, "support": support})
    macro_f1 = sum(r["f1"] for r in rows) / len(rows) if rows else 0.0
    weighted_f1 = sum(r["f1"] * r["support"] for r in rows) / max(1, total)
    return {"accuracy": accuracy, "macro_f1": macro_f1, "weighted_f1": weighted_f1, "total": total}, rows


def predict_flow(row: dict, service: ModelService, first_n: int) -> dict:
    manager = SessionManager(timeout_seconds=999999, max_packets=first_n)
    times = row.get("packet_times") or [0.0]
    lengths = row.get("packet_lengths") or [int(row.get("byte_count") or 60)]
    directions = row.get("packet_directions") or [1] * len(lengths)
    session = None
    for idx, length in enumerate(lengths[:first_n]):
        direction = directions[idx] if idx < len(directions) else 1
        if direction == 1:
            src_ip, dst_ip = row.get("src_ip", ""), row.get("dst_ip", "")
            src_port, dst_port = row.get("src_port", ""), row.get("dst_port", "")
        else:
            src_ip, dst_ip = row.get("dst_ip", ""), row.get("src_ip", "")
            src_port, dst_port = row.get("dst_port", ""), row.get("src_port", "")
        event = PacketEvent(
            ts=float(times[idx] if idx < len(times) else idx),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=str(src_port),
            dst_port=str(dst_port),
            protocol=row.get("protocol", "TCP"),
            length=int(length),
            protocol_stack=row.get("protocol_stack", ""),
        )
        session = manager.ingest(event)
    snap = session.snapshot() if session else {}
    feature = session_to_feature_row(snap, platform=row.get("platform", "pc"), environment=row.get("environment", "direct"))
    pred = service.predict_one(feature)
    return {
        "flow_id": row.get("flow_id", ""),
        "capture_file": row.get("capture_file", ""),
        "true_label": row.get("label", "unknown"),
        "predicted_label": pred["predicted_label"],
        "confidence": pred["confidence"],
        "packet_count_used": min(first_n, len(lengths)),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate online first-N-packet classification on labeled replay data.")
    parser.add_argument("--input", type=Path, default=Path("../subexp2/outputs/parsed_flows.jsonl"))
    parser.add_argument("--model", type=Path, default=Path("../subexp2/outputs/models/random_forest.pkl"))
    parser.add_argument("--output-dir", type=Path, default=Path("outputs"))
    parser.add_argument("--first-n", type=int, default=20)
    args = parser.parse_args()

    service = ModelService(model_path=args.model)
    results = []
    with args.input.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            if line.strip():
                results.append(predict_flow(json.loads(line), service, args.first_n))

    y_true = [r["true_label"] for r in results]
    y_pred = [r["predicted_label"] for r in results]
    overall, per_label = metrics(y_true, y_pred)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    with (args.output_dir / "online_replay_predictions.csv").open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["flow_id", "capture_file", "true_label", "predicted_label", "confidence", "packet_count_used"])
        writer.writeheader()
        writer.writerows(results)
    with (args.output_dir / "online_replay_classification_report.csv").open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["label", "precision", "recall", "f1", "support"])
        writer.writeheader()
        writer.writerows(per_label)
    pred_counts = Counter(y_pred)
    true_counts = Counter(y_true)
    report = [
        "# Online Replay Evaluation",
        "",
        f"- First N packets: {args.first_n}",
        f"- Total labeled flows: {overall['total']}",
        f"- Accuracy: {overall['accuracy']:.4f}",
        f"- Macro F1: {overall['macro_f1']:.4f}",
        f"- Weighted F1: {overall['weighted_f1']:.4f}",
        "",
        "## True Label Distribution",
        *(f"- {k}: {v}" for k, v in sorted(true_counts.items())),
        "",
        "## Predicted Label Distribution",
        *(f"- {k}: {v}" for k, v in sorted(pred_counts.items())),
        "",
        "## Notes",
        "- This evaluates the online first-N-packet feature path, not the offline complete-flow classifier.",
        "- Live traffic accuracy still requires manually labeled live captures or a controlled browsing script.",
    ]
    (args.output_dir / "online_replay_metrics.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report[:8]))


if __name__ == "__main__":
    main()
