#!/usr/bin/env python3
"""Evaluate trained models on the held-out test set."""

from __future__ import annotations

import argparse
import csv
import pickle
from pathlib import Path

from common import evaluate_predictions, now, read_csv, save_confusion_png, write_csv


def evaluate_one(model_path: Path, test_rows: list[dict]) -> tuple[dict, list[dict], list[list[int]], list[str], float]:
    with model_path.open("rb") as fh:
        payload = pickle.load(fh)
    x_test = payload["preprocessor"].transform(test_rows)
    y_true = [r["label"] for r in test_rows]
    labels = payload["label_encoder"].classes
    start = now()
    pred_ids = payload["model"].predict(x_test)
    infer_seconds = now() - start
    y_pred = payload["label_encoder"].inverse(pred_ids)
    metrics = evaluate_predictions(y_true, y_pred, labels)
    rows = []
    for item in metrics["per_label"]:
        rows.append({"model": payload["model_name"], **item})
    return metrics, rows, metrics["confusion_matrix"], labels, infer_seconds / max(1, len(test_rows))


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate trained classifiers.")
    parser.add_argument("--test", type=Path, default=Path("outputs/test.csv"))
    parser.add_argument("--model-dir", type=Path, default=Path("outputs/models"))
    parser.add_argument("--output-dir", type=Path, default=Path("outputs"))
    args = parser.parse_args()

    test_rows = read_csv(args.test)
    report = ["# Metrics Report", "", f"- Test flows: {len(test_rows)}", ""]
    efficiency = ["# Efficiency Report", ""]
    all_class_rows = []
    best = None
    for model_path in sorted(args.model_dir.glob("*.pkl")):
        metrics, class_rows, matrix, labels, per_flow = evaluate_one(model_path, test_rows)
        model_name = model_path.stem
        all_class_rows.extend(class_rows)
        report.extend(
            [
                f"## {model_name}",
                f"- Accuracy: {metrics['accuracy']:.4f}",
                f"- Precision macro / weighted: {metrics['macro']['precision']:.4f} / {metrics['weighted']['precision']:.4f}",
                f"- Recall macro / weighted: {metrics['macro']['recall']:.4f} / {metrics['weighted']['recall']:.4f}",
                f"- F1 macro / weighted: {metrics['macro']['f1']:.4f} / {metrics['weighted']['f1']:.4f}",
                "",
            ]
        )
        efficiency.append(f"- {model_name}: per_flow_inference_ms={per_flow * 1000:.6f}")
        if best is None or metrics["weighted"]["f1"] > best[0]:
            best = (metrics["weighted"]["f1"], matrix, labels, model_name)
    if best:
        save_confusion_png(args.output_dir / "confusion_matrix.png", best[1], best[2])
        report.append(f"Best model by weighted F1: `{best[3]}`")
    write_csv(args.output_dir / "classification_report.csv", all_class_rows, ["model", "label", "precision", "recall", "f1", "support"])
    (args.output_dir / "metrics_report.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    (args.output_dir / "efficiency_report.md").write_text("\n".join(efficiency) + "\n", encoding="utf-8")
    print("Evaluation complete")


if __name__ == "__main__":
    main()
