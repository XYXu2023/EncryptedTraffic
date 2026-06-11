#!/usr/bin/env python3
"""Run feature ablation experiments."""

from __future__ import annotations

import argparse
from pathlib import Path

from common import (
    BASIC_FEATURES,
    BURST_FEATURES,
    CATEGORICAL_FEATURES,
    CONTEXT_FEATURES,
    DIRECTION_FEATURES,
    LabelEncoder,
    Preprocessor,
    RandomForest,
    TEMPORAL_FEATURES,
    evaluate_predictions,
    now,
    read_csv,
    save_simple_bar_png,
    write_csv,
)


SETS = {
    "A_basic": BASIC_FEATURES,
    "B_basic_temporal": BASIC_FEATURES + TEMPORAL_FEATURES,
    "C_basic_temporal_burst": BASIC_FEATURES + TEMPORAL_FEATURES + BURST_FEATURES,
    "D_all_features": BASIC_FEATURES + TEMPORAL_FEATURES + DIRECTION_FEATURES + BURST_FEATURES + CONTEXT_FEATURES,
}


def run_set(name: str, features: list[str], train_rows: list[dict], test_rows: list[dict]) -> dict:
    pre = Preprocessor(features, CATEGORICAL_FEATURES).fit(train_rows)
    enc = LabelEncoder().fit([r["label"] for r in train_rows])
    x_train = pre.transform(train_rows)
    y_train = enc.transform([r["label"] for r in train_rows])
    model = RandomForest(n_estimators=30, max_depth=8, seed=17)
    start = now()
    model.fit(x_train, y_train, len(enc.classes))
    train_s = now() - start
    pred = enc.inverse(model.predict(pre.transform(test_rows)))
    metrics = evaluate_predictions([r["label"] for r in test_rows], pred, enc.classes)
    return {
        "feature_set": name,
        "feature_count": len(pre.feature_names),
        "accuracy": metrics["accuracy"],
        "precision_macro": metrics["macro"]["precision"],
        "recall_macro": metrics["macro"]["recall"],
        "f1_macro": metrics["macro"]["f1"],
        "f1_weighted": metrics["weighted"]["f1"],
        "train_seconds": train_s,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run feature ablation.")
    parser.add_argument("--train", type=Path, default=Path("outputs/train.csv"))
    parser.add_argument("--test", type=Path, default=Path("outputs/test.csv"))
    parser.add_argument("--output-dir", type=Path, default=Path("outputs"))
    args = parser.parse_args()
    train_rows = read_csv(args.train)
    test_rows = read_csv(args.test)
    rows = [run_set(name, feats, train_rows, test_rows) for name, feats in SETS.items()]
    write_csv(args.output_dir / "ablation_results.csv", rows)
    save_simple_bar_png(args.output_dir / "ablation_plot.png", [r["feature_set"] for r in rows], [float(r["f1_weighted"]) for r in rows], "Ablation")
    lines = ["# Ablation Report", "", "RandomForest was retrained for each feature set.", ""]
    for row in rows:
        lines.append(f"- {row['feature_set']}: accuracy={float(row['accuracy']):.4f}, weighted_f1={float(row['f1_weighted']):.4f}, features={row['feature_count']}")
    best = max(rows, key=lambda r: float(r["f1_weighted"])) if rows else None
    if best:
        lines.append("")
        lines.append(f"Best feature set: `{best['feature_set']}`.")
    (args.output_dir / "ablation_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("Ablation complete")


if __name__ == "__main__":
    main()
