#!/usr/bin/env python3
"""Run cross-network-environment classification experiments."""

from __future__ import annotations

import argparse
from pathlib import Path

from common import ALL_NUMERIC_FEATURES, CATEGORICAL_FEATURES, LabelEncoder, Preprocessor, RandomForest, evaluate_predictions, read_csv, save_simple_bar_png, write_csv


def train_eval(name: str, train_rows: list[dict], test_rows: list[dict]) -> dict:
    if len(set(r["label"] for r in train_rows)) < 2 or not test_rows:
        return {"experiment": name, "train_flows": len(train_rows), "test_flows": len(test_rows), "accuracy": "", "f1_macro": "", "f1_weighted": "", "notes": "insufficient labels or test rows"}
    pre = Preprocessor(ALL_NUMERIC_FEATURES, CATEGORICAL_FEATURES).fit(train_rows)
    enc = LabelEncoder().fit([r["label"] for r in train_rows])
    known_test = [r for r in test_rows if r["label"] in enc.classes]
    if not known_test:
        return {"experiment": name, "train_flows": len(train_rows), "test_flows": len(test_rows), "accuracy": "", "f1_macro": "", "f1_weighted": "", "notes": "test labels absent from training labels"}
    model = RandomForest(n_estimators=30, max_depth=8, seed=23)
    model.fit(pre.transform(train_rows), enc.transform([r["label"] for r in train_rows]), len(enc.classes))
    pred = enc.inverse(model.predict(pre.transform(known_test)))
    metrics = evaluate_predictions([r["label"] for r in known_test], pred, enc.classes)
    return {
        "experiment": name,
        "train_flows": len(train_rows),
        "test_flows": len(known_test),
        "accuracy": metrics["accuracy"],
        "f1_macro": metrics["macro"]["f1"],
        "f1_weighted": metrics["weighted"]["f1"],
        "notes": "",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run cross-environment experiments.")
    parser.add_argument("--features", type=Path, default=Path("outputs/flow_features.csv"))
    parser.add_argument("--train", type=Path, default=Path("outputs/train.csv"))
    parser.add_argument("--test", type=Path, default=Path("outputs/test.csv"))
    parser.add_argument("--output-dir", type=Path, default=Path("outputs"))
    args = parser.parse_args()
    train_split = read_csv(args.train)
    test_split = read_csv(args.test)
    rows = read_csv(args.features)
    direct_train = [r for r in train_split if r["environment"] == "direct"]
    direct_test = [r for r in test_split if r["environment"] == "direct"]
    proxy = [r for r in rows if r["environment"] == "proxy"]
    vpn = [r for r in rows if r["environment"] == "vpn"]
    results = [
        train_eval("direct_train_direct_test", direct_train, direct_test),
        train_eval("direct_train_proxy_test", direct_train, proxy),
        train_eval("direct_train_vpn_test", direct_train, vpn),
        train_eval("mixed_train_mixed_test", train_split, test_split),
    ]
    write_csv(args.output_dir / "cross_env_results.csv", results)
    plottable = [r for r in results if r["f1_weighted"] != ""]
    save_simple_bar_png(args.output_dir / "cross_env_plot.png", [r["experiment"] for r in plottable], [float(r["f1_weighted"]) for r in plottable], "Cross Env")
    lines = ["# Cross Environment Report", "", "## Results"]
    for row in results:
        if row["f1_weighted"] == "":
            lines.append(f"- {row['experiment']}: not available ({row['notes']})")
        else:
            lines.append(f"- {row['experiment']}: accuracy={float(row['accuracy']):.4f}, weighted_f1={float(row['f1_weighted']):.4f}, train={row['train_flows']}, test={row['test_flows']}")
    lines.extend(
        [
            "",
            "## Interpretation Template",
            "Compare direct-to-direct with direct-to-proxy/VPN. A lower proxy/VPN score indicates that encapsulation, proxy endpoints, or changed timing/burst patterns reduce classifier transferability. If VPN is unavailable, report it as a data limitation rather than a negative result.",
        ]
    )
    (args.output_dir / "cross_env_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("Cross-environment experiment complete")


if __name__ == "__main__":
    main()
