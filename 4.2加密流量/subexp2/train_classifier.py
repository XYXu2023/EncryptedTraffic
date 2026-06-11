#!/usr/bin/env python3
"""Train baseline encrypted traffic classifiers."""

from __future__ import annotations

import argparse
import pickle
from pathlib import Path

from common import (
    ALL_NUMERIC_FEATURES,
    CATEGORICAL_FEATURES,
    LabelEncoder,
    Preprocessor,
    RandomForest,
    SoftmaxLogisticRegression,
    evaluate_predictions,
    now,
    read_csv,
)


def train_one(model_name: str, train_rows: list[dict], val_rows: list[dict], out_dir: Path, log: list[str]) -> None:
    pre = Preprocessor(ALL_NUMERIC_FEATURES, CATEGORICAL_FEATURES).fit(train_rows)
    encoder = LabelEncoder().fit([r["label"] for r in train_rows])
    x_train = pre.transform(train_rows)
    y_train = encoder.transform([r["label"] for r in train_rows])
    x_val = pre.transform(val_rows)
    y_val_true = [r["label"] for r in val_rows]

    if model_name == "random_forest":
        model = RandomForest(n_estimators=35, max_depth=9, seed=42)
    elif model_name == "logistic_regression":
        model = SoftmaxLogisticRegression(lr=0.05, epochs=220, l2=0.001, seed=42)
    else:
        raise ValueError(f"Unsupported model: {model_name}")

    start = now()
    model.fit(x_train, y_train, len(encoder.classes))
    train_seconds = now() - start
    pred_ids = model.predict(x_val) if val_rows else []
    y_pred = encoder.inverse(pred_ids) if pred_ids else []
    metrics = evaluate_predictions(y_val_true, y_pred, encoder.classes) if val_rows else {"accuracy": 0.0, "macro": {"f1": 0.0}}
    payload = {
        "model_name": model_name,
        "model": model,
        "preprocessor": pre,
        "label_encoder": encoder,
        "feature_names": pre.feature_names,
        "train_seconds": train_seconds,
    }
    model_path = out_dir / "models" / f"{model_name}.pkl"
    model_path.parent.mkdir(parents=True, exist_ok=True)
    with model_path.open("wb") as fh:
        pickle.dump(payload, fh)
    log.append(
        f"{model_name}: train_seconds={train_seconds:.6f}, val_accuracy={metrics['accuracy']:.4f}, val_macro_f1={metrics['macro']['f1']:.4f}, model={model_path}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Train baseline classifiers.")
    parser.add_argument("--train", type=Path, default=Path("outputs/train.csv"))
    parser.add_argument("--val", type=Path, default=Path("outputs/val.csv"))
    parser.add_argument("--output-dir", type=Path, default=Path("outputs"))
    parser.add_argument("--models", nargs="+", default=["random_forest", "logistic_regression"])
    args = parser.parse_args()

    train_rows = read_csv(args.train)
    val_rows = read_csv(args.val)
    log = [f"train_rows={len(train_rows)}", f"val_rows={len(val_rows)}"]
    for model_name in args.models:
        train_one(model_name, train_rows, val_rows, args.output_dir, log)
    (args.output_dir / "training_log.txt").write_text("\n".join(log) + "\n", encoding="utf-8")
    print("\n".join(log))


if __name__ == "__main__":
    main()
