#!/usr/bin/env python3
"""Model loading and online inference wrapper."""

from __future__ import annotations

import pickle
import sys
from pathlib import Path
from typing import Any
from collections import Counter


class ModelService:
    def __init__(self, model_path: Path | str | None = None, subexp2_dir: Path | str | None = None) -> None:
        self.model_path = Path(model_path) if model_path else Path("../subexp2/outputs/models/random_forest.pkl")
        self.subexp2_dir = Path(subexp2_dir) if subexp2_dir else Path("../subexp2").resolve()
        self.payload: dict[str, Any] | None = None
        self.error: str = ""
        self.load()

    def load(self) -> None:
        try:
            if str(self.subexp2_dir) not in sys.path:
                sys.path.insert(0, str(self.subexp2_dir))
            with self.model_path.open("rb") as fh:
                self.payload = pickle.load(fh)
            self.error = ""
        except Exception as exc:
            self.payload = None
            self.error = f"{type(exc).__name__}: {exc}"

    @property
    def ready(self) -> bool:
        return self.payload is not None

    def predict_one(self, feature_row: dict[str, Any]) -> dict[str, Any]:
        if not self.payload:
            label = self._fallback_label(feature_row)
            return {"predicted_label": label, "confidence": 0.35, "model": "fallback_rules", "error": self.error}
        try:
            pre = self.payload["preprocessor"]
            model = self.payload["model"]
            enc = self.payload["label_encoder"]
            x = pre.transform([feature_row])
            pred_id = model.predict(x)[0]
            confidence = 0.80
            if hasattr(model, "trees"):
                votes = Counter(tree.predict_one(x[0]) for tree in model.trees)
                pred_id, vote_count = votes.most_common(1)[0]
                confidence = vote_count / max(1, len(model.trees))
            label = enc.inverse([pred_id])[0]
            if hasattr(model, "predict_proba_one"):
                probs = model.predict_proba_one(x[0])
                confidence = max(probs) if probs else confidence
            return {"predicted_label": label, "confidence": round(float(confidence), 4), "model": self.payload.get("model_name", "model")}
        except Exception as exc:
            return {"predicted_label": "unknown", "confidence": 0.0, "model": "error", "error": f"{type(exc).__name__}: {exc}"}

    def predict_batch(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [self.predict_one(row) for row in rows]

    def _fallback_label(self, row: dict[str, Any]) -> str:
        port = int(float(row.get("dst_port") or 0))
        total_bytes = float(row.get("total_bytes") or 0)
        packets = float(row.get("total_packets") or 0)
        if port == 53:
            return "browser"
        if total_bytes > 2_000_000 or packets > 200:
            return "video"
        if port in {80, 443, 8080}:
            return "browser"
        return "unknown"
