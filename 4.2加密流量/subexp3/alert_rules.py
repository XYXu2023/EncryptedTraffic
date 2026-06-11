#!/usr/bin/env python3
"""Configurable alert rules for online traffic detection."""

from __future__ import annotations

import time
from collections import Counter, deque
from dataclasses import dataclass
from typing import Any


@dataclass
class AlertConfig:
    low_confidence_threshold: float = 0.45
    unknown_ratio_threshold: float = 0.35
    short_flow_packet_threshold: int = 3
    short_flow_window_threshold: int = 20
    label_spike_threshold: int = 60
    hot_port_threshold: int = 80
    window_size: int = 200


class AlertEngine:
    def __init__(self, config: AlertConfig | None = None) -> None:
        self.config = config or AlertConfig()
        self.recent: deque[dict[str, Any]] = deque(maxlen=self.config.window_size)
        self.alerts: deque[dict[str, Any]] = deque(maxlen=200)

    def observe_prediction(self, prediction: dict[str, Any], session: dict[str, Any]) -> list[dict[str, Any]]:
        event = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "flow_id": session.get("flow_id", ""),
            "label": prediction.get("predicted_label", "unknown"),
            "confidence": float(prediction.get("confidence") or 0.0),
            "dst_port": str(session.get("dst_port", "")),
            "protocol": session.get("protocol", ""),
            "packet_count": int(session.get("packet_count") or 0),
        }
        self.recent.append(event)
        new_alerts: list[dict[str, Any]] = []
        if event["label"] == "unknown" or event["confidence"] < self.config.low_confidence_threshold:
            new_alerts.append(self._make_alert(event["flow_id"], "low_confidence", f"Low confidence or unknown flow: label={event['label']}, confidence={event['confidence']:.2f}", "medium"))
        if event["packet_count"] <= self.config.short_flow_packet_threshold:
            short_count = sum(1 for x in self.recent if x["packet_count"] <= self.config.short_flow_packet_threshold)
            if short_count >= self.config.short_flow_window_threshold:
                new_alerts.append(self._make_alert("window", "high_frequency_short_flows", f"Short flow count in recent window reached {short_count}", "medium"))
        new_alerts.extend(self.evaluate_window())
        for alert in new_alerts:
            if not self.alerts or self.alerts[-1].get("message") != alert.get("message"):
                self.alerts.append(alert)
        return new_alerts

    def evaluate_window(self) -> list[dict[str, Any]]:
        if not self.recent:
            return []
        alerts: list[dict[str, Any]] = []
        total = len(self.recent)
        labels = Counter(x["label"] for x in self.recent)
        ports = Counter(x["dst_port"] for x in self.recent if x["dst_port"])
        unknown_ratio = labels.get("unknown", 0) / total
        if unknown_ratio >= self.config.unknown_ratio_threshold and total >= 20:
            alerts.append(self._make_alert("window", "unknown_ratio_high", f"Unknown flow ratio is {unknown_ratio:.1%} in recent window", "high"))
        label, count = labels.most_common(1)[0]
        if count >= self.config.label_spike_threshold:
            alerts.append(self._make_alert("window", "label_spike", f"Traffic label `{label}` appears {count} times in recent window", "medium"))
        if ports:
            port, count = ports.most_common(1)[0]
            if count >= self.config.hot_port_threshold:
                alerts.append(self._make_alert("window", "port_concentration", f"Port `{port}` appears {count} times in recent window", "medium"))
        return alerts

    def _make_alert(self, flow_id: str, alert_type: str, message: str, severity: str) -> dict[str, Any]:
        return {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "flow_id": flow_id,
            "alert_type": alert_type,
            "message": message,
            "severity": severity,
        }

    def list_alerts(self, limit: int = 100) -> list[dict[str, Any]]:
        return list(self.alerts)[-limit:][::-1]

    def reset(self) -> None:
        self.recent.clear()
        self.alerts.clear()
