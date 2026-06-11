#!/usr/bin/env python3
"""Online traffic detection REST API and demo web UI.

The server uses the Python standard library so the prototype can run even when
FastAPI/uvicorn are unavailable. Endpoints intentionally mirror a FastAPI-style
REST design and return JSON.
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import threading
from collections import Counter, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from alert_rules import AlertEngine
from model_service import ModelService
from online_features import session_to_feature_row
from session_manager import SessionManager
from sniffer import CaptureController


class OnlineDetectionSystem:
    def __init__(self, model_path: Path, replay_file: Path) -> None:
        self.session_manager = SessionManager(timeout_seconds=30.0, max_packets=20)
        self.model_service = ModelService(model_path=model_path)
        self.alert_engine = AlertEngine()
        self.recent_predictions: deque[dict] = deque(maxlen=200)
        self.traffic_timeline: deque[dict] = deque(maxlen=120)
        self.lock = threading.RLock()
        self.capture = CaptureController(
            self.session_manager,
            on_session_update=self.handle_session_update,
            replay_file=replay_file,
            replay_speed=0.015,
        )

    def handle_session_update(self, snapshot: dict, session_obj: object) -> None:
        features = session_to_feature_row(snapshot)
        prediction = self.model_service.predict_one(features)
        snapshot["predicted_label"] = prediction["predicted_label"]
        snapshot["confidence"] = prediction["confidence"]
        if hasattr(session_obj, "predicted_label"):
            session_obj.predicted_label = prediction["predicted_label"]
            session_obj.confidence = prediction["confidence"]
        record = {
            "time": snapshot["last_time"],
            "flow_id": snapshot["flow_id"],
            "src": f"{snapshot['src_ip']}:{snapshot['src_port']}",
            "dst": f"{snapshot['dst_ip']}:{snapshot['dst_port']}",
            "protocol": snapshot["protocol"],
            "packet_count": snapshot["packet_count"],
            "byte_count": snapshot["byte_count"],
            "predicted_label": prediction["predicted_label"],
            "confidence": prediction["confidence"],
            "model": prediction.get("model", ""),
        }
        with self.lock:
            self.recent_predictions.append(record)
            self.traffic_timeline.append({"time": snapshot["last_time"], "packets": 1, "bytes": snapshot["byte_count"]})
            self.alert_engine.observe_prediction(prediction, snapshot)

    def health(self) -> dict:
        return {
            "status": "ok",
            "capture": self.capture.status(),
            "model_ready": self.model_service.ready,
            "model_error": self.model_service.error,
            "active_flows": len(self.session_manager.active_snapshots(limit=10_000)),
        }

    def start_capture(self, payload: dict) -> dict:
        mode = payload.get("mode", "replay")
        interface = payload.get("interface", "")
        return self.capture.start(interface=interface, mode=mode)

    def stop_capture(self) -> dict:
        return self.capture.stop()

    def live_flows(self) -> list[dict]:
        return self.session_manager.active_snapshots(limit=200)

    def recent(self) -> list[dict]:
        with self.lock:
            return list(self.recent_predictions)[::-1]

    def alerts(self) -> list[dict]:
        return self.alert_engine.list_alerts()

    def traffic_composition(self) -> dict:
        with self.lock:
            counts = Counter(r["predicted_label"] for r in self.recent_predictions)
        total = sum(counts.values()) or 1
        return {"total": total, "items": [{"label": k, "count": v, "ratio": v / total} for k, v in counts.most_common()]}

    def environment_summary(self) -> dict:
        flows = self.session_manager.active_snapshots(limit=10_000)
        protocol = Counter(f["protocol"] for f in flows)
        ports = Counter(str(f["dst_port"]) for f in flows)
        labels = Counter(f["predicted_label"] for f in flows)
        with self.lock:
            timeline = list(self.traffic_timeline)
        return {
            "active_flow_count": len(flows),
            "protocol_distribution": dict(protocol),
            "top_ports": [{"port": k, "count": v} for k, v in ports.most_common(10)],
            "label_distribution": dict(labels),
            "timeline": timeline[-60:],
        }


def make_handler(system: OnlineDetectionSystem, root: Path):
    class Handler(BaseHTTPRequestHandler):
        server_version = "Subexp3OnlineDetector/1.0"

        def _send_json(self, data, status: int = 200) -> None:
            raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _read_json(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0:
                return {}
            try:
                return json.loads(self.rfile.read(length).decode("utf-8"))
            except json.JSONDecodeError:
                return {}

        def do_GET(self) -> None:
            path = urlparse(self.path).path
            if path == "/":
                return self._send_file(root / "templates" / "index.html")
            if path.startswith("/static/"):
                return self._send_file(root / path.lstrip("/"))
            if path == "/health":
                return self._send_json(system.health())
            if path == "/live_flows":
                return self._send_json(system.live_flows())
            if path == "/stats/traffic_composition":
                return self._send_json(system.traffic_composition())
            if path == "/stats/environment_summary":
                return self._send_json(system.environment_summary())
            if path == "/alerts":
                return self._send_json(system.alerts())
            if path == "/recent_predictions":
                return self._send_json(system.recent())
            return self._send_json({"error": "not found"}, 404)

        def do_POST(self) -> None:
            path = urlparse(self.path).path
            payload = self._read_json()
            if path == "/start_capture":
                return self._send_json(system.start_capture(payload))
            if path == "/stop_capture":
                return self._send_json(system.stop_capture())
            return self._send_json({"error": "not found"}, 404)

        def _send_file(self, path: Path) -> None:
            if not path.exists() or not path.is_file():
                return self._send_json({"error": "not found"}, 404)
            content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
            raw = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, fmt: str, *args) -> None:
            print(f"{self.address_string()} - {fmt % args}")

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description="Run online traffic detection demo server.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8008)
    parser.add_argument("--model", type=Path, default=Path("../subexp2/outputs/models/random_forest.pkl"))
    parser.add_argument("--replay-file", type=Path, default=Path("../subexp2/outputs/parsed_flows.jsonl"))
    args = parser.parse_args()

    root = Path(__file__).resolve().parent
    system = OnlineDetectionSystem(args.model.resolve(), args.replay_file.resolve())
    server = ThreadingHTTPServer((args.host, args.port), make_handler(system, root))
    print(f"Online detector running at http://{args.host}:{args.port}")
    print("Use POST /start_capture with {'mode':'replay'} for demo, or {'mode':'live','interface':'...'} when scapy is installed.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        system.stop_capture()
        server.server_close()


if __name__ == "__main__":
    main()
