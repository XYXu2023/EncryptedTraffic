#!/usr/bin/env python3
"""Run the complete sub-experiment 2 pipeline."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def run(cmd: list[str], cwd: Path) -> None:
    print(" ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=str(cwd), check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run full encrypted traffic classification experiment.")
    parser.add_argument("--input-root", type=Path, default=Path(".."))
    parser.add_argument("--output-dir", type=Path, default=Path("outputs"))
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    py = sys.executable
    out = args.output_dir
    run([py, "parse_flows.py", "--input-root", str(args.input_root), "--output-dir", str(out)], here)
    run([py, "extract_features.py", "--input", str(out / "parsed_flows.jsonl"), "--output-dir", str(out)], here)
    run([py, "split_dataset.py", "--input", str(out / "flow_features.csv"), "--output-dir", str(out)], here)
    run([py, "train_classifier.py", "--train", str(out / "train.csv"), "--val", str(out / "val.csv"), "--output-dir", str(out)], here)
    run([py, "evaluate_model.py", "--test", str(out / "test.csv"), "--model-dir", str(out / "models"), "--output-dir", str(out)], here)
    run([py, "run_ablation.py", "--train", str(out / "train.csv"), "--test", str(out / "test.csv"), "--output-dir", str(out)], here)
    run([py, "run_cross_env.py", "--features", str(out / "flow_features.csv"), "--train", str(out / "train.csv"), "--test", str(out / "test.csv"), "--output-dir", str(out)], here)


if __name__ == "__main__":
    main()
