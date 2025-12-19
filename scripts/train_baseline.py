from __future__ import annotations
from pathlib import Path
import yaml

from src.capture.pcap_reader import read_pcap
from src.features.feature_vector import extract_window_features
from src.baseline.trainer import train_baseline

ROOT = Path(__file__).resolve().parents[1]

def main() -> None:
    cfg = yaml.safe_load((ROOT / "config/default.yaml").read_text())
    window = int(cfg["window_seconds"])
    ml_cfg = cfg.get("ml", {})
    ml_enabled = bool(ml_cfg.get("enabled", True))
    contamination = float(ml_cfg.get("contamination", 0.01))

    raw_dir = ROOT / "data/raw"
    out_dir = ROOT / "data/baselines"

    rows = []
    for pcap in sorted(raw_dir.glob("*.pcap*")):
        packets = read_pcap(pcap)
        if not packets:
            continue
        start = float(packets[0].time)
        cur_start = start
        cur = []
        for pkt in packets:
            t = float(pkt.time)
            if t - cur_start < window:
                cur.append(pkt)
            else:
                wf = extract_window_features(cur, cur_start, cur_start + window)
                rows.append(wf.features)
                cur_start = t
                cur = [pkt]
        if cur:
            wf = extract_window_features(cur, cur_start, cur_start + window)
            rows.append(wf.features)

    train_baseline(rows, out_dir, ml_enabled=ml_enabled, contamination=contamination)
    print(f"Trained baseline on {len(rows)} windows. Saved to {out_dir}")

if __name__ == "__main__":
    main()
