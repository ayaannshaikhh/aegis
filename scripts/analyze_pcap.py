from __future__ import annotations
from pathlib import Path
import argparse
import yaml

from src.capture.pcap_reader import read_pcap
from src.features.feature_vector import extract_window_features
from src.baseline.persistence import load_json
from src.detection.anomaly_score import final_score
from src.detection.thresholds import compute_threshold
from src.detection.isolation_forest import load_if_model
from src.alerts.console import emit_alert

ROOT = Path(__file__).resolve().parents[1]

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    args = ap.parse_args()

    cfg = yaml.safe_load((ROOT / "config/default.yaml").read_text())
    thr_cfg = yaml.safe_load((ROOT / "config/thresholds.yaml").read_text())

    window = int(cfg["window_seconds"])
    stats_w = float(cfg["scoring"]["stats_weight"])
    ml_w = float(cfg["ml"]["weight"]) if cfg.get("ml", {}).get("enabled", False) else 0.0

    baseline = load_json(ROOT / "data/baselines/baseline.json")
    if_model = None
    if cfg.get("ml", {}).get("enabled", False):
        p = ROOT / "data/baselines/isolation_forest.pkl"
        if p.exists():
            if_model = load_if_model(p)

    scores = []
    windows = []

    packets = read_pcap(Path(args.pcap))
    packets_iter = iter(packets)
    try:
        first_pkt = next(packets_iter)
    except StopIteration:
        print("No packets found in PCAP!")
        return

    cur_start = float(first_pkt.time)
    cur = [first_pkt]

    for pkt in packets_iter:
        t = float(pkt.time)
        if t - cur_start < window:
            cur.append(pkt)
        else:
            wf = extract_window_features(cur, cur_start, cur_start + window)
            s = final_score(wf.features, baseline, if_model, stats_w, ml_w)
            scores.append(s["final"])
            windows.append((wf, s))


    threshold = compute_threshold(scores, float(thr_cfg["alert_percentile"]))

    for wf, s in windows:
        if s["final"] > threshold:
            emit_alert({
                "start_ts": wf.start_ts,
                "end_ts": wf.end_ts,
                "score": s["final"],
                "stat": s["stat"],
                "ml": s["ml"],
                "reasons": {"note": "threshold exceeded", "threshold": threshold},
            })

    print(f"Done. threshold={threshold:.3f} windows={len(windows)}")

if __name__ == "__main__":
    main()
