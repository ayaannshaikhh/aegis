from __future__ import annotations
from pathlib import Path
import time
import yaml

from src.capture.live_capture import sniff_live
from src.features.feature_vector import extract_window_features
from src.baseline.persistence import load_json
from src.detection.anomaly_score import final_score
from src.detection.isolation_forest import load_if_model
from src.alerts.console import emit_alert

ROOT = Path(__file__).resolve().parents[1]

def main() -> None:
    cfg = yaml.safe_load((ROOT / "config/default.yaml").read_text())
    window = int(cfg["window_seconds"])
    iface = cfg["capture"].get("interface")
    stats_w = float(cfg["scoring"]["stats_weight"])
    ml_w = float(cfg["ml"]["weight"]) if cfg.get("ml", {}).get("enabled", False) else 0.0

    baseline = load_json(ROOT / "data/baselines/baseline.json")
    if_model = None
    if cfg.get("ml", {}).get("enabled", False):
        p = ROOT / "data/baselines/isolation_forest.pkl"
        if p.exists():
            if_model = load_if_model(p)

    buf = []
    win_start = None

    def on_packet(pkt):
        nonlocal buf, win_start
        t = float(getattr(pkt, "time", time.time()))
        if win_start is None:
            win_start = t
        buf.append(pkt)
        if t - win_start >= window:
            wf = extract_window_features(buf, win_start, win_start + window)
            s = final_score(wf.features, baseline, if_model, stats_w, ml_w)
            if s["final"] > 3.0:
                emit_alert({
                    "start_ts": wf.start_ts,
                    "end_ts": wf.end_ts,
                    "score": s["final"],
                    "stat": s["stat"],
                    "ml": s["ml"],
                    "reasons": {"note": "live heuristic threshold", "threshold": 3.0},
                })
            buf = []
            win_start = t

    print(f"Sniffing on interface={iface} window={window}s (Ctrl+C to stop)")
    sniff_live(iface, on_packet)

if __name__ == "__main__":
    main()
