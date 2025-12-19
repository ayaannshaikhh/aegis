from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, List
from collections import defaultdict

from src.baseline.statistics import compute_feature_stats
from src.baseline.persistence import save_json
from src.detection.isolation_forest import train_isolation_forest, save_if_model

def train_baseline(
    feature_rows: List[Dict[str, float]],
    out_dir: Path,
    ml_enabled: bool,
    contamination: float,
) -> Dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)

    cols = defaultdict(list)
    for r in feature_rows:
        for k, v in r.items():
            cols[k].append(float(v))

    feature_stats = {}
    for feat, vals in cols.items():
        st = compute_feature_stats(vals)
        feature_stats[feat] = {"mean": st.mean, "std": st.std, "p95": st.p95, "p99": st.p99}

    baseline = {"feature_stats": feature_stats}
    save_json(out_dir / "baseline.json", baseline)

    if ml_enabled:
        feature_order = sorted(feature_stats.keys())
        ifm = train_isolation_forest(feature_rows, feature_order, contamination=contamination)
        save_if_model(out_dir / "isolation_forest.pkl", ifm)

    return baseline
