from __future__ import annotations
from typing import Dict, Any, Optional
import math

from src.baseline.statistics import z_score
from src.detection.isolation_forest import IFModel, score_isolation_forest

def statistical_deviation_score(row: Dict[str, float], baseline: Dict[str, Any]) -> float:
    """
    baseline format:
      baseline["feature_stats"][feature] = {"mean":..., "std":..., ...}
    returns a single scalar score (higher = more anomalous)
    """
    stats = baseline["feature_stats"]
    zs = []
    for feat, x in row.items():
        if feat not in stats:
            continue
        mean = stats[feat]["mean"]
        std = stats[feat]["std"]
        z = abs(z_score(float(x), float(mean), float(std)))
        zs.append(z)
    # combine: RMS of z-scores
    if not zs:
        return 0.0
    return math.sqrt(sum(z*z for z in zs) / len(zs))

def final_score(
    row: Dict[str, float],
    baseline: Dict[str, Any],
    if_model: Optional[IFModel],
    stats_weight: float,
    ml_weight: float,
) -> Dict[str, float]:
    s_stat = statistical_deviation_score(row, baseline)
    s_ml = score_isolation_forest(if_model, row) if if_model is not None else 0.0
    score = stats_weight * s_stat + ml_weight * s_ml
    return {"final": float(score), "stat": float(s_stat), "ml": float(s_ml)}