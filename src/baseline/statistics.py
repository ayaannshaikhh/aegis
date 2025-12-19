from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List
import numpy as np

@dataclass
class FeatureStats:
    mean: float
    std: float
    p95: float
    p99: float

def compute_feature_stats(values: List[float]) -> FeatureStats:
    arr = np.array(values, dtype=float)
    if arr.size == 0:
        return FeatureStats(mean=0.0, std=1.0, p95=0.0, p99=0.0)
    mean = float(np.mean(arr))
    std = float(np.std(arr)) if float(np.std(arr)) > 1e-9 else 1.0
    return FeatureStats(
        mean=mean,
        std=std,
        p95=float(np.percentile(arr, 95)),
        p99=float(np.percentile(arr, 99)),
    )

def z_score(x: float, mean: float, std: float) -> float:
    return (x - mean) / (std if std > 1e-9 else 1.0)
