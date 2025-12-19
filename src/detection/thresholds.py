from __future__ import annotations
from typing import List
import numpy as np

def compute_threshold(scores: List[float], percentile: float) -> float:
    if not scores:
        return 0.0
    return float(np.percentile(np.array(scores, dtype=float), percentile))