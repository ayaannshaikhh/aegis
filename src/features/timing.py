from __future__ import annotations
from typing import List, Tuple
import numpy as np

def inter_arrival_times_ms(timestamps: List[float]) -> Tuple[float, float]:
    """
    timestamps: list of packet times (seconds, monotonic-ish)
    returns: mean_ms, std_ms
    """
    if len(timestamps) < 2:
        return 0.0, 0.0
    diffs = np.diff(np.array(timestamps)) * 1000.0
    return float(np.mean(diffs)), float(np.std(diffs))
