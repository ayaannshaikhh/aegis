from __future__ import annotations
import math
from collections import Counter
from typing import Iterable, Hashable

def shannon_entropy(values: Iterable[Hashable]) -> float:
    vals = list(values)
    if not vals:
        return 0.0
    counts = Counter(vals)
    n = len(vals)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent