from __future__ import annotations
from typing import Dict

def protocol_ratios(proto_counts: Dict[str, int]) -> Dict[str, float]:
    total = sum(proto_counts.values())
    if total == 0:
        return {"tcp_ratio": 0.0, "udp_ratio": 0.0, "icmp_ratio": 0.0}
    return {
        "tcp_ratio": proto_counts.get("TCP", 0) / total,
        "udp_ratio": proto_counts.get("UDP", 0) / total,
        "icmp_ratio": proto_counts.get("ICMP", 0) / total,
    }