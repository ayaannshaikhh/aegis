from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Optional

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Packet

from .entropy import shannon_entropy
from .timing import inter_arrival_times_ms
from .protocol import protocol_ratios

@dataclass
class WindowFeatures:
    start_ts: float
    end_ts: float
    features: Dict[str, float]

def extract_window_features(packets: List[Packet], start_ts: float, end_ts: float) -> WindowFeatures:
    src_ips: List[str] = []
    dst_ports: List[int] = []
    timestamps: List[float] = []
    proto_counts = {"TCP": 0, "UDP": 0, "ICMP": 0}
    total_bytes = 0

    for pkt in packets:
        # scapy sniffed packets typically have .time
        t = float(getattr(pkt, "time", 0.0))
        timestamps.append(t)
        total_bytes += len(pkt)

        if pkt.haslayer(IP):
            src_ips.append(pkt[IP].src)

        if pkt.haslayer(TCP):
            proto_counts["TCP"] += 1
            dst_ports.append(int(pkt[TCP].dport))
        elif pkt.haslayer(UDP):
            proto_counts["UDP"] += 1
            dst_ports.append(int(pkt[UDP].dport))
        elif pkt.haslayer(ICMP):
            proto_counts["ICMP"] += 1

    window_seconds = max(end_ts - start_ts, 1e-6)
    pkt_rate = len(packets) / window_seconds
    byte_rate = total_bytes / window_seconds

    ent_src = shannon_entropy(src_ips)
    ent_dport = shannon_entropy(dst_ports)
    iat_mean, iat_std = inter_arrival_times_ms(sorted(timestamps))

    ratios = protocol_ratios(proto_counts)

    feats = {
        "entropy_src_ip": ent_src,
        "entropy_dst_port": ent_dport,
        "pkt_rate": float(pkt_rate),
        "byte_rate": float(byte_rate),
        "iat_mean_ms": float(iat_mean),
        "iat_std_ms": float(iat_std),
        **ratios,
    }
    return WindowFeatures(start_ts=start_ts, end_ts=end_ts, features=feats)