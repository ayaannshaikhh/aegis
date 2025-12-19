from __future__ import annotations
from pathlib import Path
from typing import List
from scapy.all import rdpcap
from scapy.packet import Packet

def read_pcap(path: Path) -> List[Packet]:
    return list(rdpcap(str(path)))