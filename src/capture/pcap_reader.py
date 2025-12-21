from __future__ import annotations
from pathlib import Path
from typing import List
from scapy.all import rdpcap
from scapy.packet import Packet
from scapy.utils import PcapReader

def read_pcap(path):
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            yield pkt
