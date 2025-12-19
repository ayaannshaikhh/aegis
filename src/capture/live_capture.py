from __future__ import annotations
from typing import Callable, Optional
from scapy.all import sniff
from scapy.packet import Packet

def sniff_live(interface: Optional[str], on_packet: Callable[[Packet], None]) -> None:
    sniff(iface=interface, prn=on_packet, store=False)