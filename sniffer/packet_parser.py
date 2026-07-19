"""
sniffer/packet_parser.py

Extracts structured, human-readable information from a raw Scapy packet
object and returns it as a dictionary (PacketInfo) that the rest of the
application (statistics, logger, UI) can consume without needing to know
anything about Scapy internals.
"""

import string
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional, Dict, Any

from scapy.all import Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether

from config.settings import DEFAULT_PAYLOAD_DISPLAY_LIMIT
from sniffer.protocol_detector import ProtocolDetector


@dataclass
class PacketInfo:
    """Structured representation of a single captured packet."""

    packet_id: int
    timestamp: str
    protocol: str
    base_protocol: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None
    length: int = 0
    payload_size: int = 0
    payload_preview: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Return the packet information as a plain dictionary."""
        return asdict(self)


class PacketParser:
    """Parses raw Scapy packets into structured PacketInfo objects."""

    def __init__(self, payload_limit: int = DEFAULT_PAYLOAD_DISPLAY_LIMIT) -> None:
        """
        Args:
            payload_limit: Maximum number of printable payload characters
                to keep in the preview.
        """
        self.payload_limit = payload_limit
        self._counter = 0

    def _extract_printable_payload(self, raw_bytes: bytes) -> str:
        """
        Extract only printable ASCII characters from raw payload bytes,
        truncated to the configured display limit.

        Args:
            raw_bytes: The raw payload bytes from the packet.

        Returns:
            A printable string preview of the payload (may be empty).
        """
        if not raw_bytes:
            return ""
        try:
            decoded = raw_bytes.decode("utf-8", errors="ignore")
        except Exception:
            decoded = ""
        printable = "".join(ch for ch in decoded if ch in string.printable and ch not in "\r\n\t")
        return printable[: self.payload_limit]

    def parse(self, packet: Packet) -> Optional[PacketInfo]:
        """
        Convert a raw Scapy packet into a PacketInfo dataclass instance.

        Args:
            packet: The raw packet captured by Scapy.

        Returns:
            A populated PacketInfo object, or None if the packet type
            is not supported / could not be parsed.
        """
        self._counter += 1
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # --- MAC Addresses (Layer 2) ---
        src_mac = packet[Ether].src if packet.haslayer(Ether) else None
        dst_mac = packet[Ether].dst if packet.haslayer(Ether) else None

        # --- ARP Packets ---
        if packet.haslayer(ARP):
            arp_layer = packet[ARP]
            info = PacketInfo(
                packet_id=self._counter,
                timestamp=timestamp,
                protocol="ARP",
                base_protocol="ARP",
                src_ip=arp_layer.psrc,
                dst_ip=arp_layer.pdst,
                src_mac=src_mac,
                dst_mac=dst_mac,
                length=len(packet),
                payload_size=0,
                payload_preview="",
            )
            return info

        # --- IP-based Packets (TCP / UDP / ICMP) ---
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            base_protocol = ProtocolDetector.get_ip_protocol_name(ip_layer.proto)

            src_port: Optional[int] = None
            dst_port: Optional[int] = None
            tcp_flags: Optional[str] = None
            raw_payload = b""

            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                src_port = int(tcp_layer.sport)
                dst_port = int(tcp_layer.dport)
                tcp_flags = str(tcp_layer.flags)
                raw_payload = bytes(tcp_layer.payload)
                base_protocol = "TCP"
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)
                raw_payload = bytes(udp_layer.payload)
                base_protocol = "UDP"
            elif packet.haslayer(ICMP):
                raw_payload = bytes(packet[ICMP].payload)
                base_protocol = "ICMP"

            display_protocol = ProtocolDetector.resolve_display_protocol(
                base_protocol, src_port, dst_port
            )
            payload_preview = self._extract_printable_payload(raw_payload)

            info = PacketInfo(
                packet_id=self._counter,
                timestamp=timestamp,
                protocol=display_protocol,
                base_protocol=base_protocol,
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                src_mac=src_mac,
                dst_mac=dst_mac,
                src_port=src_port,
                dst_port=dst_port,
                tcp_flags=tcp_flags,
                length=len(packet),
                payload_size=len(raw_payload),
                payload_preview=payload_preview,
            )
            return info

        # --- Unsupported / Unknown packet types are skipped ---
        return None
