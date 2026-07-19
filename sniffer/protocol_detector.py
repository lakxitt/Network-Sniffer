"""
sniffer/protocol_detector.py

Responsible for translating raw protocol numbers and port numbers into
human-readable protocol names (TCP, UDP, ICMP, ARP, DNS, HTTP, HTTPS, etc.).
"""

from typing import Optional

from config.settings import IP_PROTOCOL_MAP, PORT_PROTOCOL_MAP


class ProtocolDetector:
    """Utility class that resolves protocol names from packet metadata."""

    @staticmethod
    def get_ip_protocol_name(proto_number: int) -> str:
        """
        Convert an IP protocol number into a human-readable name.

        Args:
            proto_number: The numeric IP protocol identifier (e.g. 6 for TCP).

        Returns:
            The protocol name as a string, or "OTHER" if unknown.
        """
        return IP_PROTOCOL_MAP.get(proto_number, "OTHER")

    @staticmethod
    def get_application_protocol(
        src_port: Optional[int], dst_port: Optional[int]
    ) -> Optional[str]:
        """
        Attempt to identify the application-layer protocol (HTTP, HTTPS,
        DNS, SSH, etc.) based on well-known source/destination ports.

        Args:
            src_port: Source port number, if available.
            dst_port: Destination port number, if available.

        Returns:
            The detected application-layer protocol name, or None if it
            cannot be determined from the port numbers.
        """
        if dst_port in PORT_PROTOCOL_MAP:
            return PORT_PROTOCOL_MAP[dst_port]
        if src_port in PORT_PROTOCOL_MAP:
            return PORT_PROTOCOL_MAP[src_port]
        return None

    @staticmethod
    def resolve_display_protocol(
        base_protocol: str,
        src_port: Optional[int],
        dst_port: Optional[int],
    ) -> str:
        """
        Determine the best protocol name to display to the user, preferring
        a recognized application-layer protocol (e.g. HTTP/HTTPS/DNS) over
        the generic transport-layer protocol (TCP/UDP) when possible.

        Args:
            base_protocol: The transport/network layer protocol (TCP, UDP, ICMP, ARP...).
            src_port: Source port, if any.
            dst_port: Destination port, if any.

        Returns:
            The most descriptive protocol name available.
        """
        if base_protocol in ("TCP", "UDP"):
            app_protocol = ProtocolDetector.get_application_protocol(src_port, dst_port)
            if app_protocol:
                return app_protocol
        return base_protocol
