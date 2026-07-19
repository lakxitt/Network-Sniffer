"""
sniffer/statistics.py

Tracks packet counts, per-protocol statistics, and capture duration
for the running sniffer session.
"""

import time
from collections import Counter
from typing import Dict


class StatisticsTracker:
    """Maintains running statistics for the current capture session."""

    def __init__(self) -> None:
        self.total_packets: int = 0
        self.protocol_counter: Counter = Counter()
        self._start_time: float = time.time()

    def record(self, protocol: str, base_protocol: str) -> None:
        """
        Update statistics with a newly captured packet.

        Args:
            protocol: The display protocol name (e.g. "HTTP").
            base_protocol: The underlying transport protocol (e.g. "TCP").
        """
        self.total_packets += 1
        # Track both granular (HTTP/DNS) and base (TCP/UDP/ICMP/ARP) counts
        self.protocol_counter[base_protocol] += 1
        if protocol != base_protocol:
            self.protocol_counter[protocol] += 1

    def get_elapsed_time(self) -> float:
        """Return the number of seconds elapsed since capture started."""
        return round(time.time() - self._start_time, 2)

    def get_summary(self) -> Dict[str, int]:
        """Return a dictionary summary of protocol counts."""
        return dict(self.protocol_counter)

    def format_report(self) -> str:
        """
        Build a human-readable text report of the current statistics.

        Returns:
            A formatted multi-line string summarizing the session.
        """
        lines = [
            "=" * 50,
            "PACKET CAPTURE SUMMARY REPORT",
            "=" * 50,
            f"Total Packets Captured : {self.total_packets}",
            f"Execution Time (sec)   : {self.get_elapsed_time()}",
            "-" * 50,
            "Protocol Breakdown:",
        ]
        base_protocols = ["TCP", "UDP", "ICMP", "ARP"]
        for proto in base_protocols:
            lines.append(f"  {proto:<10}: {self.protocol_counter.get(proto, 0)}")

        other_count = self.total_packets - sum(
            self.protocol_counter.get(p, 0) for p in base_protocols
        )
        lines.append(f"  {'OTHERS':<10}: {max(other_count, 0)}")
        lines.append("-" * 50)
        lines.append("Application-Layer Detections:")
        app_protocols = ["DNS", "HTTP", "HTTPS", "SSH", "FTP", "TELNET", "SMTP"]
        for proto in app_protocols:
            count = self.protocol_counter.get(proto, 0)
            if count:
                lines.append(f"  {proto:<10}: {count}")
        lines.append("=" * 50)
        return "\n".join(lines)
