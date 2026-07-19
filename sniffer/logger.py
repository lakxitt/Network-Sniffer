"""
sniffer/logger.py

Handles persistent logging of captured packets to disk, including
plain-text logs, a final summary report, and CSV/JSON export for
further analysis (bonus features).
"""

import csv
import json
import logging
from typing import List

from config.settings import (
    PACKET_LOG_FILE,
    SUMMARY_FILE,
    CSV_EXPORT_FILE,
    JSON_EXPORT_FILE,
)
from sniffer.packet_parser import PacketInfo


def build_file_logger(name: str = "sniffer") -> logging.Logger:
    """
    Create and configure a standard Python logger that writes captured
    packet information to logs/packets.log.

    Args:
        name: Logger name.

    Returns:
        A configured logging.Logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    # Avoid adding duplicate handlers if called multiple times
    if not logger.handlers:
        file_handler = logging.FileHandler(PACKET_LOG_FILE, encoding="utf-8")
        formatter = logging.Formatter("%(asctime)s | %(message)s", "%Y-%m-%d %H:%M:%S")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


class PacketLogger:
    """Wraps file logging and export utilities for captured packets."""

    def __init__(self) -> None:
        self.logger = build_file_logger()

    def log_packet(self, info: PacketInfo) -> None:
        """
        Write a single packet's information to the packet log file.

        Args:
            info: The parsed packet information to log.
        """
        message = (
            f"#{info.packet_id} | {info.protocol} | "
            f"{info.src_ip}:{info.src_port} -> {info.dst_ip}:{info.dst_port} | "
            f"Len={info.length} | PayloadSize={info.payload_size}"
        )
        try:
            self.logger.info(message)
        except Exception as exc:
            print(f"[Logger Error] Failed to write packet log: {exc}")

    def write_summary(self, report_text: str) -> None:
        """
        Write the final capture summary report to logs/summary.txt.

        Args:
            report_text: The formatted summary text to save.
        """
        try:
            with open(SUMMARY_FILE, "w", encoding="utf-8") as f:
                f.write(report_text)
        except Exception as exc:
            print(f"[Logger Error] Failed to write summary file: {exc}")

    def export_csv(self, packets: List[PacketInfo]) -> None:
        """
        Export all captured packets to a CSV file for offline analysis.

        Args:
            packets: List of PacketInfo objects captured this session.
        """
        if not packets:
            return
        try:
            fieldnames = list(packets[0].to_dict().keys())
            with open(CSV_EXPORT_FILE, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for pkt in packets:
                    writer.writerow(pkt.to_dict())
        except Exception as exc:
            print(f"[Logger Error] Failed to export CSV: {exc}")

    def export_json(self, packets: List[PacketInfo]) -> None:
        """
        Export all captured packets to a JSON file for offline analysis.

        Args:
            packets: List of PacketInfo objects captured this session.
        """
        if not packets:
            return
        try:
            data = [pkt.to_dict() for pkt in packets]
            with open(JSON_EXPORT_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as exc:
            print(f"[Logger Error] Failed to export JSON: {exc}")
