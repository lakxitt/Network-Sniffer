"""
sniffer/packet_capture.py

Core capture engine. Handles interface discovery/selection, running the
live Scapy sniff loop, and dispatching each captured packet to the
parser, statistics tracker, logger, and console display.
"""

import sys
from typing import Callable, Dict, List, Optional

from scapy.all import sniff, get_if_list, conf
from scapy.all import Packet as ScapyPacket
from scapy.error import Scapy_Exception

from sniffer.packet_parser import PacketParser, PacketInfo
from sniffer.statistics import StatisticsTracker
from sniffer.logger import PacketLogger
from config.settings import DEFAULT_STORE_LIMIT


class NetworkSniffer:
    """High-level orchestrator for live packet capture."""

    def __init__(
        self,
        interface: Optional[str] = None,
        on_packet: Optional[Callable[[PacketInfo], None]] = None,
    ) -> None:
        """
        Args:
            interface: Network interface to sniff on (None = default).
            on_packet: Optional callback invoked with each PacketInfo
                (used by the UI layer to render live output).
        """
        self.interface = interface
        self.on_packet = on_packet

        self.parser = PacketParser()
        self.stats = StatisticsTracker()
        self.file_logger = PacketLogger()
        self.captured_packets: List[PacketInfo] = []
        self._store_limit = DEFAULT_STORE_LIMIT

    # ------------------------------------------------------------------
    # Interface Discovery
    # ------------------------------------------------------------------
    @staticmethod
    def list_interfaces() -> List[str]:
        """
        Return a list of available network interfaces on this machine.

        Returns:
            A list of interface name strings.
        """
        try:
            return get_if_list()
        except Exception as exc:
            print(f"[Interface Error] Could not list interfaces: {exc}")
            return []

    @staticmethod
    def list_interfaces_friendly() -> List[Dict[str, str]]:
        """
        Return available interfaces with a human-friendly display label
        alongside the underlying device identifier Scapy needs for
        capture. This avoids showing raw Windows NPF GUIDs such as
        ``\\Device\\NPF_{2DA1298B-...}`` to the user.

        Returns:
            A list of dicts, each ``{"friendly": <display label>,
            "device": <identifier to pass as iface=...>}``.
        """
        results: List[Dict[str, str]] = []

        if sys.platform.startswith("win"):
            try:
                from scapy.arch.windows import get_windows_if_list

                for entry in get_windows_if_list():
                    name = entry.get("name") or ""
                    description = entry.get("description") or ""
                    guid = entry.get("guid") or ""
                    # Scapy resolves the friendly `name` back to the
                    # correct NPF device internally, so we can pass it
                    # straight to sniff(iface=...).
                    device = name or guid
                    if not device:
                        continue
                    results.append(
                        {
                            "friendly": NetworkSniffer._classify(name, description),
                            "device": device,
                        }
                    )
            except Exception as exc:
                print(f"[Interface Error] Could not read Windows interface details: {exc}")

        if not results:
            # Non-Windows (or as a fallback): get_if_list() names are
            # already fairly friendly (eth0, wlan0, lo, docker0, ...),
            # but run them through the same classifier for consistent
            # category labels across platforms.
            for iface in NetworkSniffer.list_interfaces():
                results.append(
                    {
                        "friendly": NetworkSniffer._classify(iface, iface),
                        "device": iface,
                    }
                )

        return results

    @staticmethod
    def _classify(name: str, description: str) -> str:
        """
        Turn a raw interface name/description into a short, recognizable
        label (e.g. 'Wi-Fi', 'Ethernet', 'VirtualBox', 'VMware',
        'Loopback'). Falls back to the original name if nothing matches.
        """
        text = f"{name} {description}".lower()

        if "loopback" in text or name.lower() == "lo":
            return f"Loopback ({name})" if name and name.lower() != "lo" else "Loopback"
        if "vmware" in text:
            return f"VMware ({name})" if name else "VMware"
        if "virtualbox" in text or "vbox" in text:
            return f"VirtualBox ({name})" if name else "VirtualBox"
        if "wi-fi" in text or "wifi" in text or "wireless" in text or "wlan" in text:
            return f"Wi-Fi ({name})" if name else "Wi-Fi"
        if "ethernet" in text or name.lower().startswith("eth"):
            return f"Ethernet ({name})" if name else "Ethernet"
        if "docker" in text:
            return f"Docker ({name})" if name else "Docker"
        if "bluetooth" in text:
            return f"Bluetooth ({name})" if name else "Bluetooth"

        return name or description or "Unknown Interface"

    # ------------------------------------------------------------------
    # Packet Handling
    # ------------------------------------------------------------------
    def _handle_packet(self, raw_packet: ScapyPacket) -> None:
        """
        Internal callback passed to scapy.sniff(). Parses the raw packet,
        updates statistics, logs it to disk, stores it in memory (bounded),
        and forwards it to any external display callback.

        Args:
            raw_packet: The raw packet captured by Scapy.
        """
        try:
            info = self.parser.parse(raw_packet)
            if info is None:
                return

            self.stats.record(info.protocol, info.base_protocol)
            self.file_logger.log_packet(info)

            if len(self.captured_packets) < self._store_limit:
                self.captured_packets.append(info)

            if self.on_packet:
                self.on_packet(info)

        except Exception as exc:
            # Never let a single malformed packet crash the whole sniffer
            print(f"[Packet Handling Error] {exc}")

    # ------------------------------------------------------------------
    # Main Capture Loop
    # ------------------------------------------------------------------
    def start(self) -> None:
        """
        Begin live packet capture. Blocks until interrupted (e.g. Ctrl+C).
        Raises no exception on KeyboardInterrupt; caller should catch it
        for graceful shutdown handling.
        """
        try:
            sniff(
                iface=self.interface,
                prn=self._handle_packet,
                store=False,
            )
        except (OSError, RuntimeError, Scapy_Exception) as exc:
            # Common on Windows machines without Npcap (or without the
            # WinPcap-compatible mode enabled): Layer-2 sniffing is
            # unavailable. Fall back to a Layer-3 socket so the program
            # still works, at the cost of not being able to read MAC
            # addresses or non-IP traffic (e.g. ARP).
            if "layer 2" in str(exc).lower() or "winpcap" in str(exc).lower():
                print(
                    "[Warning] Layer-2 sniffing unavailable (Npcap not installed "
                    "in WinPcap-compatible mode). Falling back to Layer-3 capture "
                    "-- MAC addresses and ARP packets will not be visible.\n"
                    "For full functionality, install Npcap with 'WinPcap API-compatible "
                    "mode' enabled: https://npcap.com/#download"
                )
                conf.L3socket
                sniff(
                    prn=self._handle_packet,
                    store=False,
                )
            else:
                raise

    def generate_final_report(self) -> str:
        """
        Build and persist the final summary report at the end of a
        capture session.

        Returns:
            The formatted report text.
        """
        report_text = self.stats.format_report()
        self.file_logger.write_summary(report_text)
        return report_text
