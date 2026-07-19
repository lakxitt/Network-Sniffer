#!/usr/bin/env python3
"""
main.py

Entry point for the Basic Network Sniffer project.

This script provides an interactive command-line interface that:
    1. Displays a banner and auto-detects the default network interface
       (no manual index selection required).
    2. Starts live packet capture immediately, printing a colorized
       live stream of packets using the `rich` library.
    3. On Ctrl+C, gracefully stops, prints a summary report, and
       saves logs.

Run with:
    python main.py
(On Linux/Kali, packet sniffing typically requires root/sudo privileges.)
"""

import sys
import time
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from scapy.all import conf

from sniffer.packet_capture import NetworkSniffer
from sniffer.packet_parser import PacketInfo
from config.settings import PROTOCOL_COLORS

console = Console()

BANNER = r"""
 ____            _        _   _      _                      _  __  __
|  _ \  __ _  ___| | _____| |_| |    | |_ _ __ __ _ ___  ___| |/ _|/ _| ___ _ __
| |_) |/ _` |/ __| |/ / _ \ __| |    | __| '__/ _` / __|/ __| | |_| |_ / _ \ '__|
|  __/| (_| | (__|   <  __/ |_| |___ | |_| | | (_| \__ \ (__| |  _|  _|  __/ |
|_|    \__,_|\___|_|\_\___|\__|______\__|_|  \__,_|___/\___|_|_| |_|  \___|_|

              B A S I C   N E T W O R K   S N I F F E R  (Python + Scapy)
"""


def print_banner() -> None:
    """Display the ASCII art banner and project title."""
    console.print(Text(BANNER, style="bold green"))
    console.print(
        Panel.fit(
            "Educational Cybersecurity Project — Live Packet Capture & Analysis",
            style="bold cyan",
        )
    )


def detect_default_interface() -> Optional[str]:
    """
    Automatically detect the network interface Scapy will use by default
    (its active/default route interface) and display it to the user.
    No manual index selection is required — capture starts on this
    interface automatically.

    Returns:
        None, so NetworkSniffer falls back to Scapy's own default
        interface resolution at sniff() time. The detected name is only
        used here for informational display.
    """
    try:
        default_iface = conf.iface
    except Exception:
        default_iface = None

    if default_iface:
        friendly_default = NetworkSniffer._classify(str(default_iface), str(default_iface))
        console.print(
            f"[bold cyan]Auto-detected default interface:[/bold cyan] "
            f"[bold white]{friendly_default}[/bold white]"
        )
    else:
        console.print(
            "[bold yellow]Could not auto-detect a named interface; "
            "Scapy will use its own default.[/bold yellow]"
        )

    # Still show the full list of available interfaces for reference only,
    # using friendly display names (e.g. "Wi-Fi", "Ethernet", "VirtualBox")
    # instead of raw device identifiers like \Device\NPF_{GUID}.
    interfaces = NetworkSniffer.list_interfaces_friendly()
    if interfaces:
        table = Table(title="Available Network Interfaces (informational only)")
        table.add_column("Interface", style="bold white")
        table.add_column("Device ID", style="dim")
        for entry in interfaces:
            table.add_row(entry["friendly"], entry["device"])
        console.print(table)

    return None


def render_packet(info: PacketInfo) -> None:
    """
    Print a single captured packet as a colorized console line.

    Args:
        info: The parsed packet information to display.
    """
    color = PROTOCOL_COLORS.get(info.protocol, PROTOCOL_COLORS.get(info.base_protocol, "white"))

    line = Text()
    line.append(f"[#{info.packet_id:05d}] ", style="bold white")
    line.append(f"{info.timestamp}  ", style="dim")
    line.append(f"{info.protocol:<8}", style=f"bold {color}")

    if info.src_ip:
        line.append(f" {info.src_ip}", style="white")
        if info.src_port:
            line.append(f":{info.src_port}", style="dim")
        line.append(" -> ", style="bold white")
        line.append(f"{info.dst_ip}", style="white")
        if info.dst_port:
            line.append(f":{info.dst_port}", style="dim")

    line.append(f"  len={info.length}", style="dim")

    if info.tcp_flags:
        line.append(f"  flags={info.tcp_flags}", style="yellow")

    if info.payload_preview:
        line.append(f"\n           payload: {info.payload_preview}", style="italic dim")

    console.print(line)


def print_final_summary(sniffer: NetworkSniffer) -> None:
    """
    Print and persist the final capture summary when the user stops
    the program.

    Args:
        sniffer: The NetworkSniffer instance holding session statistics.
    """
    report_text = sniffer.generate_final_report()
    console.print("\n")
    console.print(Panel(report_text, title="Session Summary", style="bold green"))
    console.print(f"[bold cyan]Packet log saved to:[/bold cyan] logs/packets.log")
    console.print(f"[bold cyan]Summary saved to:[/bold cyan] logs/summary.txt")


def main() -> None:
    """Main program entry point."""
    print_banner()

    interface = detect_default_interface()

    console.print(
        "\n[bold green]Starting live capture... Press CTRL+C to stop.[/bold green]\n"
    )
    time.sleep(1)

    sniffer = NetworkSniffer(
        interface=interface,
        on_packet=render_packet,
    )

    try:
        sniffer.start()
    except KeyboardInterrupt:
        console.print("\n\n[bold yellow]Capture stopped by user (CTRL+C).[/bold yellow]")
    except PermissionError:
        console.print(
            "\n[bold red]Permission denied. Try running with sudo/administrator privileges.[/bold red]"
        )
        sys.exit(1)
    except Exception as exc:
        console.print(f"\n[bold red]Unexpected error during capture: {exc}[/bold red]")
    finally:
        print_final_summary(sniffer)
        console.print("\n[bold green]Thank you for using Basic Network Sniffer![/bold green]")


if __name__ == "__main__":
    main()
