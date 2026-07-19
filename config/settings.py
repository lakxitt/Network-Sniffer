"""
config/settings.py

Central configuration file for the Basic Network Sniffer project.
Modify these values to change default behavior without touching
the core application logic.
"""

import os

# ---------------------------------------------------------------------------
# Directory / File Paths
# ---------------------------------------------------------------------------
BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR: str = os.path.join(BASE_DIR, "logs")
PACKET_LOG_FILE: str = os.path.join(LOGS_DIR, "packets.log")
SUMMARY_FILE: str = os.path.join(LOGS_DIR, "summary.txt")
CSV_EXPORT_FILE: str = os.path.join(LOGS_DIR, "packets_export.csv")
JSON_EXPORT_FILE: str = os.path.join(LOGS_DIR, "packets_export.json")

# ---------------------------------------------------------------------------
# Capture Settings
# ---------------------------------------------------------------------------
DEFAULT_PAYLOAD_DISPLAY_LIMIT: int = 100   # Max characters of payload to show
DEFAULT_STORE_LIMIT: int = 5000            # Max packets kept in memory for search/export

# ---------------------------------------------------------------------------
# Protocol Number -> Name Mapping (IP protocol field)
# ---------------------------------------------------------------------------
IP_PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    2: "IGMP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    89: "OSPF",
}

# ---------------------------------------------------------------------------
# Well-Known Ports -> Application Layer Protocol Mapping
# ---------------------------------------------------------------------------
PORT_PROTOCOL_MAP = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-ALT",
}

# ---------------------------------------------------------------------------
# Colors for each protocol (used with Rich/Colorama)
# ---------------------------------------------------------------------------
PROTOCOL_COLORS = {
    "TCP": "cyan",
    "UDP": "yellow",
    "ICMP": "magenta",
    "ARP": "green",
    "DNS": "blue",
    "HTTP": "bright_red",
    "HTTPS": "bright_green",
    "OTHER": "white",
}

# Ensure logs directory exists at import time
os.makedirs(LOGS_DIR, exist_ok=True)
