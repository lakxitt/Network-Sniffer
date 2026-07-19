# 🛡️ Basic Network Sniffer

A professional, beginner-friendly **Python network packet sniffer** built with [Scapy](https://scapy.net/) and [Rich](https://github.com/Textualize/rich). Captures live network traffic, identifies protocols, and displays detailed packet information in a colorized terminal interface — built as a cybersecurity internship / portfolio project.

> ⚠️ **Educational Use Only.** Only capture traffic on networks you own or have explicit written permission to monitor. Unauthorized packet sniffing may violate local laws and organizational policies.

---

## 📖 Project Overview

This project implements a lightweight, modular network sniffer that captures live packets from a chosen network interface, parses them, and presents key details — source/destination IP, ports, protocol, MAC addresses, TCP flags, payload preview, and more — in a clean, color-coded console UI. It also logs every packet to disk and generates a session summary report when capture ends.

---

## ✨ Features

- **Live Packet Capture** from any available network interface
- **Protocol Detection**: TCP, UDP, ICMP, ARP, DNS, HTTP, HTTPS (and more via well-known ports)
- **Packet Counter** and **per-protocol statistics**
- **Colorized terminal output** via `rich`
- **Timestamps** for every packet
- **Printable-only payload preview** (capped at 100 characters)
- **MAC address display** (source & destination, when available)
- **Automatic interface detection** — no manual selection required
- **Persistent logging**: `logs/packets.log` and `logs/summary.txt`
- **Graceful CTRL+C shutdown** with final statistics and execution time
- **ASCII art banner** and colorized `rich`-based interface listing

---


## ⚙️ Requirements

- Python **3.12+**
- [Npcap](https://npcap.com/) (Windows) or `libpcap` (Linux/macOS, usually preinstalled)
- Root/Administrator privileges (raw packet capture requires elevated access)

Python packages (see `requirements.txt`):
```
scapy>=2.5.0
colorama>=0.4.6
rich>=13.7.0
```

---

## 🚀 Installation

```bash
# 1. Clone or download the project
git clone https://github.com/yourusername/Basic-Network-Sniffer.git


# 2. (Recommended) Create a virtual environment
python3 -m venv venv
source venv/bin/activate      # Linux/Kali/macOS
venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt
```

**Windows users:** install [Npcap](https://npcap.com/#download) first (enable "WinPcap API-compatible mode" during setup) — Scapy needs it for raw packet capture.

---

## ▶️ How to Run

```bash
# Linux / Kali (root privileges required for raw sockets)
sudo python3 main.py

# Windows (run terminal as Administrator)
python main.py
```

What happens next:
1. The default network interface is auto-detected and displayed (all detected interfaces are also listed for reference).
2. Live, colorized packet output streams immediately — no setup steps needed.
3. Press **CTRL+C** to stop — a summary report is printed and saved automatically.

---

## 🧠 How It Works

1. **Interface Auto-Detection** — `conf.iface` (Scapy's resolved default/active interface) is displayed automatically; `NetworkSniffer.list_interfaces()` also lists all available interfaces via `get_if_list()` for reference. No manual selection step is required — capture uses Scapy's default interface resolution.
2. **Capture Loop** — `scapy.sniff()` runs continuously, invoking a callback for every packet.
3. **Parsing** — `PacketParser` extracts IP/MAC addresses, ports, protocol, TCP flags, and a printable payload preview into a `PacketInfo` dataclass.
4. **Protocol Resolution** — `ProtocolDetector` maps IP protocol numbers and well-known ports to readable names (e.g., port 443 → HTTPS).
5. **Statistics** — `StatisticsTracker` maintains running totals per protocol.
6. **Logging** — every packet is written to `logs/packets.log`; the final report goes to `logs/summary.txt`.
7. **Display** — `main.py` renders each packet as a colorized `rich` line in the terminal.
8. **Shutdown** — CTRL+C triggers a `KeyboardInterrupt`, caught by `main.py`, which prints and saves the final report.

---

## 🖥️ Output Example

```
[#00001] 2026-07-17 10:22:41  TCP      192.168.1.5:52344 -> 142.250.183.14:443  len=66  flags=S
[#00002] 2026-07-17 10:22:41  HTTPS    192.168.1.5:52344 -> 142.250.183.14:443  len=1420
[#00003] 2026-07-17 10:22:42  DNS      192.168.1.5:59211 -> 8.8.8.8:53  len=72
           payload: example.com
[#00004] 2026-07-17 10:22:43  ARP      192.168.1.5 -> 192.168.1.1  len=42

==================================================
PACKET CAPTURE SUMMARY REPORT
==================================================
Total Packets Captured : 214
Execution Time (sec)   : 47.32
--------------------------------------------------
Protocol Breakdown:
  TCP       : 150
  UDP       : 40
  ICMP      : 12
  ARP       : 12
  OTHERS    : 0
--------------------------------------------------
Application-Layer Detections:
  DNS       : 28
  HTTPS     : 96
==================================================
```



---

## ⚠️ Limitations

- Requires root/administrator privileges to capture raw packets.
- Encrypted traffic (HTTPS/TLS) payloads cannot be read in plaintext — only headers/metadata are shown.
- Designed for educational use on small/medium traffic volumes; not optimized for high-throughput enterprise capture.
- Application-layer protocol detection relies on well-known port numbers and may misclassify traffic on non-standard ports.

---

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

## 👤 Author

LakxitT
