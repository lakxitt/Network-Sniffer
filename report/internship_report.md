# Internship Project Report: Basic Network Sniffer Using Python

---

## 1. Introduction

Network traffic analysis is a foundational skill in cybersecurity, used for intrusion detection, network troubleshooting, and security auditing. This report documents the design and implementation of a **Basic Network Sniffer**, a Python application that captures live network packets, parses them into human-readable information, and displays real-time statistics. The tool was built as a hands-on internship project to demonstrate practical skills in Python programming, network protocols, and secure software design.

---

## 2. Objectives

- Build a functional, live network packet sniffer using Python.
- Correctly identify and classify network protocols (TCP, UDP, ICMP, ARP, DNS, HTTP, HTTPS).
- Present captured data in a clear, organized, and visually readable format.
- Apply professional software engineering practices: modular architecture, type hinting, exception handling, logging, and documentation.
- Produce logs and exportable reports suitable for later analysis.

---

## 3. Tools Used

| Tool | Purpose |
|---|---|
| Python 3.12+ | Core programming language |
| Scapy | Packet capture and low-level protocol parsing |
| Rich | Colorized terminal tables and live output |
| Colorama | Cross-platform terminal color support |
| Git/GitHub | Version control and portfolio hosting |

---

## 4. Libraries Used

- **scapy** — provides packet sniffing (`sniff()`), interface listing (`get_if_list()`), and protocol layer classes (`IP`, `TCP`, `UDP`, `ICMP`, `ARP`, `Ether`).
- **rich** — renders colorized tables, panels, and styled text in the terminal.
- **colorama** — ensures ANSI color codes render correctly on Windows terminals.
- **dataclasses / csv / json / logging** (Python standard library) — structured data modeling, export, and persistent logging.

---

## 5. Working Principle

The sniffer operates by placing the selected network interface into a mode where Scapy can read raw packets as they arrive on the network. Each packet is passed through a callback function, which:

1. Parses the packet's layers (Ethernet, IP, TCP/UDP/ICMP/ARP) to extract addressing and protocol information.
2. Resolves the protocol name using IP protocol numbers and well-known port mappings.
3. Extracts only the printable-ASCII portion of the payload, capped at 100 characters, to avoid dumping binary/encrypted data.
4. Updates running statistics (per-protocol packet counts).
5. Logs the packet to a file and optionally stores it in memory for search/export.
6. Displays the packet as a colorized line in the terminal.

When the user interrupts execution (CTRL+C), the program stops the capture loop, computes total execution time, prints/saves a final summary report, and offers to export the session's packets to CSV or JSON.

---

## 6. Implementation Steps

1. **Project scaffolding** — designed a modular folder structure separating configuration, capture logic, parsing, protocol detection, logging, and statistics.
2. **Configuration layer** (`config/settings.py`) — centralized file paths, protocol number mappings, port-to-protocol mappings, and color schemes.
3. **Protocol detection** (`protocol_detector.py`) — implemented lookup logic to convert numeric IP protocol identifiers and port numbers into readable names (e.g., 6 → TCP, port 443 → HTTPS).
4. **Packet parsing** (`packet_parser.py`) — built a `PacketInfo` dataclass and parsing logic to extract structured fields from raw Scapy packets, including a safe printable-payload extractor.
5. **Capture engine** (`packet_capture.py`) — implemented the `NetworkSniffer` class, which drives Scapy's `sniff()` loop over *all* traffic and applies protocol/IP/port filters in pure Python (`_matches_filters()`) rather than via a BPF filter string — a deliberate choice made after discovering that BPF filter compilation is unreliable on some Windows Npcap installations. Matching packets are dispatched to statistics, logging, and display layers; non-matching packets are dropped immediately.
6. **Statistics tracking** (`statistics.py`) — implemented counters using `collections.Counter` and a formatted report generator.
7. **Logging & export** (`logger.py`) — implemented file-based logging (`logs/packets.log`), summary persistence (`logs/summary.txt`), and CSV/JSON export functions.
8. **CLI interface** (`main.py`) — built an interactive terminal UI using `rich`, including a banner, interface selection table, filter prompts, live colorized packet rendering, graceful shutdown handling, in-memory search, and export prompts.
9. **Testing** — verified syntax correctness of all modules and validated logical flow through code review (live traffic testing requires elevated OS privileges and a physical/virtual network interface).
10. **Documentation** — authored a professional `README.md` and this internship report.

---

## 7. Code Explanation

- **`config/settings.py`** defines constants such as log file paths, `IP_PROTOCOL_MAP` (numeric protocol → name), `PORT_PROTOCOL_MAP` (well-known ports → application protocol), and per-protocol display colors.
- **`sniffer/protocol_detector.py`**'s `ProtocolDetector` class exposes static methods to resolve base and application-layer protocol names, preferring specific protocols (e.g., HTTPS) over generic ones (TCP) when a well-known port matches.
- **`sniffer/packet_parser.py`**'s `PacketParser.parse()` inspects each packet's layers (`ARP`, `IP`, `TCP`, `UDP`, `ICMP`) and returns a structured `PacketInfo` object; malformed or unsupported packets are safely skipped.
- **`sniffer/packet_capture.py`**'s `NetworkSniffer` class ties together filtering, capture, parsing, statistics, and logging. It exposes `list_interfaces()`, `start()`, and `generate_final_report()`.
- **`sniffer/statistics.py`**'s `StatisticsTracker` maintains a `Counter` of protocol occurrences and formats a readable summary report, including elapsed execution time.
- **`sniffer/logger.py`** wraps Python's standard `logging` module for packet-level logs and provides `export_csv()` / `export_json()` for bonus export functionality.
- **`main.py`** is the interactive entry point: it prints an ASCII banner, lists interfaces via a `rich.Table`, prompts for optional filters, starts capture, renders each packet with color coding by protocol, and on exit prints statistics, offers packet search, and offers CSV/JSON export.

All modules use **type hints**, **docstrings**, and **try/except exception handling** to ensure the application degrades gracefully (e.g., on permission errors or malformed packets) rather than crashing.

---

## 8. Output

When run with administrator/root privileges, the tool prints a live, color-coded stream of packets (protocol, addresses, ports, flags, payload preview) to the terminal, and on exit displays a summary such as total packets captured, per-protocol breakdown, and total execution time. All packets are also persisted to `logs/packets.log`, with a final report saved to `logs/summary.txt`. (See the `README.md` for a sample console output and the `screenshots/` folder for actual captures.)

---

## 9. Advantages

- Lightweight and easy to run on any OS with Python and libpcap/Npcap installed.
- Modular codebase makes it easy to extend with new protocols or features.
- Clear, color-coded output improves readability compared to raw `tcpdump`-style text.
- Built-in logging and export support downstream analysis without extra tooling.
- Demonstrates core cybersecurity and networking concepts suitable for an internship portfolio.

---

## 10. Limitations

- Requires elevated OS privileges (root/Administrator) for raw packet capture.
- Cannot decrypt or inspect the contents of encrypted (TLS/HTTPS) traffic — only headers and metadata are visible.
- Application-layer protocol identification is port-based and may misclassify traffic running on non-standard ports.
- Not optimized for very high-throughput enterprise network capture (educational/demo scale).

---

## 11. Future Scope

- Integration with a web-based real-time dashboard.
- PCAP file import/export for interoperability with Wireshark.
- GeoIP-based geographic visualization of traffic sources.
- Signature-based detection of suspicious/malicious traffic patterns (lightweight IDS features).
- Multi-threaded capture for higher-throughput environments.

---

## 12. Learning Outcomes

Through this project, practical experience was gained in:
- Using Scapy to capture and dissect network packets at multiple OSI layers.
- Understanding TCP/IP, UDP, ICMP, and ARP protocol structures in practice.
- Designing modular, maintainable Python applications following PEP 8 and clean-architecture principles.
- Applying exception handling and logging best practices in a real-time application.
- Building interactive, user-friendly command-line interfaces with the `rich` library.
- Documenting a software project professionally for internship and portfolio purposes.

---

## 13. Conclusion

The Basic Network Sniffer project successfully demonstrates the core principles of network traffic analysis using Python. It captures, parses, classifies, and displays live network packets in an accessible format while maintaining a clean, modular, and well-documented codebase. Beyond its immediate functionality, the project reinforces foundational cybersecurity concepts — protocol structure, traffic classification, and secure coding practices — making it a strong addition to an internship submission, resume, and GitHub portfolio.
