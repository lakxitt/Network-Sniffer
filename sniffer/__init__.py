"""
sniffer package

A modular, educational network packet sniffer built on top of Scapy.

Modules:
    packet_capture     -> Handles live capture and interface selection
    packet_parser       -> Extracts structured information from raw packets
    protocol_detector   -> Maps protocol numbers/ports to human-readable names
    logger              -> Handles file logging, CSV/JSON export
    statistics          -> Tracks packet counters and protocol statistics
"""

__version__ = "1.0.0"
__author__ = "Basic Network Sniffer Team"
