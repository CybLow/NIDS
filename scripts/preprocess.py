#!/usr/bin/env python3
"""Preprocess the LSNM2024 dataset for CNN-BiLSTM model training.

The LSNM2024 dataset contains Wireshark packet-level CSV exports, NOT
pre-computed flow features.  This script aggregates raw packets into
bidirectional flows and computes the exact 77 flow-level features that
the C++ NativeFlowExtractor produces at inference time.

Steps:
    1. Load raw Wireshark CSV packets (recursively from Benign/ and Malicious/)
    2. Parse packet fields (timestamps, IPs, ports, protocol, flags, lengths)
    3. Aggregate packets into bidirectional flows (5-tuple keying)
    4. Compute 77 flow-level features matching NativeFlowExtractor::toFeatureVector()
    5. Encode labels to integer indices (matching AttackType.h enum order)
    6. Clean: drop NaN/inf, remove constant columns
    7. Normalize features (StandardScaler)
    8. Split into train/val/test (70/15/15)
    9. Compute class weights for balanced training
   10. Save processed data (.npy) and normalization parameters (.json)

Usage:
    python scripts/preprocess.py \\
        --input-dir scripts/data/ \\
        --output-dir scripts/data/processed/

Feature reference:
    See src/infra/flow/NativeFlowExtractor.cpp :: flowFeatureNames() and
    FlowStats::toFeatureVector() for the authoritative 77-feature definition.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent

# Must match AttackType.h enum order exactly (0..15).
LABEL_MAP: dict[str, int] = {
    "Benign": 0,
    "MITM-ARP-Spoofing": 1,
    "SSH-Bruteforce": 2,
    "FTP-BruteForce": 3,
    "DDoS-ICMP_Flood": 4,
    "DDoS-RawIPDDoS": 5,
    "DDoS-UDP_Flood": 6,
    "DoS": 7,
    "Exploiting-FTP": 8,
    "Fuzzing": 9,
    "ICMP-Flood": 10,
    "SYN-Flood": 11,
    "Port_Scanning": 12,
    "Remote-Code-Execution": 13,
    "SQL_Injection": 14,
    "XSS": 15,
}

INDEX_TO_LABEL: dict[int, str] = {v: k for k, v in LABEL_MAP.items()}

# Maps actual LSNM2024 Malicious subfolder names -> canonical LABEL_MAP keys.
# Keys are lower-cased for case-insensitive lookup.
FOLDER_LABEL_MAP: dict[str, str] = {
    "arp-spoof": "MITM-ARP-Spoofing",
    "mitm-arp spoofing": "MITM-ARP-Spoofing",
    "ssh brute force": "SSH-Bruteforce",
    "ftp brute force": "FTP-BruteForce",
    "ddos icmp": "DDoS-ICMP_Flood",
    "ddos raw": "DDoS-RawIPDDoS",
    "ddos-udp": "DDoS-UDP_Flood",
    "ddos udp": "DDoS-UDP_Flood",
    "dos": "DoS",
    "exploiting ftp": "Exploiting-FTP",
    "fuzzing": "Fuzzing",
    "icmp flood": "ICMP-Flood",
    "syn flood": "SYN-Flood",
    "port scanning": "Port_Scanning",
    "remote code execution": "Remote-Code-Execution",
    "sql injection": "SQL_Injection",
    "xss": "XSS",
}

# Maps raw label strings that appear inside CSVs -> canonical LABEL_MAP keys.
RAW_LABEL_ALIASES: dict[str, str] = {
    "normal": "Benign",
    "benign": "Benign",
    "mitm-arp-spoofing": "MITM-ARP-Spoofing",
    "ssh-bruteforce": "SSH-Bruteforce",
    "ftp-bruteforce": "FTP-BruteForce",
    "ddos-icmp_flood": "DDoS-ICMP_Flood",
    "ddos-rawipddos": "DDoS-RawIPDDoS",
    "ddos-udp_flood": "DDoS-UDP_Flood",
    "dos": "DoS",
    "exploiting-ftp": "Exploiting-FTP",
    "fuzzing": "Fuzzing",
    "icmp-flood": "ICMP-Flood",
    "syn-flood": "SYN-Flood",
    "port_scanning": "Port_Scanning",
    "remote-code-execution": "Remote-Code-Execution",
    "sql_injection": "SQL_Injection",
    "xss": "XSS",
}

# 77 feature names matching NativeFlowExtractor::flowFeatureNames() exactly.
FLOW_FEATURE_NAMES: list[str] = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]

assert len(FLOW_FEATURE_NAMES) == 77, (
    f"Expected 77 features, got {len(FLOW_FEATURE_NAMES)}"
)

# TCP flag bit masks (matching C++ kTcpFin, kTcpSyn, etc.)
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWR = 0x80

# Flow parameters matching C++ NativeFlowExtractor
FLOW_TIMEOUT_US = 600_000_000  # 600 seconds
IDLE_THRESHOLD_US = 5_000_000  # 5 seconds

# Protocol number mapping
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMP = 1
PROTO_ARP = 0  # Pseudo protocol number for ARP (not a real IP protocol)

# Maximum packets per flow before forced split.  Prevents mega-flows (e.g.
# DDoS-RawIPDDoS where 326K packets share a single 5-tuple) from collapsing
# into a single sample.  Value chosen based on dataset analysis: the rarest
# classes (DDoS-ICMP, ICMP-Flood, DDoS-RawIP) have only 1-2 unique
# bidirectional 5-tuples with 200K-326K packets each.  At 200 packets/flow
# this yields ~1,000-1,600 flows per class — enough for meaningful training.
MAX_FLOW_PACKETS = 200


# ---------------------------------------------------------------------------
# Statistical helpers (must match C++ exactly)
# ---------------------------------------------------------------------------


def _mean(vals: Sequence[int] | Sequence[float]) -> float:
    """Mean of a sequence. Returns 0.0 for empty sequences."""
    if not vals:
        return 0.0
    return sum(vals) / len(vals)


def _stddev(vals: Sequence[int] | Sequence[float]) -> float:
    """Sample standard deviation (n-1 denominator). Matches C++ stddev().

    Returns 0.0 if fewer than 2 values.
    """
    if len(vals) <= 1:
        return 0.0
    m = _mean(vals)
    accum = sum((v - m) ** 2 for v in vals)
    return math.sqrt(accum / (len(vals) - 1))


def _variance(vals: Sequence[int] | Sequence[float]) -> float:
    """Population variance (n denominator). Matches C++ variance().

    Returns 0.0 if fewer than 2 values.
    """
    if len(vals) <= 1:
        return 0.0
    m = _mean(vals)
    accum = sum((v - m) ** 2 for v in vals)
    return accum / len(vals)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


class FlowKey(NamedTuple):
    """5-tuple flow identifier."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int


@dataclass
class FlowStats:
    """Accumulated per-flow statistics. Mirrors C++ FlowStats struct."""

    start_time_us: int = 0
    last_time_us: int = 0

    total_fwd_packets: int = 0
    total_bwd_packets: int = 0
    total_fwd_bytes: int = 0
    total_bwd_bytes: int = 0

    fwd_packet_lengths: list[int] = field(default_factory=list)
    bwd_packet_lengths: list[int] = field(default_factory=list)
    all_packet_lengths: list[int] = field(default_factory=list)

    flow_iat_us: list[int] = field(default_factory=list)
    fwd_iat_us: list[int] = field(default_factory=list)
    bwd_iat_us: list[int] = field(default_factory=list)

    last_fwd_time_us: int = -1
    last_bwd_time_us: int = -1

    fwd_psh_flags: int = 0
    bwd_psh_flags: int = 0
    fwd_urg_flags: int = 0
    bwd_urg_flags: int = 0

    fin_count: int = 0
    syn_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    ack_count: int = 0
    urg_count: int = 0
    cwr_count: int = 0
    ece_count: int = 0

    fwd_header_bytes: int = 0
    bwd_header_bytes: int = 0

    fwd_init_win_bytes: int = 0
    bwd_init_win_bytes: int = 0

    act_data_pkt_fwd: int = 0
    min_seg_size_forward: int = 0

    active_periods_us: list[int] = field(default_factory=list)
    idle_periods_us: list[int] = field(default_factory=list)
    last_active_time_us: int = -1
    last_idle_time_us: int = -1

    fwd_bulk_bytes: list[int] = field(default_factory=list)
    bwd_bulk_bytes: list[int] = field(default_factory=list)
    fwd_bulk_packets: list[int] = field(default_factory=list)
    bwd_bulk_packets: list[int] = field(default_factory=list)

    cur_fwd_bulk_pkts: int = 0
    cur_fwd_bulk_bytes: int = 0
    cur_bwd_bulk_pkts: int = 0
    cur_bwd_bulk_bytes: int = 0
    last_packet_was_fwd: bool = False

    def to_feature_vector(self, dst_port: int) -> list[float]:
        """Compute the 77-element feature vector.

        Must produce identical output to C++ FlowStats::toFeatureVector().
        """
        features: list[float] = []

        duration_us = float(self.last_time_us - self.start_time_us)
        if duration_us < 0:
            duration_us = 0.0

        # 0: Destination Port
        features.append(float(dst_port))
        # 1: Flow Duration (microseconds)
        features.append(duration_us)
        # 2-5: Total Fwd/Bwd Packets and Bytes
        features.append(float(self.total_fwd_packets))
        features.append(float(self.total_bwd_packets))
        features.append(float(self.total_fwd_bytes))
        features.append(float(self.total_bwd_bytes))
        # 6-9: Fwd Packet Length Max, Min, Mean, Std
        features.extend(_length_stats(self.fwd_packet_lengths))
        # 10-13: Bwd Packet Length Max, Min, Mean, Std
        features.extend(_length_stats(self.bwd_packet_lengths))
        # 14-15: Flow Bytes/s, Flow Packets/s
        if duration_us > 0:
            total_bytes = float(self.total_fwd_bytes + self.total_bwd_bytes)
            total_pkts = float(self.total_fwd_packets + self.total_bwd_packets)
            features.append(total_bytes / (duration_us / 1e6))
            features.append(total_pkts / (duration_us / 1e6))
        else:
            features.extend([0.0, 0.0])
        # 16-19: Flow IAT Mean, Std, Max, Min
        if not self.flow_iat_us:
            features.extend([0.0, 0.0, 0.0, 0.0])
        else:
            features.append(_mean(self.flow_iat_us))
            features.append(_stddev(self.flow_iat_us))
            features.append(float(max(self.flow_iat_us)))
            features.append(float(min(self.flow_iat_us)))
        # 20-24: Fwd IAT Total, Mean, Std, Max, Min
        features.extend(_iat_stats(self.fwd_iat_us))
        # 25-29: Bwd IAT Total, Mean, Std, Max, Min
        features.extend(_iat_stats(self.bwd_iat_us))
        # 30-33: Fwd PSH Flags, Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags
        features.append(float(self.fwd_psh_flags))
        features.append(float(self.bwd_psh_flags))
        features.append(float(self.fwd_urg_flags))
        features.append(float(self.bwd_urg_flags))
        # 34-35: Fwd Header Length, Bwd Header Length
        features.append(float(self.fwd_header_bytes))
        features.append(float(self.bwd_header_bytes))
        # 36-37: Fwd Packets/s, Bwd Packets/s
        if duration_us > 0:
            features.append(float(self.total_fwd_packets) / (duration_us / 1e6))
            features.append(float(self.total_bwd_packets) / (duration_us / 1e6))
        else:
            features.extend([0.0, 0.0])
        # 38-42: Min Packet Length, Max Packet Length, Mean, Std, Variance
        if not self.all_packet_lengths:
            features.extend([0.0, 0.0, 0.0, 0.0, 0.0])
        else:
            features.append(float(min(self.all_packet_lengths)))
            features.append(float(max(self.all_packet_lengths)))
            features.append(_mean(self.all_packet_lengths))
            features.append(_stddev(self.all_packet_lengths))
            features.append(_variance(self.all_packet_lengths))
        # 43-50: FIN, SYN, RST, PSH, ACK, URG, CWR, ECE counts
        features.append(float(self.fin_count))
        features.append(float(self.syn_count))
        features.append(float(self.rst_count))
        features.append(float(self.psh_count))
        features.append(float(self.ack_count))
        features.append(float(self.urg_count))
        features.append(float(self.cwr_count))
        features.append(float(self.ece_count))
        # 51: Down/Up Ratio
        if self.total_fwd_packets > 0:
            features.append(
                float(self.total_bwd_packets) / float(self.total_fwd_packets)
            )
        else:
            features.append(0.0)
        # 52: Average Packet Size
        total_packets = self.total_fwd_packets + self.total_bwd_packets
        total_bytes = self.total_fwd_bytes + self.total_bwd_bytes
        features.append(
            float(total_bytes) / float(total_packets) if total_packets > 0 else 0.0
        )
        # 53: Avg Fwd Segment Size = (totalFwdBytes - fwdHeaderBytes) / totalFwdPackets
        if self.total_fwd_packets > 0:
            features.append(
                float(self.total_fwd_bytes - self.fwd_header_bytes)
                / float(self.total_fwd_packets)
            )
        else:
            features.append(0.0)
        # 54: Avg Bwd Segment Size = (totalBwdBytes - bwdHeaderBytes) / totalBwdPackets
        if self.total_bwd_packets > 0:
            features.append(
                float(self.total_bwd_bytes - self.bwd_header_bytes)
                / float(self.total_bwd_packets)
            )
        else:
            features.append(0.0)
        # 55-57: Fwd Bulk metrics
        if not self.fwd_bulk_bytes:
            features.extend([0.0, 0.0, 0.0])
        else:
            features.append(_mean(self.fwd_bulk_bytes))
            features.append(_mean(self.fwd_bulk_packets))
            total_fwd_bulk = float(sum(self.fwd_bulk_bytes))
            features.append(
                total_fwd_bulk / (duration_us / 1e6) if duration_us > 0 else 0.0
            )
        # 58-60: Bwd Bulk metrics
        if not self.bwd_bulk_bytes:
            features.extend([0.0, 0.0, 0.0])
        else:
            features.append(_mean(self.bwd_bulk_bytes))
            features.append(_mean(self.bwd_bulk_packets))
            total_bwd_bulk = float(sum(self.bwd_bulk_bytes))
            features.append(
                total_bwd_bulk / (duration_us / 1e6) if duration_us > 0 else 0.0
            )
        # 61-64: Subflow Fwd Packets, Fwd Bytes, Bwd Packets, Bwd Bytes
        features.append(float(self.total_fwd_packets))
        features.append(float(self.total_fwd_bytes))
        features.append(float(self.total_bwd_packets))
        features.append(float(self.total_bwd_bytes))
        # 65-66: Init_Win_bytes_forward, Init_Win_bytes_backward
        features.append(float(self.fwd_init_win_bytes))
        features.append(float(self.bwd_init_win_bytes))
        # 67-68: act_data_pkt_fwd, min_seg_size_forward
        features.append(float(self.act_data_pkt_fwd))
        features.append(float(self.min_seg_size_forward))
        # 69-72: Active Mean, Std, Max, Min
        if not self.active_periods_us:
            features.extend([0.0, 0.0, 0.0, 0.0])
        else:
            features.append(_mean(self.active_periods_us))
            features.append(_stddev(self.active_periods_us))
            features.append(float(max(self.active_periods_us)))
            features.append(float(min(self.active_periods_us)))
        # 73-76: Idle Mean, Std, Max, Min
        if not self.idle_periods_us:
            features.extend([0.0, 0.0, 0.0, 0.0])
        else:
            features.append(_mean(self.idle_periods_us))
            features.append(_stddev(self.idle_periods_us))
            features.append(float(max(self.idle_periods_us)))
            features.append(float(min(self.idle_periods_us)))

        assert len(features) == 77, f"Expected 77 features, got {len(features)}"
        return features


def _length_stats(lengths: list[int]) -> list[float]:
    """Max, Min, Mean, Std for a packet length list."""
    if not lengths:
        return [0.0, 0.0, 0.0, 0.0]
    return [float(max(lengths)), float(min(lengths)), _mean(lengths), _stddev(lengths)]


def _iat_stats(iats: list[int]) -> list[float]:
    """Total, Mean, Std, Max, Min for an IAT list."""
    if not iats:
        return [0.0, 0.0, 0.0, 0.0, 0.0]
    return [
        float(sum(iats)),
        _mean(iats),
        _stddev(iats),
        float(max(iats)),
        float(min(iats)),
    ]


# ---------------------------------------------------------------------------
# Packet parsing
# ---------------------------------------------------------------------------


@dataclass
class ParsedPacket:
    """Parsed fields from a single Wireshark CSV row."""

    timestamp_us: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int  # PROTO_TCP, PROTO_UDP
    ip_length: int  # Total IP packet length
    tcp_flags: int  # Bitmask (0 for UDP)
    tcp_window: int  # TCP window size (0 for UDP)
    tcp_payload_len: int  # TCP payload length (0 for UDP)
    ip_header_len: int  # IP header length (default 20)
    transport_header_len: int  # TCP data offset or 8 for UDP


def _parse_int(val: Any, default: int = 0) -> int:
    """Safely parse an integer from a CSV field."""
    if val is None or (isinstance(val, float) and math.isnan(val)):
        return default
    try:
        # Handle float strings like "951.0"
        return int(float(val))
    except (ValueError, TypeError):
        return default


def _parse_float(val: Any, default: float = 0.0) -> float:
    """Safely parse a float from a CSV field."""
    if val is None or (isinstance(val, float) and math.isnan(val)):
        return default
    try:
        return float(val)
    except (ValueError, TypeError):
        return default


def _parse_tcp_flags_hex(flags_str: Any) -> int:
    """Parse TCP flags from hex string like '0x002', '0x018', etc."""
    if flags_str is None or (isinstance(flags_str, float) and math.isnan(flags_str)):
        return 0
    try:
        s = str(flags_str).strip()
        if s.startswith("0x") or s.startswith("0X"):
            return int(s, 16)
        return int(s)
    except (ValueError, TypeError):
        return 0


def _protocol_str_to_num(proto: Any) -> int:
    """Convert Wireshark protocol string to IP protocol number."""
    if proto is None or (isinstance(proto, float) and math.isnan(proto)):
        return -1
    proto = str(proto).strip().upper()
    if proto == "TCP":
        return PROTO_TCP
    elif proto == "UDP":
        return PROTO_UDP
    elif proto == "ICMP":
        return PROTO_ICMP
    elif proto == "ARP":
        return PROTO_ARP
    return -1


# Regex patterns for extracting IPs from ARP Info text.
# Examples:
#   "Who has 192.168.1.184? Tell 192.168.1.67"        -> (1.67 -> src, 1.184 -> dst)
#   "192.168.1.67 is at aa:bb:cc:dd:ee:ff"            -> (1.67 -> src, 1.67 -> dst)
_ARP_REQUEST_RE = re.compile(r"Who has ([\d.]+)\?\s*Tell ([\d.]+)", re.IGNORECASE)
_ARP_REPLY_RE = re.compile(r"^([\d.]+) is at", re.IGNORECASE)


def _parse_arp_info(info: str) -> tuple[str, str] | None:
    """Extract (src_ip, dst_ip) from ARP Info column text.

    For ARP requests ("Who has X? Tell Y"): src = Y (sender), dst = X (target).
    For ARP replies ("X is at MAC"):        src = X, dst = X (self-referential).
    Returns None if the Info text cannot be parsed.
    """
    m = _ARP_REQUEST_RE.search(info)
    if m:
        target_ip = m.group(1)
        sender_ip = m.group(2)
        return sender_ip, target_ip
    m = _ARP_REPLY_RE.search(info)
    if m:
        ip = m.group(1)
        return ip, ip
    return None


def _parse_packet_row(row: pd.Series) -> ParsedPacket | None:
    """Parse a single CSV row into a ParsedPacket.

    Returns None if the row cannot be parsed.
    Supports TCP, UDP, ICMP, and ARP packets.
    """
    # Timestamp: "Frame Time (Epoch)" is a Unix timestamp (seconds, float)
    epoch_str = row.get("Frame Time (Epoch)", "")
    ts_sec = _parse_float(epoch_str)
    if ts_sec <= 0:
        return None
    timestamp_us = int(ts_sec * 1_000_000)

    # Protocol -- try "IP Protocol" first, fall back to "Protocol" for ARP
    proto_str = str(row.get("IP Protocol", "") or "").strip()
    if not proto_str or proto_str == "nan":
        proto_str = str(row.get("Protocol", "") or "").strip()
    protocol = _protocol_str_to_num(proto_str)
    if protocol < 0:
        return None  # Unknown / unsupported protocol

    # --- ARP handling ---
    if protocol == PROTO_ARP:
        info = str(row.get("Info", "") or "").strip()
        parsed = _parse_arp_info(info)
        if parsed is None:
            return None
        src_ip, dst_ip = parsed
        # ARP has no IP length; use frame length as a proxy.
        ip_length = _parse_int(row.get("frame length", 0))
        if ip_length <= 0:
            ip_length = _parse_int(row.get("Length", 0))
        if ip_length <= 0:
            return None
        return ParsedPacket(
            timestamp_us=timestamp_us,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=0,
            dst_port=0,
            protocol=PROTO_ARP,
            ip_length=ip_length,
            tcp_flags=0,
            tcp_window=0,
            tcp_payload_len=0,
            ip_header_len=0,
            transport_header_len=0,
        )

    # --- IP-based protocols (TCP, UDP, ICMP) ---
    src_ip = str(row.get("IP Source", "")).strip()
    dst_ip = str(row.get("IP Destination", "")).strip()
    if not src_ip or not dst_ip or src_ip == "nan" or dst_ip == "nan":
        return None

    # IP Length
    ip_length = _parse_int(row.get("IP Length", 0))
    if ip_length <= 0:
        return None

    # Ports and transport header
    src_port: int
    dst_port: int
    tcp_flags = 0
    tcp_window = 0
    tcp_payload_len = 0
    transport_header_len: int

    if protocol == PROTO_TCP:
        src_port = _parse_int(row.get("TCP Source Port", 0))
        dst_port = _parse_int(row.get("TCP Destination Port", 0))
        transport_header_len = 20
        tcp_flags = _parse_tcp_flags_hex(row.get("TCP Flags", ""))
        tcp_window = _parse_int(row.get("TCP Window Size", 0))
        tcp_payload_len = _parse_int(row.get("TCP Length", 0))
    elif protocol == PROTO_UDP:
        src_port = _parse_int(row.get("UDP Source Port", 0))
        dst_port = _parse_int(row.get("UDP Destination Port", 0))
        transport_header_len = 8
    elif protocol == PROTO_ICMP:
        # Use ICMP type as src_port and 0 as dst_port for flow keying.
        # This mirrors the C++ approach: ICMP type differentiates flow types
        # (e.g., echo request type=8 vs echo reply type=0).
        icmp_type = _parse_int(row.get("ICMP Type", 0))
        src_port = icmp_type
        dst_port = 0
        transport_header_len = 8  # ICMP header is 8 bytes
    else:
        return None  # Should not reach here

    # IP header length: not directly available in CSV, default 20.
    ip_header_len = 20

    return ParsedPacket(
        timestamp_us=timestamp_us,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        ip_length=ip_length,
        tcp_flags=tcp_flags,
        tcp_window=tcp_window,
        tcp_payload_len=tcp_payload_len,
        ip_header_len=ip_header_len,
        transport_header_len=transport_header_len,
    )


# ---------------------------------------------------------------------------
# Flow aggregation (mirrors C++ NativeFlowExtractor::processPacket)
# ---------------------------------------------------------------------------


class FlowAggregator:
    """Aggregates packets into bidirectional flows.

    Mirrors the logic in NativeFlowExtractor::processPacket() including:
    - 5-tuple flow keying with bidirectional matching
    - Flow timeout (600s) and TCP FIN/RST termination
    - Bulk transfer tracking
    - Active/idle period tracking (5s threshold)
    """

    def __init__(self) -> None:
        self.active_flows: dict[FlowKey, FlowStats] = {}
        self.completed_flows: list[tuple[FlowKey, FlowStats]] = []

    def process_packet(self, pkt: ParsedPacket) -> None:
        """Process a single packet, matching C++ processPacket() logic."""
        timestamp_us = pkt.timestamp_us
        header_bytes = pkt.ip_header_len + pkt.transport_header_len
        total_packet_len = pkt.ip_length
        payload_size = max(0, total_packet_len - header_bytes)

        key_fwd = FlowKey(
            pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol
        )
        key_bwd = FlowKey(
            pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port, pkt.protocol
        )

        # Check for flow timeout on existing flows
        if key_fwd in self.active_flows:
            stats = self.active_flows[key_fwd]
            if timestamp_us - stats.last_time_us > FLOW_TIMEOUT_US:
                self.completed_flows.append((key_fwd, stats))
                del self.active_flows[key_fwd]

        if key_bwd in self.active_flows:
            stats = self.active_flows[key_bwd]
            if timestamp_us - stats.last_time_us > FLOW_TIMEOUT_US:
                self.completed_flows.append((key_bwd, stats))
                del self.active_flows[key_bwd]

        # Determine flow direction
        used_key: FlowKey
        is_forward: bool
        if key_fwd in self.active_flows:
            used_key = key_fwd
            is_forward = True
        elif key_bwd in self.active_flows:
            used_key = key_bwd
            is_forward = False
        else:
            # New flow
            self.active_flows[key_fwd] = FlowStats()
            used_key = key_fwd
            is_forward = True

        stats = self.active_flows[used_key]
        if stats.start_time_us == 0:
            stats.start_time_us = timestamp_us

        prev_last_time_us = stats.last_time_us
        flow_gap_us = (timestamp_us - prev_last_time_us) if prev_last_time_us > 0 else 0
        if flow_gap_us > 0:
            stats.flow_iat_us.append(flow_gap_us)
        stats.last_time_us = timestamp_us

        packet_len = total_packet_len

        if is_forward:
            stats.total_fwd_packets += 1
            stats.total_fwd_bytes += packet_len
            stats.fwd_packet_lengths.append(packet_len)
            stats.fwd_header_bytes += header_bytes

            if stats.last_fwd_time_us >= 0:
                stats.fwd_iat_us.append(timestamp_us - stats.last_fwd_time_us)
            stats.last_fwd_time_us = timestamp_us
        else:
            stats.total_bwd_packets += 1
            stats.total_bwd_bytes += packet_len
            stats.bwd_packet_lengths.append(packet_len)
            stats.bwd_header_bytes += header_bytes

            if stats.last_bwd_time_us >= 0:
                iat = timestamp_us - stats.last_bwd_time_us
                stats.bwd_iat_us.append(iat)
                stats.flow_iat_us.append(iat)
            stats.last_bwd_time_us = timestamp_us

        stats.all_packet_lengths.append(packet_len)

        # TCP flags
        tcp_fin_or_rst = False
        if pkt.protocol == PROTO_TCP:
            flags = pkt.tcp_flags
            tcp_fin_or_rst = bool(flags & (TCP_FIN | TCP_RST))

            if is_forward:
                if flags & TCP_PSH:
                    stats.fwd_psh_flags += 1
                if flags & TCP_URG:
                    stats.fwd_urg_flags += 1
                if stats.fwd_init_win_bytes == 0:
                    stats.fwd_init_win_bytes = pkt.tcp_window
                if payload_size > 0:
                    stats.act_data_pkt_fwd += 1
                    if (
                        stats.min_seg_size_forward == 0
                        or payload_size < stats.min_seg_size_forward
                    ):
                        stats.min_seg_size_forward = payload_size
            else:
                if flags & TCP_PSH:
                    stats.bwd_psh_flags += 1
                if flags & TCP_URG:
                    stats.bwd_urg_flags += 1
                if stats.bwd_init_win_bytes == 0:
                    stats.bwd_init_win_bytes = pkt.tcp_window

            if flags & TCP_FIN:
                stats.fin_count += 1
            if flags & TCP_SYN:
                stats.syn_count += 1
            if flags & TCP_RST:
                stats.rst_count += 1
            if flags & TCP_PSH:
                stats.psh_count += 1
            if flags & TCP_ACK:
                stats.ack_count += 1
            if flags & TCP_URG:
                stats.urg_count += 1
            if flags & TCP_CWR:
                stats.cwr_count += 1
            if flags & TCP_ECE:
                stats.ece_count += 1

        # Bulk tracking: bulk = 2+ packets in same direction
        if is_forward:
            stats.cur_fwd_bulk_pkts += 1
            stats.cur_fwd_bulk_bytes += packet_len
            if not stats.last_packet_was_fwd and stats.cur_bwd_bulk_pkts >= 2:
                stats.bwd_bulk_packets.append(stats.cur_bwd_bulk_pkts)
                stats.bwd_bulk_bytes.append(stats.cur_bwd_bulk_bytes)
            if not stats.last_packet_was_fwd:
                stats.cur_bwd_bulk_pkts = 0
                stats.cur_bwd_bulk_bytes = 0
            stats.last_packet_was_fwd = True
        else:
            stats.cur_bwd_bulk_pkts += 1
            stats.cur_bwd_bulk_bytes += packet_len
            if stats.last_packet_was_fwd and stats.cur_fwd_bulk_pkts >= 2:
                stats.fwd_bulk_packets.append(stats.cur_fwd_bulk_pkts)
                stats.fwd_bulk_bytes.append(stats.cur_fwd_bulk_bytes)
            if stats.last_packet_was_fwd:
                stats.cur_fwd_bulk_pkts = 0
                stats.cur_fwd_bulk_bytes = 0
            stats.last_packet_was_fwd = False

        # Active/idle tracking (5s threshold)
        if flow_gap_us > IDLE_THRESHOLD_US and prev_last_time_us > 0:
            if stats.last_active_time_us >= 0:
                stats.active_periods_us.append(
                    prev_last_time_us - stats.last_active_time_us
                )
            stats.last_idle_time_us = prev_last_time_us
            stats.last_active_time_us = -1

        if stats.last_idle_time_us >= 0:
            stats.idle_periods_us.append(timestamp_us - stats.last_idle_time_us)
            stats.last_idle_time_us = -1
        stats.last_active_time_us = timestamp_us

        # TCP FIN/RST terminates the flow
        if tcp_fin_or_rst:
            if stats.cur_fwd_bulk_pkts >= 2:
                stats.fwd_bulk_packets.append(stats.cur_fwd_bulk_pkts)
                stats.fwd_bulk_bytes.append(stats.cur_fwd_bulk_bytes)
            if stats.cur_bwd_bulk_pkts >= 2:
                stats.bwd_bulk_packets.append(stats.cur_bwd_bulk_pkts)
                stats.bwd_bulk_bytes.append(stats.cur_bwd_bulk_bytes)
            self.completed_flows.append((used_key, stats))
            del self.active_flows[used_key]
            return

        # Max-flow-size splitting: prevent mega-flows from collapsing into
        # a single sample.  When exceeded, finalize the current flow and
        # start a fresh one for the same 5-tuple.
        total_pkts = stats.total_fwd_packets + stats.total_bwd_packets
        if total_pkts >= MAX_FLOW_PACKETS:
            if stats.cur_fwd_bulk_pkts >= 2:
                stats.fwd_bulk_packets.append(stats.cur_fwd_bulk_pkts)
                stats.fwd_bulk_bytes.append(stats.cur_fwd_bulk_bytes)
            if stats.cur_bwd_bulk_pkts >= 2:
                stats.bwd_bulk_packets.append(stats.cur_bwd_bulk_pkts)
                stats.bwd_bulk_bytes.append(stats.cur_bwd_bulk_bytes)
            self.completed_flows.append((used_key, stats))
            # Start a new flow for the same key
            self.active_flows[used_key] = FlowStats()

    def finalize(self) -> list[tuple[FlowKey, FlowStats]]:
        """Finalize all remaining active flows and return all flows.

        Mirrors C++ finalizeBulks() + moving remaining flows to completed.
        """
        for key, stats in self.active_flows.items():
            if stats.cur_fwd_bulk_pkts >= 2:
                stats.fwd_bulk_packets.append(stats.cur_fwd_bulk_pkts)
                stats.fwd_bulk_bytes.append(stats.cur_fwd_bulk_bytes)
            if stats.cur_bwd_bulk_pkts >= 2:
                stats.bwd_bulk_packets.append(stats.cur_bwd_bulk_pkts)
                stats.bwd_bulk_bytes.append(stats.cur_bwd_bulk_bytes)
            self.completed_flows.append((key, stats))
        self.active_flows.clear()
        return self.completed_flows


# ---------------------------------------------------------------------------
# Label inference from directory structure
# ---------------------------------------------------------------------------


def _infer_label_from_path(csv_path: Path, input_dir: Path) -> str | None:
    """Infer an attack-type label from a CSV file's directory path.

    The LSNM2024 dataset is organised as::

        <input_dir>/.../Dataset-Ready (Use This)/Benign/<file>.csv
        <input_dir>/.../Dataset-Ready (Use This)/Malicious/<AttackFolder>/<file>.csv

    Returns a canonical LABEL_MAP key, or None if it cannot be determined.
    """
    try:
        parts = csv_path.relative_to(input_dir).parts
    except ValueError:
        return None

    for i, part in enumerate(parts):
        if part.lower() == "benign":
            return "Benign"
        if part.lower() == "malicious":
            # The next component (if not the filename itself) is the attack folder
            if i + 1 < len(parts) - 1:
                folder = parts[i + 1]
                canonical = FOLDER_LABEL_MAP.get(folder.lower())
                if canonical:
                    return canonical
                return folder
            return "Malicious"
    return None


def _resolve_label(raw_label: str) -> int:
    """Resolve a raw label string to an integer class index.

    Resolution order:
    1. Direct match against LABEL_MAP keys.
    2. Alias lookup via RAW_LABEL_ALIASES.
    3. Normalised string comparison (strip punctuation/spaces).
    4. Substring matching.
    5. Fallback -> Benign (0) with a warning.
    """
    # 1. Direct match
    if raw_label in LABEL_MAP:
        return LABEL_MAP[raw_label]

    # 2. Alias lookup (case-insensitive)
    canonical = RAW_LABEL_ALIASES.get(raw_label.lower())
    if canonical and canonical in LABEL_MAP:
        return LABEL_MAP[canonical]

    # 3. Normalised comparison
    def _norm(s: str) -> str:
        return s.lower().replace(" ", "").replace("-", "").replace("_", "")

    for map_key, map_val in LABEL_MAP.items():
        if _norm(raw_label) == _norm(map_key):
            return map_val

    # 4. Substring matching
    for map_key, map_val in LABEL_MAP.items():
        if map_key.lower() in raw_label.lower() or raw_label.lower() in map_key.lower():
            return map_val

    # 5. Fallback
    print(f"  WARNING: Unmapped label '{raw_label}' -> treating as Benign (0)")
    return 0


# ---------------------------------------------------------------------------
# CSV loading and flow extraction
# ---------------------------------------------------------------------------


def _load_and_aggregate_csv(
    csv_path: Path,
    label: str,
    input_dir: Path,
) -> tuple[list[list[float]], list[int]]:
    """Load a single CSV file, aggregate packets into flows, return features + labels.

    Returns (flow_features, flow_labels) where each flow_features[i] is a
    77-element list and flow_labels[i] is the integer class index.
    """
    df = pd.read_csv(csv_path, low_memory=False)

    # Resolve the label to an integer
    label_idx = _resolve_label(label)

    # Parse packets and sort by timestamp
    packets: list[ParsedPacket] = []
    skipped = 0
    for _, row in df.iterrows():
        pkt = _parse_packet_row(row)
        if pkt is not None:
            packets.append(pkt)
        else:
            skipped += 1

    if not packets:
        print(f"    WARNING: No valid TCP/UDP packets in {csv_path.name}")
        return [], []

    # Sort packets by timestamp (essential for correct flow aggregation)
    packets.sort(key=lambda p: p.timestamp_us)

    # Aggregate into flows
    aggregator = FlowAggregator()
    for pkt in packets:
        aggregator.process_packet(pkt)
    all_flows = aggregator.finalize()

    # Extract features
    flow_features: list[list[float]] = []
    flow_labels: list[int] = []
    for key, stats in all_flows:
        fv = stats.to_feature_vector(key.dst_port)
        flow_features.append(fv)
        flow_labels.append(label_idx)

    print(
        f"    {len(df):>9,} packets -> {len(flow_features):>7,} flows "
        f"(skipped {skipped:,} non-TCP/UDP)  [{INDEX_TO_LABEL.get(label_idx, label)}]"
    )
    return flow_features, flow_labels


def load_and_process_dataset(input_dir: Path) -> tuple[np.ndarray, np.ndarray]:
    """Load all CSVs, aggregate packets into flows, compute features.

    Returns (X, y) where X has shape (n_flows, 77) and y has shape (n_flows,).
    """
    csv_files = sorted(input_dir.rglob("*.csv"))
    if not csv_files:
        print(
            f"Error: No CSV files found (recursively) in {input_dir}", file=sys.stderr
        )
        sys.exit(1)

    print(f"Found {len(csv_files)} CSV file(s). Aggregating packets into flows...\n")

    all_features: list[list[float]] = []
    all_labels: list[int] = []

    for csv_path in csv_files:
        rel = csv_path.relative_to(input_dir)
        print(f"  Processing {rel}...")

        # Determine label
        label = _infer_label_from_path(csv_path, input_dir)

        # Check if the CSV itself has a label column
        # Read just the header to check
        with open(csv_path) as f:
            header_line = f.readline().strip()
        columns_lower = [c.strip().lower().strip('"') for c in header_line.split(",")]

        if label is None:
            # Try to get label from CSV column if present
            if "label" in columns_lower:
                # Read labels from the file
                df_labels = pd.read_csv(csv_path, usecols=["label"], low_memory=False)
                unique_labels = df_labels["label"].dropna().unique()
                if len(unique_labels) == 1:
                    label = str(unique_labels[0]).strip()
                else:
                    label = "Benign"
                    print(f"    WARNING: Multiple labels found, defaulting to Benign")
            else:
                label = "Benign"
                print(f"    WARNING: Cannot determine label, defaulting to Benign")

        features, labels = _load_and_aggregate_csv(csv_path, label, input_dir)
        all_features.extend(features)
        all_labels.extend(labels)

    if not all_features:
        print("Error: No flows extracted from any CSV file.", file=sys.stderr)
        sys.exit(1)

    X = np.array(all_features, dtype=np.float64)
    y = np.array(all_labels, dtype=np.int64)

    print(
        f"\nTotal: {X.shape[0]:,} flows, {X.shape[1]} features, "
        f"{len(np.unique(y))} classes represented\n"
    )

    return X, y


# ---------------------------------------------------------------------------
# Cleaning, normalization, splitting
# ---------------------------------------------------------------------------


def clean_features(X: np.ndarray, y: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Clean the feature matrix: replace inf with NaN, drop rows with NaN."""
    # Replace infinities with NaN
    X = np.where(np.isinf(X), np.nan, X)

    # Count and report NaN rows
    nan_mask = np.isnan(X).any(axis=1)
    nan_count = nan_mask.sum()
    if nan_count > 0:
        print(f"Dropping {nan_count:,} flows with NaN/inf values")
        X = X[~nan_mask]
        y = y[~nan_mask]

    print(f"After cleaning: {X.shape[0]:,} flows, {X.shape[1]} features\n")
    return X, y


def normalize_features(
    X_train: np.ndarray,
    X_val: np.ndarray,
    X_test: np.ndarray,
    clip_value: float = 10.0,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, dict]:
    """Fit StandardScaler on training set, transform all splits.

    After normalization, clips values to [-clip_value, clip_value] to mitigate
    the effect of extreme outliers (heavy-tailed flow features like packet
    counts and byte volumes can produce values 100-800x the standard deviation).
    """
    scaler = StandardScaler()
    X_train_norm = scaler.fit_transform(X_train).astype(np.float32)
    X_val_norm = scaler.transform(X_val).astype(np.float32)
    X_test_norm = scaler.transform(X_test).astype(np.float32)

    # Clip extreme outliers post-normalization
    n_clipped_train = int((np.abs(X_train_norm) > clip_value).sum())
    X_train_norm = np.clip(X_train_norm, -clip_value, clip_value)
    X_val_norm = np.clip(X_val_norm, -clip_value, clip_value)
    X_test_norm = np.clip(X_test_norm, -clip_value, clip_value)

    # Guard near-zero stds: replace any std < 1e-8 with 1.0 so that C++
    # inference (which does (x - mean) / std) never divides by ~0.
    # sklearn's StandardScaler already does this internally, but we make it
    # explicit in the saved metadata for safety.
    safe_stds = scaler.scale_.copy()
    near_zero_mask = safe_stds < 1e-8
    n_zero_var = int(near_zero_mask.sum())
    if n_zero_var > 0:
        safe_stds[near_zero_mask] = 1.0
        zero_var_names = [
            FLOW_FEATURE_NAMES[i]
            for i in range(len(FLOW_FEATURE_NAMES))
            if near_zero_mask[i]
        ]
        print(
            f"  {n_zero_var} zero-variance feature(s) (std replaced with 1.0): "
            f"{zero_var_names}"
        )

    norm_params = {
        "feature_names": FLOW_FEATURE_NAMES,
        "means": scaler.mean_.tolist(),
        "stds": safe_stds.tolist(),
        "clip_value": clip_value,
        "n_features": len(FLOW_FEATURE_NAMES),
    }

    print(
        f"Normalization: {len(FLOW_FEATURE_NAMES)} features, "
        f"StandardScaler fitted on training set"
    )
    if n_clipped_train > 0:
        total_cells = X_train_norm.shape[0] * X_train_norm.shape[1]
        pct = 100.0 * n_clipped_train / total_cells
        print(
            f"  Clipped {n_clipped_train:,} values ({pct:.4f}%) to "
            f"[{-clip_value}, {clip_value}]"
        )
    return X_train_norm, X_val_norm, X_test_norm, norm_params


def compute_class_weights(y: np.ndarray, n_classes: int) -> dict[int, float]:
    """Compute inverse-frequency class weights for balanced training."""
    counts = np.bincount(y, minlength=n_classes)
    total = len(y)
    weights: dict[int, float] = {}
    for i in range(n_classes):
        if counts[i] > 0:
            weights[i] = total / (n_classes * counts[i])
        else:
            weights[i] = 0.0
    return weights


def save_metadata(
    output_dir: Path,
    norm_params: dict,
    class_weights: dict[int, float],
    label_map: dict[str, int],
    split_sizes: dict[str, int],
) -> None:
    """Save model metadata (normalization params, class info) as JSON."""
    metadata = {
        "dataset": "LSNM2024",
        "source": "https://data.mendeley.com/datasets/7pzyfvv9jn/1",
        "n_classes": len(label_map),
        "n_features": norm_params["n_features"],
        "feature_names": norm_params["feature_names"],
        "normalization": {
            "method": "standard_scaler",
            "means": norm_params["means"],
            "stds": norm_params["stds"],
            "clip_value": norm_params["clip_value"],
        },
        "label_map": label_map,
        "index_to_label": {str(v): k for k, v in label_map.items()},
        "class_weights": {str(k): round(v, 6) for k, v in class_weights.items()},
        "split_sizes": split_sizes,
    }

    metadata_path = output_dir / "model_metadata.json"
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"Metadata saved to: {metadata_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Preprocess LSNM2024 Wireshark CSVs into 77 bidirectional flow features.",
    )
    parser.add_argument(
        "--input-dir",
        "-i",
        type=Path,
        default=SCRIPT_DIR / "data",
        help="Root directory containing LSNM2024 CSV files (searched recursively)",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=Path,
        default=SCRIPT_DIR / "data" / "processed",
        help="Directory for processed output files",
    )
    parser.add_argument(
        "--val-ratio",
        type=float,
        default=0.15,
        help="Validation set ratio (default: 0.15)",
    )
    parser.add_argument(
        "--test-ratio",
        type=float,
        default=0.15,
        help="Test set ratio (default: 0.15)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility",
    )
    args = parser.parse_args()

    output_dir: Path = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Load CSVs and aggregate packets into flows with 77 features
    X, y = load_and_process_dataset(args.input_dir)

    # 2. Clean (remove NaN/inf rows)
    X, y = clean_features(X, y)

    n_classes = len(LABEL_MAP)
    print(
        f"Dataset: {X.shape[0]:,} flows, {X.shape[1]} features, {n_classes} classes\n"
    )

    # 3. Print label distribution and identify rare/empty classes
    counts = np.bincount(y, minlength=n_classes)
    print("Label distribution:")
    for idx in range(n_classes):
        label_name = INDEX_TO_LABEL.get(idx, f"class_{idx}")
        print(f"  {label_name:30s}: {counts[idx]:>9,} flows")
    print()

    # 4. Split: train / val / test (70 / 15 / 15)
    #
    # Stratified splitting requires each class to have enough samples for every
    # split bucket.  Classes with very few flows (e.g. pure-ICMP attacks that
    # produce 0 TCP/UDP flows, or DDoS-RawIPDDoS with only 3 flows) would cause
    # sklearn to raise a ValueError.  We handle this by:
    #   1. Separating "rare" classes (< MIN_SAMPLES_FOR_SPLIT) from the main data.
    #   2. Performing the stratified split on the remaining "common" classes.
    #   3. Putting all rare-class samples into the *training* set only.
    #
    # This keeps the label indices intact (the model still has 16 output classes)
    # while avoiding the split crash.  A warning is printed for transparency.

    MIN_SAMPLES_FOR_SPLIT = 10  # need >=10 to reliably get >=1 per split bucket
    rare_mask = np.zeros(len(y), dtype=bool)
    rare_classes: list[int] = []
    for cls_idx in range(n_classes):
        if 0 < counts[cls_idx] < MIN_SAMPLES_FOR_SPLIT:
            rare_classes.append(cls_idx)
            rare_mask |= y == cls_idx

    if rare_classes:
        rare_names = [INDEX_TO_LABEL.get(c, f"class_{c}") for c in rare_classes]
        print(
            f"WARNING: Classes with <{MIN_SAMPLES_FOR_SPLIT} samples will be placed "
            f"entirely in the training set (no val/test samples): {rare_names}\n"
        )

    # Also warn about completely empty classes
    empty_classes = [c for c in range(n_classes) if counts[c] == 0]
    if empty_classes:
        empty_names = [INDEX_TO_LABEL.get(c, f"class_{c}") for c in empty_classes]
        print(f"WARNING: Classes with 0 samples (no flows extracted): {empty_names}\n")

    # Separate rare-class samples
    X_rare = X[rare_mask]
    y_rare = y[rare_mask]
    X_common = X[~rare_mask]
    y_common = y[~rare_mask]

    test_val_ratio = args.val_ratio + args.test_ratio
    X_train_common, X_temp, y_train_common, y_temp = train_test_split(
        X_common,
        y_common,
        test_size=test_val_ratio,
        random_state=args.seed,
        stratify=y_common,
    )
    relative_test_ratio = args.test_ratio / test_val_ratio
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp,
        y_temp,
        test_size=relative_test_ratio,
        random_state=args.seed,
        stratify=y_temp,
    )

    # Merge rare-class samples into training set
    if len(X_rare) > 0:
        X_train = np.concatenate([X_train_common, X_rare], axis=0)
        y_train = np.concatenate([y_train_common, y_rare], axis=0)
    else:
        X_train = X_train_common
        y_train = y_train_common

    split_sizes = {
        "train": len(X_train),
        "val": len(X_val),
        "test": len(X_test),
    }
    print(
        f"Split sizes: train={split_sizes['train']:,}, "
        f"val={split_sizes['val']:,}, test={split_sizes['test']:,}\n"
    )

    # 5. Normalize
    X_train, X_val, X_test, norm_params = normalize_features(X_train, X_val, X_test)

    # 6. Compute class weights
    class_weights = compute_class_weights(y_train, n_classes)
    print("Class weights:")
    for idx in sorted(class_weights):
        label_name = INDEX_TO_LABEL.get(idx, f"class_{idx}")
        print(f"  {label_name:30s}: {class_weights[idx]:.4f}")
    print()

    # 7. Save processed data
    np.save(output_dir / "X_train.npy", X_train)
    np.save(output_dir / "X_val.npy", X_val)
    np.save(output_dir / "X_test.npy", X_test)
    np.save(output_dir / "y_train.npy", y_train)
    np.save(output_dir / "y_val.npy", y_val)
    np.save(output_dir / "y_test.npy", y_test)
    print(f"Processed data saved to: {output_dir}/")

    # 8. Save metadata
    save_metadata(output_dir, norm_params, class_weights, LABEL_MAP, split_sizes)

    print(f"\nDone! Next step: python scripts/train_model.py --data-dir {output_dir}/")


if __name__ == "__main__":
    main()
