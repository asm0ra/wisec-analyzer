import math
import os
from collections import defaultdict, Counter
from typing import List

from .models import TimeBin, FileSummary, BatchSummary

from datetime import datetime, timezone

try:
    from scapy.all import PcapReader, Dot11
    from scapy.layers.dot11 import Dot11Deauth, Dot11Disas
    try:
        from scapy.layers.eap import EAPOL
        EAPOL_AVAILABLE = True
    except Exception:
        EAPOL_AVAILABLE = False
except Exception as e:
    raise RuntimeError(
        "Scapy is required for WiSecAnalyzer. Install it via: pip install scapy"
    ) from e


def human_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def bin_floor(ts: float, interval_seconds: int) -> float:
    return math.floor(ts / interval_seconds) * interval_seconds


def iter_packets(pcap_path: str):
    """Итератор по пакетам pcap (стримово, чтобы не съедать память)."""
    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            yield pkt


def analyze_file(pcap_path: str, bin_size_sec: int, threshold: int) -> FileSummary:
    bins_raw = defaultdict(list)   # floor_ts -> [(ts, src, dst, kind), ...]
    src_counter = Counter()

    total_pkts = 0
    total_deauth = 0
    total_disassoc = 0
    total_eapol = 0

    min_ts = None
    max_ts = None

    for pkt in iter_packets(pcap_path):
        total_pkts += 1

        try:
            ts = float(pkt.time)
        except Exception:
            continue

        if min_ts is None or ts < min_ts:
            min_ts = ts
        if max_ts is None or ts > max_ts:
            max_ts = ts

        # 802.11
        if pkt.haslayer(Dot11):
            dot11 = pkt.getlayer(Dot11)

            # Deauthentication
            if int(dot11.type) == 0 and int(dot11.subtype) == 12:
                total_deauth += 1
                src = dot11.addr2 or "unknown"
                dst = dot11.addr1 or "ff:ff:ff:ff:ff:ff"
                floor_ts = bin_floor(ts, bin_size_sec)
                bins_raw[floor_ts].append((ts, src, dst, "DEAUTH"))
                src_counter[src] += 1

            # Disassociation
            elif int(dot11.type) == 0 and int(dot11.subtype) == 10:
                total_disassoc += 1
                src = dot11.addr2 or "unknown"
                dst = dot11.addr1 or "ff:ff:ff:ff:ff:ff"
                floor_ts = bin_floor(ts, bin_size_sec)
                bins_raw[floor_ts].append((ts, src, dst, "DISASSOC"))
                src_counter[src] += 1

        # EAPOL — handshake candidates
        if EAPOL_AVAILABLE and pkt.haslayer("EAPOL"):
            total_eapol += 1

    # формируем TimeBin[]
    bins: List[TimeBin] = []
    attack_detected = False
    first_attack_ts = None
    last_attack_ts = None

    for floor_ts in sorted(bins_raw.keys()):
        items = bins_raw[floor_ts]
        count = len(items)
        srcs = [i[1] for i in items]
        uniq = len(set(srcs))
        top = Counter(srcs).most_common(5)
        alert = count >= threshold

        if alert:
            attack_detected = True
            if first_attack_ts is None:
                first_attack_ts = floor_ts
            last_attack_ts = floor_ts

        bins.append(
            TimeBin(
                start_ts=floor_ts,
                count=count,
                unique_sources=uniq,
                top_sources=top,
                alert=alert,
            )
        )

    duration = (max_ts - min_ts) if (min_ts is not None and max_ts is not None) else 0.0

    return FileSummary(
        file_path=os.path.abspath(pcap_path),
        duration_sec=duration,
        total_packets=total_pkts,
        total_deauth=total_deauth,
        total_disassoc=total_disassoc,
        total_eapol=total_eapol,
        bins=bins,
        bin_size_sec=bin_size_sec,
        threshold=threshold,
        attack_detected=attack_detected,
        first_attack_ts=first_attack_ts,
        last_attack_ts=last_attack_ts,
    )


def find_pcaps(input_dir: str) -> List[str]:
    result = []
    for root, _, files in os.walk(input_dir):
        for name in files:
            if name.lower().endswith((".pcap", ".pcapng")):
                result.append(os.path.join(root, name))
    return sorted(result)


def analyze_directory(input_dir: str, bin_size_sec: int, threshold: int) -> BatchSummary:
    pcaps = find_pcaps(input_dir)
    summaries: List[FileSummary] = []
    for pcap in pcaps:
        summary = analyze_file(pcap, bin_size_sec, threshold)
        summaries.append(summary)
    return BatchSummary(input_dir=os.path.abspath(input_dir), files=summaries)

