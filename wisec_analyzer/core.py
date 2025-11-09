import os
import csv
from datetime import datetime
from collections import Counter

from scapy.all import rdpcap, Dot11, EAPOL
import matplotlib.pyplot as plt


def _analyze_events(packets, bin_size: float, threshold: int):
    """
    Internal helper: extracts interesting wireless events (deauth, disassoc, EAPOL),
    aggregates them into time bins and returns stats.
    """

    total_packets = len(packets)
    total_deauth = 0
    total_disassoc = 0
    total_eapol = 0

    event_times = []          # timestamps of interesting events
    event_srcs = []           # corresponding source MACs

    start_time = None
    end_time = None

    for pkt in packets:
        # timestamp
        ts = float(getattr(pkt, "time", 0.0))
        if start_time is None:
            start_time = ts
        end_time = ts

        has_dot11 = pkt.haslayer(Dot11)
        has_eapol = pkt.haslayer(EAPOL)

        src_mac = None
        if has_dot11:
            d11 = pkt[Dot11]
            src_mac = getattr(d11, "addr2", None)

            # management frame type=0, subtype=12 => deauth
            if d11.type == 0 and d11.subtype == 12:
                total_deauth += 1
                event_times.append(ts)
                if src_mac:
                    event_srcs.append(src_mac)

            # management frame type=0, subtype=10 => disassoc
            if d11.type == 0 and d11.subtype == 10:
                total_disassoc += 1
                event_times.append(ts)
                if src_mac:
                    event_srcs.append(src_mac)

        if has_eapol:
            total_eapol += 1
            event_times.append(ts)
            if src_mac:
                event_srcs.append(src_mac)

    if start_time is None or end_time is None:
        return {
            "duration": 0.0,
            "total_packets": total_packets,
            "total_deauth": total_deauth,
            "total_disassoc": total_disassoc,
            "total_eapol": total_eapol,
            "bins": [],
            "alerts": [],
            "start_time": None,
            "end_time": None,
        }

    duration = end_time - start_time

    # if no interesting events, return empty bins
    if not event_times:
        return {
            "duration": duration,
            "total_packets": total_packets,
            "total_deauth": total_deauth,
            "total_disassoc": total_disassoc,
            "total_eapol": total_eapol,
            "bins": [],
            "alerts": [],
            "start_time": start_time,
            "end_time": end_time,
        }

    # aggregate into bins
    bin_counters = {}  # index -> (count, Counter(srcs))
    for ts, src in zip(event_times, event_srcs):
        idx = int((ts - start_time) / bin_size)
        if idx not in bin_counters:
            bin_counters[idx] = [0, Counter()]
        bin_counters[idx][0] += 1
        if src:
            bin_counters[idx][1][src] += 1

    bins = []
    for idx, (count, src_counter) in bin_counters.items():
        t_epoch = start_time + idx * bin_size
        t_iso = datetime.utcfromtimestamp(t_epoch).isoformat()
        unique_srcs = len(src_counter)
        if src_counter:
            # top 3 sources in "mac(count)" format
            top = ", ".join(
                f"{mac}({c})" for mac, c in src_counter.most_common(3)
            )
        else:
            top = ""
        alert = count >= threshold
        bins.append((t_iso, t_epoch, count, unique_srcs, top, alert))

    # sort by time
    bins.sort(key=lambda x: x[1])

    alerts = [b for b in bins if b[5]]

    return {
        "duration": duration,
        "total_packets": total_packets,
        "total_deauth": total_deauth,
        "total_disassoc": total_disassoc,
        "total_eapol": total_eapol,
        "bins": bins,
        "alerts": alerts,
        "start_time": start_time,
        "end_time": end_time,
    }


def _write_csv(out_csv: str, bins):
    with open(out_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            ["time_iso", "time_epoch", "count", "unique_srcs", "top_sources", "alert"]
        )
        for row in bins:
            writer.writerow(row)


def _write_report(out_report: str, pcap_path: str, stats, bin_size: float, threshold: int):
    with open(out_report, "w") as f:
        f.write("WiSecAnalyzer - File Report\n")
        f.write(f"File: {pcap_path}\n")
        f.write(f"Duration: {stats['duration']:.2f} s\n")
        f.write(f"Total packets: {stats['total_packets']}\n")
        f.write(f"Total deauth: {stats['total_deauth']}\n")
        f.write(f"Total disassoc: {stats['total_disassoc']}\n")
        f.write(f"Total EAPOL: {stats['total_eapol']}\n")
        f.write(f"Bin size: {bin_size} s\n")
        f.write(f"Threshold: {threshold}\n")
        f.write(f"Attack detected: {bool(stats['alerts'])}\n\n")

        f.write("Top bins (alerts only):\n")
        if stats["alerts"]:
            for t_iso, _, count, uniq, top, _ in stats["alerts"][:10]:
                f.write(
                    f"{t_iso} -> count={count}, unique_srcs={uniq}, top_sources={top}\n"
                )
        else:
            f.write("(none)\n")


def _plot_bins(out_plot: str, bins):
    """
    Always создаёт PNG:
    - если bins пустой -> картинка с текстом 'No abnormal activity detected'
    - если есть данные -> обычный line-plot.
    """
    if not bins:
        plt.figure(figsize=(8, 3))
        plt.text(
            0.5,
            0.5,
            "No abnormal activity detected",
            ha="center",
            va="center",
            fontsize=12,
            color="gray",
        )
        plt.title("WiSecAnalyzer - Empty Report")
        plt.axis("off")
        plt.tight_layout()
        plt.savefig(out_plot)
        plt.close()
        print(f"[+] Empty plot saved: {out_plot}")
        return

    times = [datetime.fromisoformat(b[0]) for b in bins]
    counts = [b[2] for b in bins]

    plt.figure(figsize=(10, 3))
    plt.plot(times, counts, linewidth=1)
    plt.fill_between(times, counts, alpha=0.3)
    plt.xlabel("Time (UTC)")
    plt.ylabel("Events per bin")
    plt.title("WiSecAnalyzer - Activity Timeline")
    plt.tight_layout()
    plt.savefig(out_plot)
    plt.close()
    print(f"[+] Plot saved: {out_plot}")


def analyze_file(pcap_path: str, bin_size: float = 1.0, threshold: int = 50):
    """
    Public API: analyze a single PCAP file.
    This is what wisec_analyzer.cli imports as analyze_file().
    """

    print(f"[+] Analyzing file: {pcap_path}")
    print(f"[+] Bin size: {bin_size}s, threshold: {threshold}")

    if not os.path.isfile(pcap_path):
        print(f"[!] File not found: {pcap_path}")
        return

    base_name = os.path.basename(pcap_path).replace(".pcap", "")
    out_dir = "out_single"
    os.makedirs(out_dir, exist_ok=True)

    out_csv = os.path.join(out_dir, f"{base_name}_bins.csv")
    out_report = os.path.join(out_dir, f"{base_name}_report.txt")
    out_plot = os.path.join(out_dir, f"{base_name}_plot.png")

    packets = rdpcap(pcap_path)
    stats = _analyze_events(packets, bin_size=bin_size, threshold=threshold)

    _write_csv(out_csv, stats["bins"])
    _write_report(out_report, pcap_path, stats, bin_size, threshold)
    _plot_bins(out_plot, stats["bins"])

    print(f"[+] CSV: {out_csv}")
    print(f"[+] Report: {out_report}")
    print(
        f"[+] Totals -> deauth={stats['total_deauth']}, "
        f"disassoc={stats['total_disassoc']}, eapol={stats['total_eapol']}"
    )


def analyze_directory(input_dir: str, bin_size: float = 1.0, threshold: int = 50):
    """
    Public API: analyze all PCAP files in a given directory.
    This is what wisec_analyzer.cli imports as analyze_directory().
    """

    if not os.path.isdir(input_dir):
        print(f"[!] Not a directory: {input_dir}")
        return

    out_dir = f"out_{os.path.basename(os.path.abspath(input_dir))}"
    os.makedirs(out_dir, exist_ok=True)

    pcap_files = [
        f
        for f in os.listdir(input_dir)
        if f.lower().endswith(".pcap")
    ]

    if not pcap_files:
        print(f"[!] No .pcap files found in {input_dir}")
        return

    print(f"[+] Found {len(pcap_files)} PCAP files in {input_dir}")
    for name in pcap_files:
        pcap_path = os.path.join(input_dir, name)
        print(f"\n[+] Processing {pcap_path}")
        # временно меняем out_dir для каждого файла
        base_name = os.path.basename(pcap_path).replace(".pcap", "")
        csv_path = os.path.join(out_dir, f"{base_name}_bins.csv")
        report_path = os.path.join(out_dir, f"{base_name}_report.txt")
        plot_path = os.path.join(out_dir, f"{base_name}_plot.png")

        packets = rdpcap(pcap_path)
        stats = _analyze_events(packets, bin_size=bin_size, threshold=threshold)

        _write_csv(csv_path, stats["bins"])
        _write_report(report_path, pcap_path, stats, bin_size, threshold)
        _plot_bins(plot_path, stats["bins"])

        print(
            f"[+] {name}: deauth={stats['total_deauth']}, "
            f"disassoc={stats['total_disassoc']}, eapol={stats['total_eapol']}"
        )
