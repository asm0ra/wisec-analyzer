import csv
import os
from datetime import datetime, timezone
from typing import List

from .models import FileSummary, BatchSummary, TimeBin

try:
    import pandas as pd
    import matplotlib.pyplot as plt
    PANDAS_AVAILABLE = True
except Exception:
    PANDAS_AVAILABLE = False


def human_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def export_file_bins_csv(summary: FileSummary, out_csv: str):
    fieldnames = [
        "time_iso",
        "time_epoch",
        "count",
        "unique_srcs",
        "top_sources",
        "alert",
    ]
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for b in summary.bins:
            writer.writerow(
                {
                    "time_iso": human_ts(b.start_ts),
                    "time_epoch": b.start_ts,
                    "count": b.count,
                    "unique_srcs": b.unique_sources,
                    "top_sources": ";".join(
                        [f"{s}:{c}" for s, c in b.top_sources]
                    ),
                    "alert": int(b.alert),
                }
            )


def export_file_text_report(summary: FileSummary, out_txt: str):
    with open(out_txt, "w", encoding="utf-8") as f:
        f.write("WiSecAnalyzer - File Report\n")
        f.write(f"File: {summary.file_path}\n")
        f.write(f"Duration: {summary.duration_sec:.2f} s\n")
        f.write(f"Total packets: {summary.total_packets}\n")
        f.write(f"Total deauth: {summary.total_deauth}\n")
        f.write(f"Total disassoc: {summary.total_disassoc}\n")
        f.write(f"Total EAPOL: {summary.total_eapol}\n")
        f.write(f"Bin size: {summary.bin_size_sec} s\n")
        f.write(f"Threshold: {summary.threshold}\n")
        f.write(f"Attack detected: {summary.attack_detected}\n")
        if summary.first_attack_ts is not None:
            f.write(
                f"First attack bin: {human_ts(summary.first_attack_ts)}\n"
            )
        if summary.last_attack_ts is not None:
            f.write(
                f"Last attack bin: {human_ts(summary.last_attack_ts)}\n"
            )
        f.write("\nTop bins (alerts only):\n")
        for b in summary.bins:
            if b.alert:
                f.write(
                    f"- {human_ts(b.start_ts)} | count={b.count} "
                    f"| unique_srcs={b.unique_sources} "
                    f"| top={b.top_sources}\n"
                )


def export_file_plot(summary: FileSummary, out_png: str):
    if not PANDAS_AVAILABLE:
        print("pandas/matplotlib not available, skipping plot.")
        return
    if not summary.bins:
        print("No bins to plot.")
        return
    times = [datetime.fromtimestamp(b.start_ts, tz=timezone.utc) for b in summary.bins]
    counts = [b.count for b in summary.bins]
    plt.figure(figsize=(10, 4))
    plt.plot(times, counts, marker="o")
    plt.xlabel("Time (UTC)")
    plt.ylabel(f"Deauth/Disassoc frames per {summary.bin_size_sec}s")
    plt.title(os.path.basename(summary.file_path))
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(out_png)
    plt.close()


def export_batch_summary_csv(batch: BatchSummary, out_csv: str):
    fieldnames = [
        "file_path",
        "duration_sec",
        "total_packets",
        "total_deauth",
        "total_disassoc",
        "total_eapol",
        "attack_detected",
        "first_attack_ts_iso",
        "last_attack_ts_iso",
        "bin_size_sec",
        "threshold",
    ]
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for s in batch.files:
            writer.writerow(
                {
                    "file_path": s.file_path,
                    "duration_sec": s.duration_sec,
                    "total_packets": s.total_packets,
                    "total_deauth": s.total_deauth,
                    "total_disassoc": s.total_disassoc,
                    "total_eapol": s.total_eapol,
                    "attack_detected": int(s.attack_detected),
                    "first_attack_ts_iso": human_ts(s.first_attack_ts)
                    if s.first_attack_ts is not None
                    else "",
                    "last_attack_ts_iso": human_ts(s.last_attack_ts)
                    if s.last_attack_ts is not None
                    else "",
                    "bin_size_sec": s.bin_size_sec,
                    "threshold": s.threshold,
                }
            )


def export_batch_text_report(batch: BatchSummary, out_txt: str):
    with open(out_txt, "w", encoding="utf-8") as f:
        f.write("WiSecAnalyzer - Batch Report\n")
        f.write(f"Input dir: {batch.input_dir}\n")
        f.write(f"Files analyzed: {len(batch.files)}\n\n")

        total_deauth_all = sum(s.total_deauth for s in batch.files)
        total_disassoc_all = sum(s.total_disassoc for s in batch.files)
        total_eapol_all = sum(s.total_eapol for s in batch.files)

        f.write(f"Total deauth (all files): {total_deauth_all}\n")
        f.write(f"Total disassoc (all files): {total_disassoc_all}\n")
        f.write(f"Total EAPOL (all files): {total_eapol_all}\n\n")

        f.write("Files with detected attacks:\n")
        for s in batch.files:
            if s.attack_detected:
                f.write(
                    f"- {s.file_path} | deauth={s.total_deauth} "
                    f"| disassoc={s.total_disassoc}\n"
                )

        f.write("\nTop 5 files by deauth count:\n")
        top_files = sorted(
            batch.files, key=lambda s: s.total_deauth, reverse=True
        )[:5]
        for s in top_files:
            f.write(
                f"- {s.file_path} | deauth={s.total_deauth} "
                f"| disassoc={s.total_disassoc}\n"
            )
