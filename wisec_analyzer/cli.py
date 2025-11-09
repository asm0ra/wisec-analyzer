import os
import click

from .core import analyze_file, analyze_directory
from .reporting import (
    export_file_bins_csv,
    export_file_text_report,
    export_file_plot,
    export_batch_summary_csv,
    export_batch_text_report,
)


def parse_bin_arg(bin_arg: str) -> int:
    # "1s", "5s", "1m" -> секунды
    s = bin_arg.strip().lower()
    if s.endswith("s"):
        return int(s[:-1])
    if s.endswith("m"):
        return int(s[:-1]) * 60
    return int(s)


@click.group()
def cli():
    """WiSecAnalyzer - Wireless Security PCAP analyzer."""
    pass


@cli.command()
@click.option(
    "--input",
    "-i",
    "pcap_path",
    required=True,
    type=click.Path(exists=True),
    help="Input PCAP/PCAPNG file",
)
@click.option(
    "--out-dir",
    "-o",
    "out_dir",
    default="out_single",
    help="Directory for output files",
)
@click.option(
    "--bin",
    "bin_arg",
    default="1s",
    help="Bin size (e.g. 1s, 5s, 1m)",
)
@click.option(
    "--threshold",
    "-t",
    default=50,
    type=int,
    help="Threshold (frames per bin) for alert",
)
@click.option(
    "--no-plot",
    is_flag=True,
    help="Do not generate PNG plot",
)
def analyze(pcap_path, out_dir, bin_arg, threshold, no_plot):
    """Analyze a single PCAP file."""
    bin_size_sec = parse_bin_arg(bin_arg)
    os.makedirs(out_dir, exist_ok=True)

    click.echo(f"[+] Analyzing file: {pcap_path}")
    click.echo(f"[+] Bin size: {bin_size_sec}s, threshold: {threshold}")

    summary = analyze_file(pcap_path, bin_size_sec, threshold)

    base_name = os.path.splitext(os.path.basename(pcap_path))[0]
    csv_path = os.path.join(out_dir, f"{base_name}_bins.csv")
    txt_path = os.path.join(out_dir, f"{base_name}_report.txt")
    png_path = os.path.join(out_dir, f"{base_name}_plot.png")

    export_file_bins_csv(summary, csv_path)
    export_file_text_report(summary, txt_path)
    if not no_plot:
        export_file_plot(summary, png_path)

    click.echo(f"[+] CSV: {csv_path}")
    click.echo(f"[+] Report: {txt_path}")
    if not no_plot:
        click.echo(f"[+] Plot: {png_path}")
    click.echo(
        f"[+] Totals -> deauth={summary.total_deauth}, "
        f"disassoc={summary.total_disassoc}, eapol={summary.total_eapol}"
    )


@cli.command()
@click.option(
    "--input-dir",
    "-i",
    "input_dir",
    required=True,
    type=click.Path(exists=True),
    help="Directory with PCAP/PCAPNG files",
)
@click.option(
    "--out-dir",
    "-o",
    "out_dir",
    default="out_batch",
    help="Directory for batch output",
)
@click.option(
    "--bin",
    "bin_arg",
    default="1s",
    help="Bin size (e.g. 1s, 5s, 1m)",
)
@click.option(
    "--threshold",
    "-t",
    default=50,
    type=int,
    help="Threshold (frames per bin) for alert",
)
@click.option(
    "--no-per-file-plot",
    is_flag=True,
    help="Do not generate per-file PNG plots",
)
def batch(input_dir, out_dir, bin_arg, threshold, no_per_file_plot):
    """Analyze all PCAP files in a directory."""
    from .core import find_pcaps

    bin_size_sec = parse_bin_arg(bin_arg)
    os.makedirs(out_dir, exist_ok=True)

    pcaps = find_pcaps(input_dir)
    if not pcaps:
        click.echo("No PCAP/PCAPNG files found.")
        return

    click.echo(f"[+] Found {len(pcaps)} pcap files in {input_dir}")
    click.echo(f"[+] Bin size: {bin_size_sec}s, threshold: {threshold}")

    from .core import analyze_file
    from .models import BatchSummary

    batch_summary = BatchSummary(input_dir=input_dir, files=[])

    for p in pcaps:
        click.echo(f"[+] Analyzing {p} ...")
        summary = analyze_file(p, bin_size_sec, threshold)
        batch_summary.files.append(summary)

        base_name = os.path.splitext(os.path.basename(p))[0]
        csv_path = os.path.join(out_dir, f"{base_name}_bins.csv")
        txt_path = os.path.join(out_dir, f"{base_name}_report.txt")
        png_path = os.path.join(out_dir, f"{base_name}_plot.png")

        export_file_bins_csv(summary, csv_path)
        export_file_text_report(summary, txt_path)
        if not no_per_file_plot:
            export_file_plot(summary, png_path)

    # общий batch CSV + общий текстовый отчёт
    batch_csv = os.path.join(out_dir, "batch_summary.csv")
    batch_txt = os.path.join(out_dir, "batch_report.txt")
    export_batch_summary_csv(batch_summary, batch_csv)
    export_batch_text_report(batch_summary, batch_txt)

    click.echo(f"[+] Batch CSV: {batch_csv}")
    click.echo(f"[+] Batch report: {batch_txt}")

def main():
    """Entry point for console_scripts."""
    cli()
