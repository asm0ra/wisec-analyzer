import click

from .core import analyze_file, analyze_directory


@click.group(help="WiSecAnalyzer - Wireless Security PCAP analyzer.")
def cli():
    """Root command group for WiSecAnalyzer CLI."""
    pass


@cli.command(name="analyze", help="Analyze a single PCAP file.")
@click.option(
    "-i",
    "--input",
    "input_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to a PCAP file.",
)
@click.option(
    "-b",
    "--bin",
    "bin_size",
    default=1,
    show_default=True,
    type=int,
    help="Bin size in seconds for event aggregation.",
)
@click.option(
    "-t",
    "--threshold",
    default=50,
    show_default=True,
    type=int,
    help="Event count threshold per bin for alerting.",
)
def analyze_command(input_path: str, bin_size: int, threshold: int):
    """
    Analyze a single PCAP file.

    All reports (CSV, text, plot) are written by core.analyze_file().
    """
    analyze_file(input_path, bin_size=float(bin_size), threshold=threshold)


@cli.command(name="batch", help="Analyze all PCAP files in a directory.")
@click.option(
    "-d",
    "--input-dir",
    "input_dir",
    required=True,
    type=click.Path(exists=True, file_okay=False),
    help="Directory containing .pcap files.",
)
@click.option(
    "-b",
    "--bin",
    "bin_size",
    default=1,
    show_default=True,
    type=int,
    help="Bin size in seconds for event aggregation.",
)
@click.option(
    "-t",
    "--threshold",
    default=50,
    show_default=True,
    type=int,
    help="Event count threshold per bin for alerting.",
)
def batch_command(input_dir: str, bin_size: int, threshold: int):
    """
    Analyze all PCAP files in the specified directory.
    """
    analyze_directory(input_dir, bin_size=float(bin_size), threshold=threshold)


def main():
    """Entry point for console_scripts."""
    cli()
