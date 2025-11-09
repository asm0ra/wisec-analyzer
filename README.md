# WiSecAnalyzer  
### Wireless Security PCAP Analysis Tool

WiSecAnalyzer is a cross-platform command-line application for offline analysis of wireless network captures (PCAP files).  
It was developed to support research and education in the field of wireless information security and protocol analysis.

---

## 1. Overview

WiSecAnalyzer performs structural and statistical analysis of captured Wi-Fi traffic.  
It classifies frames by type and subtype, identifies suspicious activity such as deauthentication or probe floods, and generates both text and CSV reports for further processing.

Main features:

- Analysis of IEEE 802.11 traffic in PCAP files (WPA2, WPA3, open networks).  
- Automatic classification of management, control, and data frames.  
- Detection of potential security anomalies.  
- Generation of human-readable and machine-readable reports.  
- Cross-platform CLI interface for Linux and Windows.  
- Modular design for integration with other research tools.

---

## 2. System Requirements

- **Python ≥ 3.10**
- **Dependencies (installed automatically):**
  - scapy
  - pyshark
  - matplotlib
  - pandas
  - click
- **Tested environments:**
  - Linux — Arch Linux, Ubuntu 22+, Fedora 40+
  - Windows 10 / 11

## 3. Installation Instructions

### 3.1 Linux / macOS

```bash
# 1) Install system packages
sudo apt install python3 python3-venv python3-pip git -y
# or on Arch Linux:
# sudo pacman -S python python-pip git

# 2) Clone the repository
git clone https://github.com/asm0ra/wisec-analyzer.git
cd wisec-analyzer

# 3) Create and activate a virtual environment
python -m venv venv
source venv/bin/activate

# 4) Install WiSecAnalyzer inside the environment
pip install -e .

# 5) Verify installation
wisec-analyzer --help
```

### 3.2 Windows (PowerShell)

```powershell
# 1) Install prerequisites
#    - Python 3.10+ (check "Add Python to PATH" during installation)
#    - Git for Windows

# 2) Clone the repository
git clone https://github.com/asm0ra/wisec-analyzer.git
cd wisec-analyzer

# 3) Create and activate a virtual environment
python -m venv venv
.\venv\Scripts\activate

# 4) Install WiSecAnalyzer
pip install -e .

# 5) Verify installation
wisec-analyzer --help
```

If the command is not found after installation, ensure that  
`%USERPROFILE%\AppData\Local\Programs\Python\PythonXX\Scripts` (Windows) or  
`~/.local/bin` (Linux) is included in the system PATH.

---

## 4. Command-Line Usage

### 4.1 Analyze a Single Capture

```bash
wisec-analyzer analyze -i path/to/capture.pcap
```

Output files in the current directory:

- `capture_report.txt` – textual summary  
- `capture_bins.csv` – statistical data
- `capture_plot.png` – activity timeline visualization

### 4.2 Batch Analysis of a Directory

```bash
wisec-analyzer batch -d ./captures/
```

Results are saved in the subfolder `out_<directory_name>`.

---

## 5. Project Structure

```
wisec-analyzer/
│
├── wisec_analyzer/           # Source package
│   ├── __init__.py
│   ├── cli.py                # Command-line interface
│   ├── core.py               # Core analysis logic
│   ├── models.py             # Data structures and frame classes
│   └── reporting.py          # Report generation
│
├── main.py                   # Entry point for testing
├── pyproject.toml            # Build configuration
├── LICENSE                   # MIT License
├── README.md                 # Documentation
└── out_4sics/                # Example output reports
```

---

## 6. Example Report (Text Format)

```
=== WiSecAnalyzer Report ===
File: example_capture.pcap
Total packets: 15,423
Management frames: 4,235
Data frames: 10,753
Control frames: 435

Detected events:
 - Deauthentication flood (45 packets)
 - Probe request flood (31 packets)
```

---

## 7. Citation and Attribution

If you use WiSecAnalyzer in academic or professional research, please cite as:

> Gabdullin, A. (2025). *Analysis of Modern Wireless Network Security Protocols and Prospects for Their Development.*  
> WiSecAnalyzer tool, GitHub repository: https://github.com/asm0ra/wisec-analyzer

---

## 8. License

WiSecAnalyzer is distributed under the **MIT License**.  
You are free to use, modify, and distribute this software with proper attribution.

---

## 9. Author

**Abzal Gabdullin**  
Master’s Program in Information Security Systems  
L.N. Gumilyov Eurasian National University, Astana  
Email: anchorite.exe@gmail.com  
GitHub: https://github.com/asm0ra
