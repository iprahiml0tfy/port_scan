# Python TCP Port Scanner

A fast, multithreaded TCP port scanner written in pure Python, built as a cybersecurity portfolio project. It performs TCP connect scans against a single target, classifies each port as **open**, **closed**, or **filtered**, identifies common services, and exports a timestamped report.

> **Disclaimer:** This tool is for **educational purposes and authorized security testing only**. Scanning systems without explicit permission is illegal in most jurisdictions. See [Disclaimer](#disclaimer) below.

---

## Features

- 🎯 Scan a single IP address or hostname (with automatic DNS resolution)
- 🔢 User-defined custom port range (1–65535)
- 🟢 Detects **open**, **closed**, and **filtered** port states
- 🏷️ Maps common ports to known service names (HTTP, SSH, FTP, RDP, MySQL, etc.)
- ⚡ Multithreaded scanning via `ThreadPoolExecutor` for high performance
- 📊 Live progress bar during the scan
- ⏱️ Scan duration measurement
- 🎨 Colorized CLI output using `colorama`
- 📄 Automatic timestamped `.txt` report generation
- 🛡️ Graceful handling of socket timeouts, DNS failures, and interruptions (Ctrl+C)
- 🐍 Built entirely on Python's standard library (only `colorama` is an external dependency, purely for CLI colors)

---

## Installation

**Requirements:** Python 3.8+

1. Clone or download this project:
   ```bash
   git clone <your-repo-url>
   cd port-scanner
   ```

2. (Optional but recommended) create a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate      # Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage

Run the script directly:

```bash
python3 port_scanner.py
```

You will be prompted interactively:

```
Enter target IP or hostname: scanme.nmap.org
Enter start port (1-65535): 1
Enter end port (1-65535): 1024
```

The scanner will:
1. Resolve the hostname to an IP address.
2. Scan the specified port range using multiple threads.
3. Display a live progress bar.
4. Print a color-coded summary (open/closed/filtered).
5. Save a full report to a timestamped `.txt` file in the current directory.

> ⚠️ Only scan hosts you own or are explicitly authorized to test (e.g., `scanme.nmap.org`, which is Nmap's official public test target, or your own local machine/lab).

---

## Example Output

```
=============================================
        PYTHON TCP PORT SCANNER
   Educational & Authorized Use Only
=============================================

[!] LEGAL NOTICE: Only scan systems you own or are
    explicitly authorized to test.

Enter target IP or hostname: scanme.nmap.org
Enter start port (1-65535): 1
Enter end port (1-65535): 100

[*] Resolving target...
[+] Resolved scanme.nmap.org -> 45.33.32.156

[*] Starting scan of 1-100 (100 ports)...

Scanning: |########################################| 100/100 ports (100.0%)

===== SCAN RESULTS =====
Target        : scanme.nmap.org (45.33.32.156)
Ports scanned : 100
Duration      : 2.14 seconds

OPEN PORTS:
  [+] Port 22     OPEN     (SSH)
  [+] Port 80     OPEN     (HTTP)

CLOSED PORTS : 95
FILTERED PORTS: 3

[+] Report saved to: scan_report_scanme.nmap.org_20260718_101530.txt
```

Example report file (`scan_report_<target>_<timestamp>.txt`):

```
==================================================
       TCP PORT SCAN REPORT
==================================================

Target          : scanme.nmap.org
Resolved IP     : 45.33.32.156
Port Range      : 1-100
Scan Date       : 2026-07-18 10:15:30
Duration        : 2.14 seconds
Total Ports     : 100
Open Ports      : 2
Closed Ports    : 95
Filtered Ports  : 3

--------------------------------------------------
DETAILED RESULTS
--------------------------------------------------
Port 22     | OPEN     | SSH
Port 80     | OPEN     | HTTP
Port 25     | FILTERED | SMTP
...
```

---

## Project Structure

```
port-scanner/
│
├── port_scanner.py      # Main application (all logic, single-file)
├── requirements.txt      # External dependency (colorama)
├── README.md              # Project documentation
└── scan_report_*.txt     # Auto-generated reports (created after each scan)
```

---

## Disclaimer

This project is provided **strictly for educational and authorized security testing purposes**. By using this tool you agree that:

- You will only scan systems, networks, or hosts that you **own** or have **explicit, written authorization** to test.
- Unauthorized port scanning may violate laws such as the **Computer Fraud and Abuse Act (CFAA)** in the United States, the **Computer Misuse Act 1990** in the United Kingdom, and similar legislation in other countries.
- The author(s) and contributors accept **no liability** for any misuse, damage, or legal consequences resulting from the use of this software.
- Good practice for legally testing this tool includes using dedicated lab environments (e.g., a local VM), your own infrastructure, or public test targets designated for scanning practice such as `scanme.nmap.org`.

**Use responsibly.**
