#!/usr/bin/env python3
"""
Professional TCP Port Scanner
==============================

A multithreaded TCP port scanner built for cybersecurity portfolios.

LEGAL / ETHICAL DISCLAIMER
---------------------------
This tool is intended STRICTLY for educational purposes and for use
against systems you own or have explicit written authorization to test.
Scanning networks or hosts without permission may be illegal under
computer misuse laws (e.g., CFAA in the US, Computer Misuse Act in the
UK, and equivalent legislation elsewhere). The author assumes no
liability for misuse of this software.

Author: Senior Cybersecurity Engineer (portfolio project)
"""

import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# colorama gives us cross-platform (Windows/Linux/Mac) colored terminal text.
from colorama import Fore, Style, init

# init(autoreset=True) makes sure color codes auto-reset after every print,
# so we don't have to manually append Style.RESET_ALL everywhere.
init(autoreset=True)

# --------------------------------------------------------------------------
# CONSTANTS
# --------------------------------------------------------------------------

# A small lookup table of common ports -> service names.
# This is intentionally a static dictionary (no external "nmap-services"
# file) to keep the tool dependency-free and standard-library friendly.
COMMON_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    123: "NTP",
    135: "MS-RPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    179: "BGP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    515: "LPD/Printer",
    587: "SMTP-Submission",
    631: "IPP/CUPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle-DB",
    2049: "NFS",
    2222: "SSH-Alt",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

# Default socket timeout (seconds). Short enough to keep scans fast,
# long enough to avoid false "filtered" results on slow links.
DEFAULT_TIMEOUT = 1.0

# Thread-safety lock used when printing from multiple worker threads,
# so output lines don't interleave/garble on the terminal.
print_lock = threading.Lock()


# --------------------------------------------------------------------------
# BANNER / UI HELPERS
# --------------------------------------------------------------------------

def print_banner():
    """Print a clean ASCII banner for the CLI tool."""
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}=============================================
        PYTHON TCP PORT SCANNER
   Educational & Authorized Use Only
============================================={Style.RESET_ALL}
"""
    print(banner)


def print_progress(current, total, bar_length=40):
    """
    Render a simple in-place text progress bar to stdout.

    Args:
        current (int): number of ports scanned so far.
        total (int): total number of ports to scan.
        bar_length (int): width of the progress bar in characters.
    """
    # Guard against division by zero if the port range is empty.
    if total == 0:
        return

    progress = current / total
    filled = int(bar_length * progress)
    bar = "#" * filled + "-" * (bar_length - filled)

    # '\r' returns the cursor to the start of the line so the bar
    # appears to update in place rather than printing a new line
    # for every completed port.
    with print_lock:
        sys.stdout.write(
            f"\r{Fore.YELLOW}Scanning: |{bar}| "
            f"{current}/{total} ports ({progress * 100:.1f}%){Style.RESET_ALL}"
        )
        sys.stdout.flush()


# --------------------------------------------------------------------------
# CORE NETWORKING FUNCTIONS
# --------------------------------------------------------------------------

def resolve_target(target):
    """
    Resolve a hostname (e.g. 'example.com') to an IPv4 address.
    If the target is already an IP address, socket.gethostbyname()
    simply returns it unchanged.

    Args:
        target (str): hostname or IP address supplied by the user.

    Returns:
        str: resolved IPv4 address.

    Raises:
        SystemExit: if the hostname cannot be resolved (invalid target).
    """
    try:
        ip_address = socket.gethostbyname(target)
        return ip_address
    except socket.gaierror:
        # gaierror = "getaddrinfo error" -> DNS resolution failed.
        print(f"{Fore.RED}[!] Could not resolve hostname: {target}")
        print(f"{Fore.RED}[!] Please check the target and try again.")
        sys.exit(1)


def scan_port(ip_address, port, timeout=DEFAULT_TIMEOUT):
    """
    Attempt a TCP connect() to a single port and classify its state.

    We use a full TCP connect scan (as opposed to a raw SYN scan) because
    connect() only requires standard user-level sockets -- no raw socket
    / root privileges needed, which keeps this tool fully cross-platform
    and dependency-free.

    Args:
        ip_address (str): resolved target IP.
        port (int): TCP port number to test.
        timeout (float): socket timeout in seconds.

    Returns:
        tuple: (port, state, service) where state is one of
               'open', 'closed', or 'filtered'.
    """
    # AF_INET  -> IPv4
    # SOCK_STREAM -> TCP
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    state = "closed"
    try:
        # connect_ex() returns an error indicator instead of raising an
        # exception, which is more efficient for scanning large ranges.
        result = sock.connect_ex((ip_address, port))

        if result == 0:
            # 0 means the TCP handshake completed successfully -> port open.
            state = "open"
        else:
            # Non-zero result usually means the remote host actively
            # refused the connection (RST received) -> port closed.
            state = "closed"

    except socket.timeout:
        # No response at all within the timeout window typically means
        # a firewall/ACL is silently dropping packets -> filtered.
        state = "filtered"

    except socket.error:
        # Covers other low-level socket errors (e.g., network unreachable,
        # host down). We conservatively classify these as filtered since
        # we cannot confirm the port is actually closed.
        state = "filtered"

    finally:
        # Always release the socket resource, even if an exception occurred.
        sock.close()

    service = COMMON_PORTS.get(port, "Unknown")
    return port, state, service


# --------------------------------------------------------------------------
# SCAN ORCHESTRATION
# --------------------------------------------------------------------------

def run_scan(ip_address, start_port, end_port, max_threads=100, timeout=DEFAULT_TIMEOUT):
    """
    Orchestrate a multithreaded scan across a range of ports.

    Uses ThreadPoolExecutor to parallelize socket connections, which is
    the dominant bottleneck in a port scan (I/O-bound, network latency).

    Args:
        ip_address (str): resolved target IP.
        start_port (int): first port in range (inclusive).
        end_port (int): last port in range (inclusive).
        max_threads (int): maximum concurrent worker threads.
        timeout (float): per-connection socket timeout.

    Returns:
        list[tuple]: list of (port, state, service) results, sorted by port.
    """
    ports = list(range(start_port, end_port + 1))
    total_ports = len(ports)
    results = []
    completed = 0

    # ThreadPoolExecutor manages a pool of worker threads for us and
    # handles task scheduling/cleanup automatically via the context manager.
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        # Submit all scan_port() tasks and map each future back to its port.
        future_to_port = {
            executor.submit(scan_port, ip_address, port, timeout): port
            for port in ports
        }

        # as_completed() yields futures as soon as they finish, letting us
        # update the progress bar in real time rather than waiting for
        # every thread to finish sequentially.
        for future in as_completed(future_to_port):
            try:
                port, state, service = future.result()
                results.append((port, state, service))
            except Exception as exc:
                # Defensive catch-all: log unexpected per-port failures
                # without crashing the entire scan.
                port = future_to_port[future]
                results.append((port, "error", str(exc)))

            completed += 1
            print_progress(completed, total_ports)

    # Clear the progress bar line and move to a new line before printing
    # results.
    print()
    results.sort(key=lambda item: item[0])
    return results


# --------------------------------------------------------------------------
# INPUT / VALIDATION HELPERS
# --------------------------------------------------------------------------

def get_user_input():
    """
    Prompt the user for target and port range, with basic validation.

    Returns:
        tuple: (target, start_port, end_port)
    """
    target = input(f"{Fore.CYAN}Enter target IP or hostname: {Style.RESET_ALL}").strip()
    if not target:
        print(f"{Fore.RED}[!] Target cannot be empty.")
        sys.exit(1)

    try:
        start_port = int(
            input(f"{Fore.CYAN}Enter start port (1-65535): {Style.RESET_ALL}").strip()
        )
        end_port = int(
            input(f"{Fore.CYAN}Enter end port (1-65535): {Style.RESET_ALL}").strip()
        )
    except ValueError:
        print(f"{Fore.RED}[!] Ports must be valid integers.")
        sys.exit(1)

    # Validate the port range boundaries and ordering.
    if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
        print(f"{Fore.RED}[!] Ports must be between 1 and 65535.")
        sys.exit(1)

    if start_port > end_port:
        print(f"{Fore.RED}[!] Start port cannot be greater than end port.")
        sys.exit(1)

    return target, start_port, end_port


# --------------------------------------------------------------------------
# REPORTING
# --------------------------------------------------------------------------

def display_results(results, ip_address, target, duration):
    """
    Print a formatted, color-coded summary of scan results to the console.

    Args:
        results (list[tuple]): (port, state, service) tuples.
        ip_address (str): resolved IP that was scanned.
        target (str): original user-supplied target.
        duration (float): total scan time in seconds.
    """
    open_ports = [r for r in results if r[1] == "open"]
    closed_ports = [r for r in results if r[1] == "closed"]
    filtered_ports = [r for r in results if r[1] == "filtered"]

    print(f"\n{Fore.CYAN}{Style.BRIGHT}===== SCAN RESULTS ====={Style.RESET_ALL}")
    print(f"Target        : {target} ({ip_address})")
    print(f"Ports scanned : {len(results)}")
    print(f"Duration      : {duration:.2f} seconds\n")

    if open_ports:
        print(f"{Fore.GREEN}{Style.BRIGHT}OPEN PORTS:{Style.RESET_ALL}")
        for port, state, service in open_ports:
            print(f"{Fore.GREEN}  [+] Port {port:<6} OPEN     ({service}){Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[i] No open ports found.{Style.RESET_ALL}")

    print(f"\n{Fore.RED}CLOSED PORTS : {len(closed_ports)}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}FILTERED PORTS: {len(filtered_ports)}{Style.RESET_ALL}")


def save_report(results, ip_address, target, duration, start_port, end_port):
    """
    Save scan results to a timestamped .txt report file.

    Args:
        results (list[tuple]): (port, state, service) tuples.
        ip_address (str): resolved IP that was scanned.
        target (str): original user-supplied target.
        duration (float): total scan time in seconds.
        start_port (int): first port scanned.
        end_port (int): last port scanned.

    Returns:
        str: filename of the generated report.
    """
    # Timestamp format avoids filesystem-illegal characters (no ':').
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_report_{target}_{timestamp}.txt"

    open_ports = [r for r in results if r[1] == "open"]
    closed_ports = [r for r in results if r[1] == "closed"]
    filtered_ports = [r for r in results if r[1] == "filtered"]

    try:
        with open(filename, "w", encoding="utf-8") as report_file:
            report_file.write("=" * 50 + "\n")
            report_file.write("       TCP PORT SCAN REPORT\n")
            report_file.write("=" * 50 + "\n\n")
            report_file.write(f"Target          : {target}\n")
            report_file.write(f"Resolved IP     : {ip_address}\n")
            report_file.write(f"Port Range      : {start_port}-{end_port}\n")
            report_file.write(f"Scan Date       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            report_file.write(f"Duration        : {duration:.2f} seconds\n")
            report_file.write(f"Total Ports     : {len(results)}\n")
            report_file.write(f"Open Ports      : {len(open_ports)}\n")
            report_file.write(f"Closed Ports    : {len(closed_ports)}\n")
            report_file.write(f"Filtered Ports  : {len(filtered_ports)}\n\n")

            report_file.write("-" * 50 + "\n")
            report_file.write("DETAILED RESULTS\n")
            report_file.write("-" * 50 + "\n")
            for port, state, service in results:
                report_file.write(f"Port {port:<6} | {state.upper():<8} | {service}\n")

            report_file.write("\n" + "=" * 50 + "\n")
            report_file.write("Scan performed for educational/authorized use only.\n")

        return filename

    except OSError as exc:
        # Catches disk-full, permission-denied, invalid-path, etc.
        print(f"{Fore.RED}[!] Failed to write report file: {exc}")
        return None


# --------------------------------------------------------------------------
# MAIN ENTRY POINT
# --------------------------------------------------------------------------

def main():
    """Main program flow: banner -> input -> resolve -> scan -> report."""
    print_banner()

    print(f"{Fore.YELLOW}[!] LEGAL NOTICE: Only scan systems you own or are")
    print(f"{Fore.YELLOW}    explicitly authorized to test.{Style.RESET_ALL}\n")

    # Step 1: Gather and validate user input.
    target, start_port, end_port = get_user_input()

    # Step 2: Resolve hostname -> IP (also validates reachability of DNS).
    print(f"\n{Fore.CYAN}[*] Resolving target...{Style.RESET_ALL}")
    ip_address = resolve_target(target)
    print(f"{Fore.GREEN}[+] Resolved {target} -> {ip_address}{Style.RESET_ALL}\n")

    # Step 3: Run the multithreaded scan, timing the whole operation.
    print(f"{Fore.CYAN}[*] Starting scan of {start_port}-{end_port} "
          f"({end_port - start_port + 1} ports)...{Style.RESET_ALL}\n")

    start_time = time.time()
    try:
        results = run_scan(ip_address, start_port, end_port)
    except KeyboardInterrupt:
        # Allow the user to Ctrl+C out of a long scan cleanly.
        print(f"\n{Fore.RED}[!] Scan interrupted by user.{Style.RESET_ALL}")
        sys.exit(1)
    duration = time.time() - start_time

    # Step 4: Display results in the terminal.
    display_results(results, ip_address, target, duration)

    # Step 5: Persist results to a timestamped report file.
    filename = save_report(results, ip_address, target, duration, start_port, end_port)
    if filename:
        print(f"\n{Fore.CYAN}[+] Report saved to: {filename}{Style.RESET_ALL}")


if __name__ == "__main__":
    # Wrap the whole program so an unexpected error never dumps an ugly
    # raw traceback on the user -- we print something readable instead.
    try:
        main()
    except Exception as unexpected_error:
        print(f"{Fore.RED}[!] Unexpected error: {unexpected_error}{Style.RESET_ALL}")
        sys.exit(1)
