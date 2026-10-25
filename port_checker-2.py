#!/usr/bin/env python3
"""
Port Status Checker
--------------------
A network socket utility that checks open ports and basic service
responsiveness on a target host using TCP connection handshakes.

IMPORTANT: Only scan hosts you own or have explicit permission to test.
Scanning systems without authorization may violate computer misuse laws.

Usage:
    python port_checker.py -H 127.0.0.1 -p 1-1024
    python port_checker.py -H example.com -p 22,80,443,3306
    python port_checker.py -H 127.0.0.1 -p 1-100 -t 0.5

Author: <your name>
"""

import argparse
import socket
import sys
import time

# ---------------------------------------------------------------------------
# Step 1: socket programming library is imported above (socket module)
# ---------------------------------------------------------------------------

# A small lookup of well-known ports, used only to label results in the
# output table (does not affect the scan logic itself).
COMMON_SERVICES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
}


# ---------------------------------------------------------------------------
# Step 2: accept target IP address and port range inputs
# ---------------------------------------------------------------------------
def parse_ports(port_arg: str) -> list:
    """
    Parse a port specification into a sorted list of unique ports.
    Accepts:
      - a range:      "1-1024"
      - a comma list: "22,80,443"
      - a mix:        "22,80,1000-1010"
    """
    ports = set()
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            start, end = int(start), int(end)
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid port range: {part}")
            ports.update(range(start, end + 1))
        elif part:
            p = int(part)
            if p < 1 or p > 65535:
                raise ValueError(f"Invalid port: {p}")
            ports.add(p)
    return sorted(ports)


def resolve_host(host: str) -> str:
    """Resolve a hostname to an IP address; raise a clear error if it fails."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as exc:
        raise SystemExit(f"Error: could not resolve host '{host}': {exc}")


# ---------------------------------------------------------------------------
# Step 3: attempt TCP connection handshakes with specified timeout values
# ---------------------------------------------------------------------------
def check_port(host: str, port: int, timeout: float) -> str:
    """
    Attempt a TCP three-way handshake to (host, port).
    Returns one of: "Open", "Closed", "Filtered".
      - Open     : connection succeeded
      - Closed   : connection actively refused (RST received)
      - Filtered : timed out / no response (likely firewall dropping packets)
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        if result == 0:
            return "Open"
        else:
            return "Closed"
    except socket.timeout:
        return "Filtered"
    except OSError:
        return "Filtered"
    finally:
        sock.close()


def try_banner_grab(host: str, port: int, timeout: float) -> str:
    """
    Best-effort attempt to read a short service banner from an open port,
    to demonstrate 'service responsiveness' beyond just the handshake.
    Returns an empty string if nothing is received quickly.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                banner = sock.recv(64)
                return banner.decode(errors="ignore").strip()
            except socket.timeout:
                return ""
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Step 4: display table of Open, Closed, and Filtered ports
# ---------------------------------------------------------------------------
def scan_host(host: str, ports: list, timeout: float, grab_banner: bool) -> list:
    ip = resolve_host(host)
    print(f"\nScanning {host} ({ip}) — {len(ports)} port(s), timeout={timeout}s")
    print("-" * 60)

    results = []
    start = time.time()
    for port in ports:
        status = check_port(ip, port, timeout)
        service = COMMON_SERVICES.get(port, "")
        banner = ""
        if grab_banner and status == "Open":
            banner = try_banner_grab(ip, port, timeout)
        results.append((port, service, status, banner))
    elapsed = round(time.time() - start, 2)

    print(f"{'PORT':<8}{'SERVICE':<12}{'STATUS':<10}BANNER")
    for port, service, status, banner in results:
        print(f"{port:<8}{service:<12}{status:<10}{banner}")

    counts = {"Open": 0, "Closed": 0, "Filtered": 0}
    for _, _, status, _ in results:
        counts[status] += 1

    print("-" * 60)
    print(f"Summary: {counts['Open']} open, {counts['Closed']} closed, "
          f"{counts['Filtered']} filtered  (scan time: {elapsed}s)")
    print("=" * 60 + "\n")
    return results


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Port Status Checker — TCP port/service audit utility. "
                    "Only scan hosts you own or are authorized to test."
    )
    parser.add_argument("-H", "--host", required=True, help="Target host (IP or hostname)")
    parser.add_argument("-p", "--ports", required=True,
                        help="Ports to scan, e.g. '1-1024' or '22,80,443'")
    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                        help="Connection timeout in seconds (default: 1.0)")
    parser.add_argument("--banner", action="store_true",
                        help="Attempt to grab a short service banner on open ports")
    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        print(f"Error: {exc}")
        sys.exit(1)

    scan_host(args.host, ports, args.timeout, args.banner)


if __name__ == "__main__":
    main()
