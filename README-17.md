# Port Status Checker

A Python command-line network utility that checks open ports and basic
service responsiveness on a target host using TCP connection handshakes.

> ⚠️ **Ethical use notice:** Only scan hosts and networks you own or have
> explicit written permission to test. Unauthorized port scanning may
> violate computer misuse laws in your jurisdiction. This tool is intended
> for learning, and for auditing systems you control (e.g. localhost, your
> own lab VMs, or systems you're contracted to test).

## Objective

Program network socket connections to audit open host ports, classify
each as Open / Closed / Filtered, and display the results in a clear
summary table.

## How it works

1. **Socket library** — built on Python's standard `socket` module.
2. **Target & port inputs** — accepts a target host (IP or hostname) and a
   port specification (single ports, comma lists, or ranges).
3. **TCP handshake with timeout** — attempts a TCP `connect()` to each
   port with a configurable timeout:
   - `Open` — the three-way handshake succeeded
   - `Closed` — the connection was actively refused
   - `Filtered` — no response within the timeout (likely firewalled)
4. **Results table** — prints a table of port / service / status, plus an
   optional banner grab, and a final open/closed/filtered summary.

## Usage

```bash
# Scan a port range
python port_checker.py -H 127.0.0.1 -p 1-1024

# Scan specific ports
python port_checker.py -H example.com -p 22,80,443,3306

# Mix ranges and single ports, with a custom timeout
python port_checker.py -H 127.0.0.1 -p 22,80,1000-1010 -t 0.5

# Also attempt to read a short service banner on open ports
python port_checker.py -H 127.0.0.1 -p 1-100 --banner
```

## Example output

```
Scanning 127.0.0.1 (127.0.0.1) — 10 port(s), timeout=0.5s
------------------------------------------------------------
PORT    SERVICE     STATUS    BANNER
9990                Closed
9991                Closed
...
9999                Open
------------------------------------------------------------
Summary: 1 open, 9 closed, 0 filtered  (scan time: 0.0s)
============================================================
```

## Project structure

```
port-status-checker/
├── port_checker.py   # main program
└── README.md
```

## Notes

- Scan results were verified against `127.0.0.1` (localhost), including
  a live test listener to confirm the tool correctly reports both `Open`
  and `Closed` states.
- `Filtered` is reported when a connection attempt times out without an
  explicit refusal — typical of a firewall silently dropping packets.
