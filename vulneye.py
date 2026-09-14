#!/usr/bin/env python3
"""
VulnEye — Educational Network & Vulnerability Scanner
=======================================================

A lightweight, dependency-free TCP port scanner with service/banner
detection and known-vulnerable-version flagging. Built for security
education, demos, and lab environments.

LEGAL / ETHICAL USE ONLY
-------------------------
Only scan systems you own or have explicit written authorization to
test. Unauthorized scanning of networks/systems you do not control
may be illegal in your jurisdiction (e.g., under the U.S. CFAA, UK
Computer Misuse Act, or equivalent local laws). This tool requires an
interactive confirmation before it will run.

Usage examples
--------------
    python3 vulneye.py 192.168.1.10
    python3 vulneye.py 192.168.1.0/24 -p 1-1024
    python3 vulneye.py scanme.example.com -p 22,80,443,8080 --json out.json
"""

import argparse
import ipaddress
import json
import socket
import sys
import threading
import queue
import time
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Reference data: common ports and a small set of well-known EOL/vulnerable
# version signatures. This is intentionally limited to *identification*
# (flagging that a banner matches a version with known public CVEs) — it
# does not contain or perform any exploit logic.
# ---------------------------------------------------------------------------

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
}

# Signature -> (advisory, note). These are coarse, well-publicized EOL /
# known-weak configurations, useful for a "does this look outdated" flag —
# always verify against an authoritative CVE feed (e.g., NVD) before
# reporting anything to a client or on video.
VERSION_ADVISORIES = [
    ("OpenSSH_5.", "Old OpenSSH branch (pre-2016 era) — check for known CVEs and unsupported status"),
    ("OpenSSH_6.", "Old OpenSSH branch — verify current patch level"),
    ("Apache/2.2", "Apache 2.2 reached EOL in 2017 — check for outdated modules/config"),
    ("Apache/2.4.6", "Bundled with old RHEL builds — verify backported patch level, not just version string"),
    ("nginx/1.0", "Very old nginx release — verify patch level"),
    ("vsftpd 2.3.4", "Historically associated with a known backdoored build — verify integrity"),
    ("Microsoft-IIS/6.0", "IIS 6.0 is long EOL (Windows Server 2003) — flag for retirement"),
    ("ProFTPD 1.3.3", "Older ProFTPD release — verify patch level"),
]

LOCK = threading.Lock()


def banner():
    print(r"""
__     __    _       _____           
\ \   / /   | |     |  ___|          
 \ \ / /   _| |_ __ | |__ _   _  ___ 
  \ V / | | | | '_ \|  __| | | |/ _ \
   \ / | |_| | | | | | |__| |_| |  __/
    \_/ \__,_|_|_| |_\____/\__, |\___|
                            __/ |     
                           |___/      
  Educational Network & Vulnerability Scanner
""")


def confirm_authorization(target):
    print("=" * 70)
    print(" LEGAL NOTICE")
    print("=" * 70)
    print(f"You are about to scan: {target}")
    print("Only proceed if you OWN this system/network, or have explicit")
    print("written authorization to test it. Unauthorized scanning can be")
    print("illegal. This tool will not run without confirmation.\n")
    resp = input("Type YES to confirm you are authorized to scan this target: ").strip()
    if resp != "YES":
        print("Authorization not confirmed. Exiting.")
        sys.exit(1)


def parse_ports(port_spec):
    """Parse '22,80,443' or '1-1024' or a mix into a sorted list of ints."""
    ports = set()
    for chunk in port_spec.split(","):
        chunk = chunk.strip()
        if "-" in chunk:
            start, end = chunk.split("-")
            ports.update(range(int(start), int(end) + 1))
        elif chunk:
            ports.add(int(chunk))
    return sorted(p for p in ports if 0 < p <= 65535)


def expand_targets(target_spec):
    """Expand a single host or CIDR range into a list of IP strings."""
    try:
        network = ipaddress.ip_network(target_spec, strict=False)
        if network.num_addresses > 1:
            return [str(ip) for ip in network.hosts()]
        return [str(network.network_address)]
    except ValueError:
        # Not an IP/CIDR — treat as hostname
        try:
            resolved = socket.gethostbyname(target_spec)
            return [resolved]
        except socket.gaierror:
            print(f"Could not resolve host: {target_spec}")
            sys.exit(1)


def grab_banner(sock):
    try:
        sock.settimeout(1.5)
        data = sock.recv(256)
        return data.decode(errors="ignore").strip()
    except Exception:
        return ""


def probe_http(host, port, use_ssl=False):
    """Send a minimal HTTP HEAD request to pull a Server header."""
    try:
        import ssl as ssl_lib
        raw = socket.create_connection((host, port), timeout=2)
        s = ssl_lib.wrap_socket(raw) if use_ssl else raw
        s.settimeout(2)
        req = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n"
        s.send(req.encode())
        resp = s.recv(1024).decode(errors="ignore")
        s.close()
        for line in resp.split("\r\n"):
            if line.lower().startswith("server:"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return ""


def check_advisories(banner_text):
    hits = []
    for sig, note in VERSION_ADVISORIES:
        if sig.lower() in banner_text.lower():
            hits.append(note)
    return hits


def scan_port(host, port, timeout, results):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((host, port)) == 0:
                service = COMMON_PORTS.get(port, "unknown")
                banner_text = grab_banner(sock)
                if not banner_text and port in (80, 8080):
                    banner_text = probe_http(host, port)
                elif not banner_text and port in (443, 8443):
                    banner_text = probe_http(host, port, use_ssl=True)

                advisories = check_advisories(banner_text)

                with LOCK:
                    results.append({
                        "port": port,
                        "service": service,
                        "banner": banner_text,
                        "advisories": advisories,
                    })
    except Exception:
        pass


def worker(host, timeout, results, q):
    while True:
        try:
            port = q.get_nowait()
        except queue.Empty:
            return
        scan_port(host, port, timeout, results)
        q.task_done()


def scan_host(host, ports, timeout=1.0, threads=100):
    q = queue.Queue()
    for p in ports:
        q.put(p)

    results = []
    workers = []
    thread_count = min(threads, max(1, len(ports)))
    for _ in range(thread_count):
        t = threading.Thread(target=worker, args=(host, timeout, results, q))
        t.daemon = True
        t.start()
        workers.append(t)

    q.join()
    results.sort(key=lambda r: r["port"])
    return results


def print_report(host, results, elapsed):
    print(f"\nHost: {host}")
    print("-" * 70)
    if not results:
        print("  No open ports found in the scanned range.")
        return
    for r in results:
        line = f"  [OPEN] {r['port']:<6} {r['service']:<12}"
        if r["banner"]:
            line += f" banner: {r['banner'][:60]}"
        print(line)
        for note in r["advisories"]:
            print(f"          ⚠  {note}")
    print(f"\n  {len(results)} open port(s) found. Scan took {elapsed:.2f}s.")


def main():
    parser = argparse.ArgumentParser(
        description="VulnEye — educational TCP port/vulnerability scanner"
    )
    parser.add_argument("target", help="IP, hostname, or CIDR range (e.g. 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", default="1-1024",
                         help="Ports to scan, e.g. '22,80,443' or '1-1024' (default: 1-1024)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                         help="Per-port socket timeout in seconds (default: 1.0)")
    parser.add_argument("--threads", type=int, default=150,
                         help="Max concurrent threads per host (default: 150)")
    parser.add_argument("--json", metavar="FILE", help="Write results to a JSON file")
    parser.add_argument("--yes", action="store_true",
                         help="Skip the interactive authorization prompt (use with care, e.g. in CI)")
    args = parser.parse_args()

    banner()

    if not args.yes:
        confirm_authorization(args.target)
    else:
        print(f"[!] --yes passed: skipping interactive authorization prompt for {args.target}\n")

    ports = parse_ports(args.ports)
    hosts = expand_targets(args.target)

    print(f"Scanning {len(hosts)} host(s), {len(ports)} port(s) each...")

    all_results = {}
    start = time.time()
    for host in hosts:
        host_start = time.time()
        results = scan_host(host, ports, timeout=args.timeout, threads=args.threads)
        elapsed = time.time() - host_start
        print_report(host, results, elapsed)
        all_results[host] = results
    total_elapsed = time.time() - start

    print("\n" + "=" * 70)
    print(f"Scan complete in {total_elapsed:.2f}s across {len(hosts)} host(s).")

    if args.json:
        output = {
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "target_spec": args.target,
            "ports_scanned": ports,
            "results": all_results,
        }
        with open(args.json, "w") as f:
            json.dump(output, f, indent=2)
        print(f"Results written to {args.json}")


if __name__ == "__main__":
    main()
