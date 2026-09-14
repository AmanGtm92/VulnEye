# VulnEye

**An educational network & vulnerability scanner** — a lightweight, dependency-free
Python tool that scans hosts for open TCP ports, grabs service banners, and flags
software versions with known public advisories. Built for security education,
YouTube walkthroughs, and authorized lab/pentest use.

## Features

- 🔎 Multithreaded TCP connect-scan (single host or full CIDR range)
- 🏷️ Service banner grabbing (SSH, FTP, SMTP, etc.)
- 🌐 HTTP/HTTPS `Server:` header probing
- ⚠️ Known-EOL / outdated-version flagging (identification only — no exploit code)
- 📄 JSON export of scan results
- 🔐 Built-in authorization gate — won't run against a target until you confirm
  you're allowed to scan it

## Installation

VulnEye needs only Python 3.7+ and the standard library — no external packages
are required. Installation is just cloning/downloading the repo.

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/vulneye.git
cd vulneye
```

*(Or just download `vulneye.py` directly if you're not using git.)*

### 2. (Optional) Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
```

### 3. Install requirements

```bash
pip install -r requirements.txt
```

This is a no-op today (VulnEye has no external dependencies) but is included so
the project follows standard Python packaging conventions, and so future
dependencies (if any get added) install the same way.

### 4. Verify it runs

```bash
python3 vulneye.py --help
```

## Usage

```bash
# Scan the default range (ports 1-1024) on a single host
python3 vulneye.py 192.168.1.10

# Scan a specific port list
python3 vulneye.py 192.168.1.10 -p 22,80,443,8080

# Scan a port range
python3 vulneye.py 192.168.1.10 -p 1-65535

# Scan an entire subnet
python3 vulneye.py 192.168.1.0/24 -p 1-1024

# Scan a hostname and save results to JSON
python3 vulneye.py scanme.example.com -p 22,80,443 --json results.json

# Skip the interactive authorization prompt (lab/CI use only)
python3 vulneye.py 10.0.0.5 --yes
```

### CLI options

| Flag | Description | Default |
|---|---|---|
| `target` | IP, hostname, or CIDR range | required |
| `-p`, `--ports` | Ports to scan, e.g. `22,80,443` or `1-1024` | `1-1024` |
| `-t`, `--timeout` | Per-port socket timeout (seconds) | `1.0` |
| `--threads` | Max concurrent threads per host | `150` |
| `--json FILE` | Write full results to a JSON file | — |
| `--yes` | Skip the interactive authorization prompt | off |

## Example output

```
Host: 192.168.1.10
----------------------------------------------------------------------
  [OPEN] 22     SSH          banner: SSH-2.0-OpenSSH_6.6.1
          ⚠  Old OpenSSH branch — verify current patch level
  [OPEN] 80     HTTP         banner: Apache/2.2.15 (CentOS)
          ⚠  Apache 2.2 reached EOL in 2017 — check for outdated modules/config

  2 open port(s) found. Scan took 0.41s.
```

## ⚖️ Legal & Ethical Use

VulnEye performs **reconnaissance only** — open-port detection and version/banner
identification. It contains **no exploit code**. That said, scanning a network or
system without authorization is illegal in most jurisdictions (e.g., the U.S.
Computer Fraud and Abuse Act, UK Computer Misuse Act, and equivalents elsewhere).

**Only run this against:**
- Systems/networks you personally own
- Systems you have explicit written authorization to test (e.g., an agreed
  pentest scope)
- Intentionally vulnerable lab targets (e.g., Metasploitable, HackTheBox,
  TryHackMe, your own home lab VMs)

The tool will refuse to run until you confirm authorization, but that
confirmation does not make scanning legal — you are responsible for making
sure you actually have permission.

## Roadmap / ideas for contributions

- UDP scanning support
- OS fingerprinting
- Live CVE lookups against the NVD API instead of the static advisory list
- HTML report export
- Web dashboard front-end

## License

MIT — see [LICENSE](LICENSE) for details.
