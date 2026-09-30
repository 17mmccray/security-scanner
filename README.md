# Security Scanner

An automated security audit CLI tool built in Python. Takes a target domain or IP, scans for open ports and services, maps findings to known CVEs, and generates a structured vulnerability report.

Built as a portfolio project applying concepts from CSIS 486 (Ethical Hacking) to a real-world security workflow.

---

## Features

- **Port & Service Scanning** — Nmap-based fingerprinting of open ports and service versions, with quick / standard / full / stealth scan profiles
- **CVE Lookup** — Queries the NIST National Vulnerability Database (NVD) API for known vulnerabilities by exact product version (CPE), with a flagged keyword fallback
- **Severity Scoring** — Maps CVSS scores to Critical / High / Medium / Low ratings and flags CVEs in CISA's Known Exploited Vulnerabilities (KEV) catalog
- **Exposure Checks** — Flags risky services (Telnet, FTP, SMB, RDP, exposed databases) regardless of version
- **HTML & Markdown Reports** — Executive summary, prioritized recommendations, and per-service findings via Jinja2
- **Passive Recon** *(planned)* — Shodan API lookup for historical exposure data without touching the target

---

## Tech Stack

- Python 3.11+
- [Nmap](https://nmap.org/) + [python-nmap](https://pypi.org/project/python-nmap/)
- [NIST NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities)
- [Jinja2](https://jinja.palletsprojects.com/)
- [Rich](https://github.com/Textualize/rich)
- [Shodan API](https://developer.shodan.io/) *(planned)*

---

## Project Structure

```
security-scanner/
├── main.py                 # CLI entry point: scan → recon → CVE lookup → report
├── scanner/
│   ├── nmap_scan.py        # Port and service fingerprinting
│   ├── shodan_recon.py     # Passive recon via Shodan (planned)
│   └── cve_lookup.py       # NVD API CVE queries
├── reporter/
│   ├── report.py           # Assembles findings into HTML / Markdown
│   └── template.html       # Jinja2 HTML report template
├── tests/                  # Offline unit tests (no network or nmap needed)
├── requirements.txt
└── README.md
```

---

## Usage

```bash
# Basic scan
python main.py --target example.com --output report.html

# With Shodan passive recon (planned)
python main.py --target 192.168.1.1 --shodan --output report.html

# Output as Markdown
python main.py --target example.com --output report.md
```

More options:

```bash
# Faster scan of the top 100 ports, or specific ports only
python main.py --target 10.0.0.5 --profile quick --output report.html
python main.py --target 10.0.0.5 --ports 22,80,443 --output report.html

# Show every NVD query and how many CVEs it matched
python main.py --target example.com --output report.html -v

# Keep the raw findings as JSON and re-render the report later without rescanning
python main.py --target example.com --output report.html --save-json
python -m reporter.report report.json --output report.md

# List scan profiles / all options
python main.py --list-profiles
python main.py --help
```

> Only scan systems you own or have explicit permission to test. [scanme.nmap.org](http://scanme.nmap.org/) is provided by the Nmap project for testing. Please keep it to a few scans a day.

---

## Setup

1. Install [Nmap](https://nmap.org/download.html) (on Windows, keep the Npcap option checked) and confirm with `nmap --version`.
2. Clone and install:

```bash
git clone https://github.com/17mmccray/security-scanner.git
cd security-scanner
python -m venv .venv
source .venv/bin/activate        # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

3. Set your API keys in a `.env` file in the project folder:

```
NVD_API_KEY=your_key_here      # optional but recommended, free at https://nvd.nist.gov/developers/request-an-api-key
SHODAN_API_KEY=your_key_here   # for --shodan (planned)
```

Without an NVD key the tool still works, but NVD limits lookups to 5 requests per 30 seconds (50 with a key). Responses are cached for 24 hours.

---

## Sample Output

Scan of [scanme.nmap.org](http://scanme.nmap.org/), the Nmap project's public test host:

```
$ python main.py --target scanme.nmap.org --output report.html -v

  Port   Proto   State   Service      Product / Version
    22   tcp     open    ssh          OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 Ubuntu Linux; protocol 2.0
    80   tcp     open    http         Apache httpd 2.4.7 (Ubuntu)
  9929   tcp     open    nping-echo   Nping echo

Step 3: CVE lookup (NVD)
  NVD CPE     cpe:2.3:a:openbsd:openssh:6.6.1:p1:*:*:*:*:*:*  → 1 match
  NVD CPE     cpe:2.3:a:openbsd:openssh:6.6.1:*:*:*:*:*:*:*  → 44 matches
  NVD CPE     cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*  → 108 matches
 Critical  25   High  56   Medium  67   Low  4  ⚠ 2 known exploited (CISA KEV)

45.33.32.156:80/tcp  Apache httpd 2.4.7
  CVE                Severity     CVSS   Description
  CVE-2017-3167       Critical     9.8   In Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26, ...
  CVE-2021-44790      Critical     9.8   A carefully crafted request body can cause a buffer overflow in ...
  CVE-2024-38475 ⚠    Critical     9.1   Improper escaping of output in mod_rewrite in Apache HTTP Server ...
  CVE-2021-40438 ⚠    Critical     9.0   A crafted request uri-path can cause mod_proxy to forward the ...
  ...
showing the 12 most severe of 108 matches
Ubuntu package: distros often backport fixes without changing the version number,
so some of these may already be patched.
```

| Service | Version | CVEs matched | Worst | Notes |
|---|---|---|---|---|
| SSH (22) | OpenSSH 6.6.1p1 | 44 | Critical | Ubuntu package; fixes may be backported |
| HTTP (80) | Apache httpd 2.4.7 | 108 | Critical | 2 in CISA KEV (CVE-2024-38475, CVE-2021-40438) |
| 9929 | Nping echo | n/a | n/a | No version detected, so not checked |

The generated HTML report includes an executive summary with an overall risk rating, prioritized recommendations (actively exploited CVEs first), key findings, per-host service tables, and full CVE details with links to NVD.

---

## How It Works

1. **Scan.** Nmap runs with service/version detection (`-sV`). CPE identifiers are read directly from Nmap's XML output, because python-nmap keeps only the last CPE per port (for an SSH port it would keep `linux_kernel` and drop `openssh`).
2. **Look up.** Each service's CPE is converted to CPE 2.3 and matched with NVD's `virtualMatchString`. Queries run in tiers: the exact version plus update (`6.6.1:p1`) and the same version with any update (`6.6.1:*`) are merged, because NVD records most CVEs as version ranges. A keyword search is the last resort and is labeled low confidence.
3. **Score.** Every match is counted and rated on the CVSS v3 scale (v2 scores are re-rated). KEV-listed CVEs are always shown, even outside the top N.
4. **Report.** Findings are rendered to HTML or Markdown. Banner and CVE text are escaped, since they come from the scanned host and third parties.

### Limitations

- Matching is by advertised version. Linux distributions backport security fixes without changing version numbers, so distro-packaged services can be flagged for CVEs that are already patched. Results indicate likely exposure, not confirmed exploitability.
- Services that don't report a version (common for Windows RPC/SMB) can't be matched to CVEs.

---

## Testing

```bash
python -m unittest discover -s tests -v
```

49 offline tests cover CPE conversion, NVD query fallbacks, rate limiting and retries, CVSS parsing, report rendering, and HTML escaping of hostile banners. They include regression cases from live scans. No network or Nmap install needed.

---

## Background

This project applies the security methodology from CSIS 486 (Ethical Hacking) — recon, scanning, vulnerability identification, and reporting — to an automated CLI tool. The same static audit methodology was previously applied manually to a production Next.js application, identifying 20 findings including 2 criticals. This tool automates that workflow.

---

## Roadmap

- [x] Nmap scanner module
- [x] NVD CVE lookup module
- [ ] Shodan recon module
- [x] HTML report generator
- [ ] `--compare` flag to diff two reports
- [ ] CI pipeline with automated test scans

---

## License

MIT
