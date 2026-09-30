# Security Scanner

An automated security audit CLI tool built in Python. Takes a target domain or IP, scans for open ports and services, maps findings to known CVEs, and generates a structured vulnerability report.

Built as a portfolio project applying concepts from CSIS 486 (Ethical Hacking) to a real-world security workflow.

---

## Features

- **Port & Service Scanning** — Nmap-based fingerprinting of open ports and service versions
- **Passive Recon** — Shodan API lookup for historical exposure data without touching the target
- **CVE Lookup** — Queries the NIST National Vulnerability Database (NVD) API for known vulnerabilities by service and version
- **Severity Scoring** — Maps CVSS scores to Critical / High / Medium / Low ratings
- **HTML Report Generation** — Outputs a clean, structured vulnerability report via Jinja2

---

## Tech Stack

- Python 3.11+
- [python-nmap](https://pypi.org/project/python-nmap/)
- [Shodan API](https://developer.shodan.io/)
- [NIST NVD API](https://nvd.nist.gov/developers/vulnerabilities)
- [Jinja2](https://jinja.palletsprojects.com/)
- [Rich](https://github.com/Textualize/rich)

---

## Project Structure
security-scanner/
├── main.py # CLI entry point
├── scanner/
│ ├── nmap_scan.py # Port and service fingerprinting
│ ├── shodan_recon.py # Passive recon via Shodan
│ └── cve_lookup.py # NVD API CVE queries
├── reporter/
│ ├── report.py # Assembles findings into report
│ └── template.html # Jinja2 HTML report template
├── requirements.txt
└── README.md

---

## Usage

```bash
# Basic scan
python main.py --target example.com --output report.html

# With Shodan passive recon
python main.py --target 192.168.1.1 --shodan --output report.html

# Output as Markdown
python main.py --target example.com --output report.md
```

---

## Setup

```bash
git clone https://github.com/17mmccray/security-scanner.git
cd security-scanner
pip install -r requirements.txt
```

Set your API keys in a `.env` file:

SHODAN_API_KEY=your_key_here
NVD_API_KEY=your_key_here   # optional, free at https://nvd.nist.gov/developers/request-an-api-key

---

## Sample Output

*Coming soon — will include example scan report against a test environment.*

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
