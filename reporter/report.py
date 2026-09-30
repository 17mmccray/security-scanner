"""
Report generation: turns the pipeline's findings into an HTML or Markdown report.

Input is the `findings` dict that main.py builds (and saves with --output x.json):
    {"target": ..., "tool_version": ..., "scan": ScanResult.to_dict(),
     "cves": CVEReport.to_dict() (optional), "shodan": {...} (optional)}

HTML is rendered from reporter/template.html with Jinja2 (autoescaped, since
service banners and CVE text come from the target / third parties and must
never be treated as markup). Markdown uses an inline template below.

Can also be run on its own to re-render a saved JSON without rescanning:
    python -m reporter.report findings.json -o report.html
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATE_DIR = Path(__file__).resolve().parent
HTML_TEMPLATE = "template.html"

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"]
TOP_FINDINGS_LIMIT = 15

# Services that are a finding on their own when exposed, regardless of CVEs.
RISKY_SERVICES = {
    "telnet": "Telnet sends credentials in cleartext. Replace with SSH.",
    "ftp": "FTP sends credentials in cleartext. Prefer SFTP/FTPS, or restrict access.",
    "tftp": "TFTP has no authentication. It should not be reachable from untrusted networks.",
    "microsoft-ds": "SMB exposed. Frequent target for wormable exploits; restrict to internal networks.",
    "netbios-ssn": "NetBIOS/SMB exposed. Restrict to internal networks.",
    "ms-wbt-server": "RDP exposed. Common brute-force and exploit target; put behind a VPN or gateway.",
    "vnc": "VNC exposed. Often weakly authenticated; put behind a VPN or SSH tunnel.",
    "mysql": "Database port exposed. Databases should not be reachable from untrusted networks.",
    "postgresql": "Database port exposed. Databases should not be reachable from untrusted networks.",
    "ms-sql-s": "Database port exposed. Databases should not be reachable from untrusted networks.",
    "oracle-tns": "Database port exposed. Databases should not be reachable from untrusted networks.",
    "mongodb": "MongoDB exposed. Historically deployed without authentication; restrict access.",
    "redis": "Redis exposed. Often runs without authentication; restrict access.",
    "elasticsearch": "Elasticsearch exposed. Often runs without authentication; restrict access.",
    "memcached": "Memcached exposed. Abusable for data leaks and DDoS amplification.",
    "snmp": "SNMP exposed. Default community strings can leak device configuration.",
    "rpcbind": "RPC portmapper exposed. Leaks service information; restrict access.",
    "x11": "X11 exposed. Can allow screen capture and keystroke injection.",
}

FORMATS = {".html": "html", ".htm": "html", ".md": "markdown", ".markdown": "markdown"}


class ReportError(Exception):
    """Raised for errors the CLI should show cleanly."""


# ---------------------------------------------------------------------------
# Context building (shared by HTML and Markdown)
# ---------------------------------------------------------------------------

def _rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index((severity or "").upper())
    except ValueError:
        return len(SEVERITY_ORDER)


def _banner(port: dict) -> str:
    return " ".join(p for p in (port.get("product"), port.get("version"), port.get("extra_info")) if p).strip()


def _fmt_time(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError):
        return iso or ""


def build_context(findings: dict, generated_at: Optional[datetime] = None) -> dict:
    """Flatten raw findings into what the templates need."""
    scan = findings.get("scan") or {}
    cve_data = findings.get("cves")  # None means the CVE step didn't run
    generated_at = generated_at or datetime.now().astimezone()

    # Index CVE results by (host, port, protocol)
    svc_cves: dict[tuple, dict] = {}
    for svc in (cve_data or {}).get("services", []):
        svc_cves[(svc.get("host"), svc.get("port"), svc.get("protocol"))] = svc

    hosts = []
    exposures = []
    open_ports_total = 0
    for h in scan.get("hosts", []):
        ports = []
        for p in h.get("ports", []):
            if p.get("state") != "open":
                continue
            open_ports_total += 1
            svc = svc_cves.get((h.get("address"), p.get("port"), p.get("protocol")), {})
            matches = svc.get("all_matches") or svc.get("cves", [])
            worst = min((c.get("severity", "UNKNOWN") for c in matches), key=_rank) if matches else None
            ports.append({
                "port": p.get("port"),
                "protocol": p.get("protocol"),
                "service": p.get("service") or "unknown",
                "banner": _banner(p),
                "cve_count": len(matches),
                "worst": worst,
                "query_method": svc.get("query_method"),
            })
            note = RISKY_SERVICES.get((p.get("service") or "").lower())
            if note:
                exposures.append({
                    "host": h.get("address"),
                    "port": p.get("port"),
                    "protocol": p.get("protocol"),
                    "service": p.get("service"),
                    "note": note,
                })
        hosts.append({
            "address": h.get("address"),
            "hostname": h.get("hostname"),
            "state": h.get("state"),
            "os_matches": h.get("os_matches", []),
            "ports": ports,
        })

    # Unique CVEs across all services, with every place each one was seen
    unique: dict[str, dict] = {}
    for svc in (cve_data or {}).get("services", []):
        loc = f"{svc.get('host')}:{svc.get('port')}/{svc.get('protocol')}"
        for c in svc.get("cves", []):
            entry = unique.setdefault(c["cve_id"], {**c, "affected": [], "low_confidence": False})
            entry["affected"].append(loc)
            if svc.get("confidence") == "low":
                entry["low_confidence"] = True
    all_cves = sorted(unique.values(), key=lambda c: (_rank(c.get("severity")), -(c.get("cvss_score") or 0)))

    # Totals count every match NVD returned, not just the subset displayed per service
    every: dict[str, dict] = {}
    for svc in (cve_data or {}).get("services", []):
        for m in svc.get("all_matches") or svc.get("cves", []):
            every.setdefault(m["cve_id"], m)
    counts = {s: 0 for s in SEVERITY_ORDER}
    for m in every.values():
        counts[m.get("severity", "UNKNOWN")] = counts.get(m.get("severity", "UNKNOWN"), 0) + 1
    kev = [m for m in every.values() if m.get("known_exploited")]

    top = [c for c in all_cves if c.get("severity") in ("CRITICAL", "HIGH") or c.get("known_exploited")]
    top = top[:TOP_FINDINGS_LIMIT]

    if cve_data is None:
        overall = "NOT_ASSESSED"
    elif every:
        overall = min((m.get("severity", "UNKNOWN") for m in every.values()), key=_rank)
    else:
        overall = "NONE"
    if overall in ("NONE", "LOW") and exposures:
        overall = "MEDIUM"  # exposed risky services outweigh a clean CVE result

    services_detail = [
        s for s in (cve_data or {}).get("services", []) if s.get("cves")
    ]
    services_detail.sort(key=lambda s: min((_rank(c.get("severity")) for c in s["cves"]), default=99))
    skipped = [s for s in (cve_data or {}).get("services", []) if s.get("query_method") == "skipped"]
    low_conf = [s for s in (cve_data or {}).get("services", []) if s.get("confidence") == "low" and s.get("cves")]
    backported = [s for s in (cve_data or {}).get("services", []) if s.get("distro") and s.get("cves")]

    shodan = _shodan_context(findings.get("shodan"), set(every))

    return {
        "target": findings.get("target") or scan.get("target", ""),
        "tool_version": findings.get("tool_version", ""),
        "generated_at": generated_at.strftime("%Y-%m-%d %H:%M %Z").strip(),
        "scan": {
            "profile": scan.get("profile", ""),
            "command_line": scan.get("command_line", ""),
            "started_at": _fmt_time(scan.get("started_at", "")),
            "elapsed": scan.get("elapsed_seconds", 0),
        },
        "stats": {
            "hosts_total": len(hosts),
            "hosts_up": sum(1 for h in hosts if h["state"] == "up"),
            "open_ports": open_ports_total,
            "cves_total": len(every),
            "kev_count": len(kev),
        },
        "cve_assessed": cve_data is not None,
        "severity_counts": counts,
        "severity_order": SEVERITY_ORDER[:4],
        "overall_risk": overall,
        "hosts": hosts,
        "top_findings": top,
        "all_cves": all_cves,
        "services_detail": services_detail,
        "exposures": exposures,
        "skipped": skipped,
        "low_confidence": low_conf,
        "backported": backported,
        "recommendations": _recommendations(counts, kev, exposures, skipped, low_conf, backported,
                                            cve_data is not None, shodan),
        "shodan": shodan,
    }


def _shodan_context(data: Optional[dict], nvd_ids: set[str]) -> Optional[dict]:
    """Shape Shodan results for the templates. None when --shodan wasn't used."""
    if not data:
        return None
    hosts = []
    for h in data.get("hosts", []):
        vulns = h.get("vulns") or []
        hosts.append({
            **h,
            "source_label": {"shodan": "Shodan API", "internetdb": "Shodan InternetDB"}.get(h.get("source"), h.get("source")),
            # CVEs Shodan associates with the host that our version-based NVD lookup didn't produce
            "extra_vulns": [v for v in vulns if v not in nvd_ids],
        })
    return {
        "hosts": hosts,
        "skipped": data.get("skipped", []),
        "api_problem": data.get("api_problem", ""),
        "extra_ports": [
            (h["ip"], [p for p in h["ports_only_in_shodan"] if p not in (h.get("likely_udp") or [])])
            for h in hosts if set(h.get("ports_only_in_shodan") or []) - set(h.get("likely_udp") or [])
        ],
        "udp_ports": [(h["ip"], h["likely_udp"]) for h in hosts if h.get("likely_udp")],
    }


def _recommendations(counts, kev, exposures, skipped, low_conf, backported, assessed, shodan=None) -> list[str]:
    recs = []
    if kev:
        ids = ", ".join(c["cve_id"] for c in kev[:5]) + (" and others" if len(kev) > 5 else "")
        recs.append(
            f"Patch actively exploited vulnerabilities first ({ids}). These are in CISA's "
            "Known Exploited Vulnerabilities catalog, meaning attackers are using them now."
        )
    if counts.get("CRITICAL"):
        recs.append(f"Remediate the {counts['CRITICAL']} critical-severity CVE(s) by upgrading the affected services.")
    if counts.get("HIGH"):
        recs.append(f"Schedule fixes for the {counts['HIGH']} high-severity CVE(s).")
    if exposures:
        recs.append(
            f"Review the {len(exposures)} exposed high-risk service(s) listed under Exposure findings; "
            "restrict them with a firewall or VPN if they don't need to be public."
        )
    if backported:
        distros = sorted({s["distro"] for s in backported})
        recs.append(
            f"{len(backported)} service(s) run {'/'.join(distros)} packages. Distributions backport security "
            "fixes without changing the upstream version number, so check the distro's security tracker "
            "(e.g. ubuntu.com/security/cves) before treating these CVEs as confirmed."
        )
    if low_conf:
        recs.append(
            "Manually verify keyword-matched CVEs. They were found by text search, not an exact "
            "product/version match, and may not apply."
        )
    if skipped:
        recs.append(
            f"{len(skipped)} service(s) couldn't be checked for CVEs because no version was detected. "
            "Re-scan with version detection (e.g. --profile full) or check them manually."
        )
    if shodan and shodan["extra_ports"]:
        detail = "; ".join(f"{ip}: {', '.join(map(str, ports))}" for ip, ports in shodan["extra_ports"])
        recs.append(
            f"Shodan has seen open ports our scan didn't report ({detail}). Re-scan those ports with "
            "--ports to confirm whether they're still exposed."
        )
    if shodan and shodan["udp_ports"]:
        detail = "; ".join(f"{ip}: {', '.join(map(str, ports))}" for ip, ports in shodan["udp_ports"])
        recs.append(
            f"Shodan lists ports that normally run over UDP ({detail}), which this TCP scan can't see. "
            "Confirm with a UDP scan (nmap -sU) and close any that don't need to be public."
        )
    if not assessed:
        recs.append("CVE lookup was not run. Re-run without --no-cve for vulnerability data.")
    if not recs:
        recs.append("No known vulnerabilities or risky exposures were found. Keep services patched and re-scan periodically.")
    return recs


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _sev_label(severity: str) -> str:
    return {"NOT_ASSESSED": "Not assessed"}.get(severity or "", (severity or "Unknown").title())


def _md(value) -> str:
    """Escape text for a Markdown table cell / inline text."""
    text = "" if value is None else str(value)
    text = text.replace("\\", "\\\\").replace("|", "\\|")
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    text = re.sub(r"[\r\n]+", " ", text)
    return text


def _truncate(value, length: int = 200) -> str:
    text = "" if value is None else str(value)
    return text if len(text) <= length else text[: length - 1].rstrip() + "…"


def _env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "htm"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["sev_label"] = _sev_label
    env.filters["md"] = _md
    env.filters["trunc"] = _truncate
    return env


def render_html(context: dict) -> str:
    return _env().get_template(HTML_TEMPLATE).render(**context)


MARKDOWN_TEMPLATE = """\
# Security Audit Report: {{ target | md }}

| | |
|---|---|
| **Target** | `{{ target | md }}` |
| **Generated** | {{ generated_at }} |
| **Scan profile** | {{ scan.profile | md }} |
| **Scan started** | {{ scan.started_at }} ({{ "%.1f" | format(scan.elapsed) }}s) |
| **Tool version** | security-scanner {{ tool_version }} |

## Executive summary

**Overall risk: {{ overall_risk | sev_label }}**

- Hosts up: **{{ stats.hosts_up }}** of {{ stats.hosts_total }}
- Open ports: **{{ stats.open_ports }}**
{% if cve_assessed %}
- Known CVEs: **{{ stats.cves_total }}** ({% for s in severity_order %}{{ severity_counts[s] }} {{ s | sev_label }}{{ ", " if not loop.last }}{% endfor %})
{% if stats.kev_count %}
- ⚠ **{{ stats.kev_count }}** actively exploited (CISA KEV)
{% endif %}
{% else %}
- CVE lookup: not run
{% endif %}
{% if exposures %}
- High-risk exposed services: **{{ exposures | length }}**
{% endif %}

### Recommendations

{% for r in recommendations %}
{{ loop.index }}. {{ r | md }}
{% endfor %}

{% if top_findings %}
## Key findings

| CVE | Severity | CVSS | Affected | Description |
|---|---|---|---|---|
{% for c in top_findings %}
| [{{ c.cve_id }}]({{ c.url }}){{ " ⚠ KEV" if c.known_exploited }}{{ " *(unverified)*" if c.low_confidence }} | {{ c.severity | sev_label }} | {{ c.cvss_score if c.cvss_score is not none else "-" }} | {{ c.affected | join(", ") | md }} | {{ c.description | trunc(180) | md }} |
{% endfor %}

{% endif %}
{% if exposures %}
## Exposure findings

| Host | Port | Service | Issue |
|---|---|---|---|
{% for e in exposures %}
| {{ e.host | md }} | {{ e.port }}/{{ e.protocol }} | {{ e.service | md }} | {{ e.note | md }} |
{% endfor %}

{% endif %}
## Hosts and services

{% for h in hosts %}
### {{ h.address | md }}{{ " (" ~ (h.hostname | md) ~ ")" if h.hostname }}

State: {{ h.state }}{{ " · OS guess: " ~ (h.os_matches | join(", ") | md) if h.os_matches }}

{% if h.ports %}
| Port | Service | Product / Version | CVEs |
|---|---|---|---|
{% for p in h.ports %}
| {{ p.port }}/{{ p.protocol }} | {{ p.service | md }} | {{ p.banner | md or "-" }} | {% if p.cve_count %}{{ p.cve_count }} (worst: {{ p.worst | sev_label }}){% elif p.query_method == "skipped" %}not checked{% elif cve_assessed %}0{% else %}-{% endif %} |
{% endfor %}
{% else %}
No open ports found.
{% endif %}

{% endfor %}
{% if services_detail %}
## Vulnerability details

{% for s in services_detail %}
### {{ s.host | md }}:{{ s.port }}/{{ s.protocol }}: {{ (s.product or s.service) | md }} {{ s.version | md }}

{% if s.confidence == "low" %}
> Keyword match (`{{ s.query | md }}`). Verify these apply before acting on them.

{% endif %}
{% if s.distro %}
> {{ s.distro }} package: {{ s.distro }} backports security fixes without changing the version number, so some of these may already be patched.

{% endif %}
{% for c in s.cves %}
- **[{{ c.cve_id }}]({{ c.url }})**: {{ c.severity | sev_label }}{% if c.cvss_score is not none %} ({{ c.cvss_score }}){% endif %}{{ " · ⚠ actively exploited" if c.known_exploited }}{% if c.published %} · published {{ c.published }}{% endif %}

  {{ c.description | md }}
{% endfor %}
{% if s.note %}

*{{ s.note | md }}*
{% endif %}

{% endfor %}
{% endif %}
{% if skipped %}
## Not checked for CVEs

{% for s in skipped %}
- {{ s.host | md }}:{{ s.port }}/{{ s.protocol }} {{ s.service | md }}: {{ s.note | md }}
{% endfor %}

{% endif %}
{% if shodan %}
## Passive recon (Shodan)

{% if shodan.api_problem %}
*Shodan API not used ({{ shodan.api_problem | md }}); results are from the free InternetDB.*

{% endif %}
{% for h in shodan.hosts %}
### {{ h.ip | md }}

{% if not h.found %}
{{ (h.note or "No Shodan data.") | md }} ({{ h.source_label }})

{% else %}
| | |
|---|---|
| **Source** | {{ h.source_label }}{% if h.last_update %}, last seen {{ h.last_update }}{% endif %} |
{% if h.hostnames %}
| **Hostnames** | {{ h.hostnames | join(", ") | md }} |
{% endif %}
{% if h.org or h.isp %}
| **Org / ISP** | {{ [h.org, h.isp] | select | join(" / ") | md }} |
{% endif %}
| **Ports** | {% for p in h.ports %}{{ p }}{{ " (likely UDP; not in our TCP scan)" if p in (h.likely_udp or []) else (" (not in our scan)" if p in h.ports_only_in_shodan) }}{{ ", " if not loop.last }}{% endfor %} |
{% if h.tags %}
| **Tags** | {{ h.tags | join(", ") | md }} |
{% endif %}
| **CVEs Shodan lists** | {{ h.vulns | length }}{% if h.extra_vulns %} ({{ h.extra_vulns | length }} not found by our NVD lookup){% endif %} |

{% if h.extra_vulns %}
CVEs Shodan associates with this host that the NVD step didn't match: {% for v in h.extra_vulns[:20] %}[{{ v }}](https://nvd.nist.gov/vuln/detail/{{ v }}){{ ", " if not loop.last }}{% endfor %}{{ " ..." if h.extra_vulns | length > 20 }}

{% endif %}
{% if h.note %}
*{{ h.note | md }}*

{% endif %}
{% endif %}
{% endfor %}
{% for s in shodan.skipped %}
- Skipped {{ s.target | md }}: {{ s.reason | md }}
{% endfor %}

{% endif %}
## Methodology

1. **Port & service scan:** nmap (`{{ scan.command_line | md }}`).
2. **CVE lookup:** NIST NVD API 2.0. Services with a CPE were matched by product and version (high confidence); others by keyword search (low confidence).
3. **Severity:** CVSS base scores mapped to Critical (9.0+), High (7.0-8.9), Medium (4.0-6.9), Low (0.1-3.9).
{% if shodan %}
4. **Passive recon:** Shodan ({{ shodan.hosts | map(attribute="source_label") | unique | join(", ") or "none" }}), which reports what Shodan's own internet-wide scans observed. Its data can be days or weeks old.
{% endif %}
5. **Limitations:** matching is by advertised version. Linux distributions backport fixes without changing version numbers, so distro-packaged services can be flagged for CVEs that are already patched.

---

*Generated by security-scanner. Results reflect publicly known vulnerabilities for detected versions and do not confirm exploitability. Only scan systems you are authorized to test.*
"""


def render_markdown(context: dict) -> str:
    env = _env()
    env.autoescape = False
    return env.from_string(MARKDOWN_TEMPLATE).render(**context)


def generate_report(findings: dict, output: Path | str, fmt: Optional[str] = None) -> Path:
    """Render findings to `output`. Format comes from `fmt` or the file extension."""
    output = Path(output)
    fmt = fmt or FORMATS.get(output.suffix.lower())
    if fmt not in ("html", "markdown"):
        raise ReportError(f"Unsupported report format for '{output.name}'. Use .html or .md.")
    if not findings.get("scan"):
        raise ReportError("Findings contain no scan data to report on.")

    context = build_context(findings)
    content = render_html(context) if fmt == "html" else render_markdown(context)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")
    return output


# ---------------------------------------------------------------------------
# Standalone CLI: re-render a saved findings JSON
# ---------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m reporter.report",
        description="Render a saved findings JSON (from main.py --output x.json) into a report.",
    )
    parser.add_argument("input", help="findings JSON file")
    parser.add_argument("--output", "-o", required=True, help="report path (.html or .md)")
    args = parser.parse_args(argv)

    try:
        findings = json.loads(Path(args.input).read_text(encoding="utf-8"))
        path = generate_report(findings, args.output)
    except (OSError, ValueError, ReportError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"Report written to {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
