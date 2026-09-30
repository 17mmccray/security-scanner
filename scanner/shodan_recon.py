"""
Passive reconnaissance via Shodan.

Shodan continuously scans the internet, so it can tell us what a host has
exposed without sending the host a single packet. That's useful two ways:
  * it may know about ports our nmap scan didn't cover (or that are filtered
    from where we scanned), and
  * it shows what the rest of the internet sees, and when it last saw it.

Two data sources, picked automatically:
  1. Shodan API (https://api.shodan.io): full banners, org/ISP, OS, geo.
     Needs SHODAN_API_KEY on an account with a membership. Free keys get
     403 for host lookups.
  2. InternetDB (https://internetdb.shodan.io): free, no key, updated weekly.
     Returns ports, CPEs, hostnames, tags and CVE IDs. Free for
     non-commercial use.
If there's no key, or the key is rejected, we fall back to InternetDB.

Shodan only has data for public IPs, so private/loopback addresses are skipped.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import time
from dataclasses import asdict, dataclass, field
from typing import Callable, Optional

import requests

SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"
INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
MAX_HOSTS_DEFAULT = 16  # keep --shodan on a /24 from turning into 254 lookups
REQUEST_INTERVAL = 1.0
# Ports whose services normally run over UDP. InternetDB doesn't say which protocol a port is,
# and our default scan is TCP-only, so these need `nmap -sU` rather than --ports to confirm.
COMMON_UDP_PORTS = {53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1194, 1900, 4500, 5060, 5353, 11211}  # Shodan asks for at most ~1 request per second


class ShodanError(Exception):
    """Raised for errors the CLI should show cleanly."""


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------

@dataclass
class ShodanService:
    port: int
    transport: str = "tcp"
    product: str = ""
    version: str = ""
    module: str = ""  # Shodan's name for the protocol it detected, e.g. "ssh", "http"
    cpes: list[str] = field(default_factory=list)
    timestamp: str = ""


@dataclass
class ShodanHost:
    ip: str
    source: str = ""  # "shodan", "internetdb", or "" when not looked up
    found: bool = False
    note: str = ""
    hostnames: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    cpes: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    vulns: list[str] = field(default_factory=list)  # CVE IDs Shodan associates with the host
    org: str = ""
    isp: str = ""
    os: str = ""
    country: str = ""
    last_update: str = ""
    services: list[ShodanService] = field(default_factory=list)
    # Filled in by compare_with_scan()
    ports_only_in_shodan: list[int] = field(default_factory=list)
    ports_only_in_scan: list[int] = field(default_factory=list)
    likely_udp: list[int] = field(default_factory=list)  # subset of ports_only_in_shodan


@dataclass
class ShodanReport:
    hosts: list[ShodanHost] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)  # [{"target": ..., "reason": ...}]
    api_problem: str = ""  # why the full Shodan API wasn't used, if a key was set

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class ShodanRecon:
    def __init__(
        self,
        api_key: Optional[str] = None,
        session: Optional[requests.Session] = None,
        timeout: int = 20,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.api_key = api_key if api_key is not None else (os.environ.get("SHODAN_API_KEY") or None)
        self.session = session or requests.Session()
        self.session.headers.setdefault("User-Agent", "security-scanner (github.com/17mmccray/security-scanner)")
        self.timeout = timeout
        self._sleep = sleep
        self._last_request = 0.0
        self.api_usable = bool(self.api_key)  # flips to False after a 401/403
        self.api_problem = ""

    # -- public -------------------------------------------------------------

    def lookup(self, ip: str) -> ShodanHost:
        """Look up one public IP, using the full API when possible, else InternetDB."""
        if self.api_usable:
            host = self._lookup_api(ip)
            if host is not None:
                return host
        return self._lookup_internetdb(ip)

    # -- HTTP ---------------------------------------------------------------

    def _get(self, url: str, **params) -> requests.Response:
        wait = REQUEST_INTERVAL - (time.monotonic() - self._last_request)
        if wait > 0:
            self._sleep(wait)
        try:
            resp = self.session.get(url, params=params or None, timeout=self.timeout)
        except requests.RequestException as exc:
            raise ShodanError(f"network error contacting Shodan: {exc}") from exc
        finally:
            self._last_request = time.monotonic()
        return resp

    @staticmethod
    def _error_text(resp: requests.Response) -> str:
        try:
            return (resp.json() or {}).get("error") or (resp.json() or {}).get("detail") or ""
        except ValueError:
            return resp.text[:200]

    def _lookup_api(self, ip: str) -> Optional[ShodanHost]:
        """Full Shodan API. Returns None if the key can't be used, so the caller falls back."""
        resp = self._get(SHODAN_HOST_URL.format(ip=ip), key=self.api_key)
        if resp.status_code == 200:
            return parse_shodan_host(ip, resp.json())
        if resp.status_code == 404:
            return ShodanHost(ip=ip, source="shodan", found=False, note="Shodan has no data for this IP")
        if resp.status_code in (401, 403):
            # Invalid key, or a free key without membership. Don't keep retrying the API.
            self.api_usable = False
            detail = self._error_text(resp)
            self.api_problem = (
                "invalid API key" if resp.status_code == 401
                else "host lookups need a Shodan membership" + (f": {detail}" if detail else "")
            )
            return None
        if resp.status_code == 429:
            raise ShodanError("Shodan rate limit hit. Wait a minute and try again.")
        raise ShodanError(f"Shodan API error HTTP {resp.status_code}: {self._error_text(resp)}")

    def _lookup_internetdb(self, ip: str) -> ShodanHost:
        resp = self._get(INTERNETDB_URL.format(ip=ip))
        if resp.status_code == 200:
            return parse_internetdb(ip, resp.json())
        if resp.status_code == 404:
            return ShodanHost(ip=ip, source="internetdb", found=False,
                              note="Shodan has no data for this IP")
        if resp.status_code == 429:
            raise ShodanError("InternetDB rate limit hit. Wait a minute and try again.")
        raise ShodanError(f"InternetDB error HTTP {resp.status_code}: {self._error_text(resp)}")


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _sorted_unique(items) -> list:
    return sorted({i for i in items if i not in (None, "")})


def parse_internetdb(ip: str, data: dict) -> ShodanHost:
    """
    InternetDB response:
      {"ip": "...", "ports": [22, 80], "cpes": ["cpe:/a:..."], "hostnames": [...],
       "tags": [...], "vulns": ["CVE-..."]}
    """
    return ShodanHost(
        ip=data.get("ip") or ip,
        source="internetdb",
        found=True,
        hostnames=_sorted_unique(data.get("hostnames") or []),
        ports=_sorted_unique(int(p) for p in data.get("ports") or []),
        cpes=_sorted_unique(data.get("cpes") or []),
        tags=_sorted_unique(data.get("tags") or []),
        vulns=_sorted_unique(data.get("vulns") or []),
    )


def parse_shodan_host(ip: str, data: dict) -> ShodanHost:
    """Parse GET /shodan/host/{ip}: top-level host info plus one banner per service in data[]."""
    services = []
    cpes: set[str] = set()
    vulns: set[str] = set(data.get("vulns") or [])
    for banner in data.get("data") or []:
        banner_cpes = list(banner.get("cpe") or []) + list(banner.get("cpe23") or [])
        cpes.update(banner_cpes)
        # Per-banner vulns are a dict keyed by CVE ID
        vulns.update((banner.get("vulns") or {}).keys())
        services.append(ShodanService(
            port=int(banner.get("port", 0)),
            transport=banner.get("transport") or "tcp",
            product=banner.get("product") or "",
            version=banner.get("version") or "",
            module=((banner.get("_shodan") or {}).get("module") or "").split("-")[0],
            cpes=_sorted_unique(banner_cpes),
            timestamp=(banner.get("timestamp") or "")[:10],
        ))
    services.sort(key=lambda s: (s.port, s.transport))

    return ShodanHost(
        ip=data.get("ip_str") or ip,
        source="shodan",
        found=True,
        hostnames=_sorted_unique(data.get("hostnames") or []),
        ports=_sorted_unique(int(p) for p in data.get("ports") or [s.port for s in services]),
        cpes=_sorted_unique(cpes),
        tags=_sorted_unique(data.get("tags") or []),
        vulns=_sorted_unique(vulns),
        org=data.get("org") or "",
        isp=data.get("isp") or "",
        os=data.get("os") or "",
        country=data.get("country_name") or "",
        last_update=(data.get("last_update") or "")[:10],
        services=services,
    )


# ---------------------------------------------------------------------------
# Targets and comparison
# ---------------------------------------------------------------------------

def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def resolve_targets(target: str, scan: Optional[dict] = None) -> list[str]:
    """
    IPs to look up. Prefer hosts the nmap scan found up (that covers CIDR ranges
    and hostnames already resolved by nmap); otherwise resolve the target ourselves.
    """
    ips = [h.get("address") for h in (scan or {}).get("hosts", []) if h.get("state") == "up"]
    ips = [ip for ip in ips if ip]
    if ips:
        return list(dict.fromkeys(ips))
    try:
        ipaddress.ip_address(target)
        return [target]
    except ValueError:
        pass
    try:
        return [socket.gethostbyname(target)]
    except (socket.gaierror, UnicodeError):
        return []


def compare_with_scan(host: ShodanHost, scan: Optional[dict]) -> None:
    """Record which open ports only Shodan saw, and which only our scan saw."""
    if not scan or not host.found:
        return
    ours = {
        p.get("port") for h in scan.get("hosts", []) if h.get("address") == host.ip
        for p in h.get("ports", []) if p.get("state") == "open"
    }
    theirs = set(host.ports)
    host.ports_only_in_shodan = sorted(theirs - ours)
    host.ports_only_in_scan = sorted(ours - theirs)
    host.likely_udp = [p for p in host.ports_only_in_shodan if p in COMMON_UDP_PORTS]


def recon(
    target: str,
    scan: Optional[dict] = None,
    client: Optional[ShodanRecon] = None,
    max_hosts: int = MAX_HOSTS_DEFAULT,
    on_progress: Optional[Callable[[int, int, str], None]] = None,
) -> ShodanReport:
    """Run Shodan lookups for the target (and hosts found by the scan)."""
    client = client or ShodanRecon()
    report = ShodanReport()

    ips = resolve_targets(target, scan)
    if not ips:
        report.skipped.append({"target": target, "reason": "could not resolve to an IP address"})
        return report

    public = []
    for ip in ips:
        if is_public_ip(ip):
            public.append(ip)
        else:
            report.skipped.append({"target": ip, "reason": "private or local address; Shodan only indexes public IPs"})

    if len(public) > max_hosts:
        for ip in public[max_hosts:]:
            report.skipped.append({"target": ip, "reason": f"over the {max_hosts}-host lookup limit"})
        public = public[:max_hosts]

    for i, ip in enumerate(public):
        if on_progress:
            on_progress(i, len(public), ip)
        host = client.lookup(ip)
        compare_with_scan(host, scan)
        report.hosts.append(host)

    report.api_problem = client.api_problem
    if on_progress:
        on_progress(len(public), len(public), "done")
    return report
