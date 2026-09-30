"""
CVE lookup against the NIST National Vulnerability Database (NVD) API 2.0.

Takes the services found by nmap_scan.py and returns known CVEs for each one,
with CVSS scores mapped to Critical / High / Medium / Low.

Lookup strategy, per service:
  1. CPE match (high confidence). nmap reports CPEs like
     "cpe:/a:openbsd:openssh:8.9p1". We convert those to CPE 2.3 and query
     NVD's `virtualMatchString`, which also matches CVEs whose affected
     configuration is a version *range* containing our version.
  2. Keyword fallback (low confidence). If there's no usable CPE but nmap
     did get a product + version, search NVD descriptions for them.
  Services with no version are skipped: "every CVE ever filed against
  Apache" isn't a useful finding.

API key: set NVD_API_KEY (free at https://nvd.nist.gov/developers/request-an-api-key).
Without one, NVD allows 5 requests per rolling 30 seconds; with one, 50.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CVE_URL = "https://nvd.nist.gov/vuln/detail/{}"

CACHE_DIR = Path.home() / ".cache" / "security-scanner" / "nvd"
CACHE_TTL_SECONDS = 24 * 60 * 60

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"]


class CVELookupError(Exception):
    """Raised for errors the CLI should show cleanly."""


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

def score_to_severity(score: Optional[float]) -> str:
    """CVSS v3/v4 qualitative rating scale."""
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def severity_rank(severity: str) -> int:
    """Lower is worse. Useful as a sort key."""
    try:
        return SEVERITY_ORDER.index(severity.upper())
    except ValueError:
        return len(SEVERITY_ORDER)


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------

@dataclass
class CVEFinding:
    cve_id: str
    description: str
    cvss_score: Optional[float]
    severity: str
    cvss_version: str = ""
    vector: str = ""
    published: str = ""
    known_exploited: bool = False  # listed in CISA's Known Exploited Vulnerabilities catalog
    url: str = ""
    references: list[str] = field(default_factory=list)


@dataclass
class ServiceCVEs:
    host: str
    port: int
    protocol: str
    service: str
    product: str
    version: str
    query_method: str  # "cpe", "keyword", or "skipped"
    query: str = ""
    confidence: str = ""  # "high" (CPE) or "low" (keyword)
    total_results: int = 0
    note: str = ""
    distro: str = ""  # e.g. "Ubuntu": distro packages backport fixes without changing versions
    queries_tried: list[str] = field(default_factory=list)
    cves: list[CVEFinding] = field(default_factory=list)  # displayed subset, most severe first
    # Lightweight record of *every* matched CVE, so totals aren't limited to the displayed subset
    all_matches: list[dict] = field(default_factory=list)

    @property
    def worst_severity(self) -> str:
        pool = self.all_matches or [{"severity": c.severity} for c in self.cves]
        if not pool:
            return "NONE"
        return min((m["severity"] for m in pool), key=severity_rank)


@dataclass
class CVEReport:
    services: list[ServiceCVEs] = field(default_factory=list)

    @property
    def all_cves(self) -> list[CVEFinding]:
        """The displayed CVEs across all services."""
        return [c for s in self.services for c in s.cves]

    def _all_matches(self) -> dict[str, dict]:
        unique: dict[str, dict] = {}
        for s in self.services:
            pool = s.all_matches or [
                {"cve_id": c.cve_id, "severity": c.severity, "known_exploited": c.known_exploited} for c in s.cves
            ]
            for m in pool:
                unique.setdefault(m["cve_id"], m)
        return unique

    def severity_counts(self) -> dict[str, int]:
        """Counts of unique CVE IDs by severity, across every match (not just those displayed)."""
        counts = {s: 0 for s in SEVERITY_ORDER}
        for m in self._all_matches().values():
            counts[m["severity"]] = counts.get(m["severity"], 0) + 1
        return counts

    def kev_count(self) -> int:
        return sum(1 for m in self._all_matches().values() if m.get("known_exploited"))

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity_counts"] = self.severity_counts()
        data["kev_count"] = self.kev_count()
        return data


# ---------------------------------------------------------------------------
# CPE helpers
# ---------------------------------------------------------------------------

_OPENSSH_STYLE = re.compile(r"^(\d+(?:\.\d+)*)(p\d+)$")  # 8.9p1 -> 8.9 + p1


def cpe22_to_23(cpe: str, fallback_version: str = "") -> Optional[str]:
    """
    Convert an nmap CPE 2.2 URI (cpe:/a:vendor:product:version) to a
    CPE 2.3 match string. Returns None for CPEs we can't meaningfully
    query (no product, or no version available at all).
    """
    if cpe.startswith("cpe:2.3:"):
        return cpe
    if not cpe.startswith("cpe:/"):
        return None

    parts = cpe[len("cpe:/"):].split(":")
    part = parts[0] if parts else ""
    vendor = parts[1] if len(parts) > 1 else ""
    product = parts[2] if len(parts) > 2 else ""
    version = parts[3] if len(parts) > 3 else ""
    update = parts[4] if len(parts) > 4 else ""

    if part not in ("a", "o", "h") or not vendor or not product:
        return None

    if not version:
        version = _clean_version(fallback_version)
    if not version:
        return None

    m = _OPENSSH_STYLE.match(version)
    if m and not update:
        version, update = m.group(1), m.group(2)

    fields = [part, vendor, product, version, update or "*"] + ["*"] * 6
    return "cpe:2.3:" + ":".join(_escape_cpe(f) for f in fields)


def _clean_version(version: str) -> str:
    """Pull a usable version token out of nmap's version string."""
    m = re.match(r"^\s*v?(\d+(?:\.\d+)*[a-z0-9]*)", version or "", re.IGNORECASE)
    return m.group(1) if m else ""


def _escape_cpe(value: str) -> str:
    if value == "*":
        return value
    return re.sub(r"([^A-Za-z0-9._\-~])", r"\\\1", value)


def _numeric_prefix_cpe(cpe23: str) -> Optional[str]:
    """If the version has a suffix (e.g. 2.4.49-ubuntu), retry with just 2.4.49."""
    fields = cpe23.split(":")
    if len(fields) < 6:
        return None
    m = re.match(r"^(\d+(?:\.\d+)*)", fields[5])
    if not m or m.group(1) == fields[5]:
        return None
    fields[5] = m.group(1)
    return ":".join(fields)


# ---------------------------------------------------------------------------
# NVD client
# ---------------------------------------------------------------------------

class NVDClient:
    """Minimal NVD API 2.0 client with rate limiting, retries, and a disk cache."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        use_cache: bool = True,
        session: Optional[requests.Session] = None,
        request_timeout: int = 30,
        max_retries: int = 4,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.api_key = api_key if api_key is not None else os.environ.get("NVD_API_KEY") or None
        self.use_cache = use_cache
        self.session = session or requests.Session()
        self.session.headers.setdefault("User-Agent", "security-scanner (github.com/17mmccray/security-scanner)")
        if self.api_key:
            self.session.headers["apiKey"] = self.api_key
        self.request_timeout = request_timeout
        self.max_retries = max_retries
        self._sleep = sleep

        # NVD limits: 5 req / 30s without key, 50 req / 30s with key.
        self._window = 30.0
        self._limit = 50 if self.api_key else 5
        self._recent: deque[float] = deque()
        self._memory_cache: dict[str, dict] = {}

    # -- public -------------------------------------------------------------

    def search(self, *, max_results: int = 20, **params) -> dict:
        """Run one NVD query. Params are passed straight to the API."""
        params = {k: v for k, v in params.items() if v is not None}
        params["resultsPerPage"] = min(max(max_results, 1), 2000)

        key = self._cache_key(params)
        if key in self._memory_cache:
            return self._memory_cache[key]
        cached = self._read_disk_cache(key)
        if cached is not None:
            self._memory_cache[key] = cached
            return cached

        data = self._get(params)
        self._memory_cache[key] = data
        self._write_disk_cache(key, data)
        return data

    # -- HTTP ---------------------------------------------------------------

    def _throttle(self) -> None:
        now = time.monotonic()
        while self._recent and now - self._recent[0] > self._window:
            self._recent.popleft()
        if len(self._recent) >= self._limit:
            wait = self._window - (now - self._recent[0]) + 0.5
            if wait > 0:
                self._sleep(wait)
        self._recent.append(time.monotonic())

    def _get(self, params: dict) -> dict:
        last_error = ""
        for attempt in range(self.max_retries + 1):
            self._throttle()
            try:
                resp = self.session.get(NVD_API_URL, params=params, timeout=self.request_timeout)
            except requests.RequestException as exc:
                last_error = f"network error: {exc}"
            else:
                if resp.status_code == 200:
                    try:
                        return resp.json()
                    except ValueError:
                        last_error = "NVD returned invalid JSON"
                elif resp.status_code == 404:
                    # NVD answers 404 for queries it considers invalid (e.g. malformed CPE).
                    msg = resp.headers.get("message") or "query rejected (HTTP 404)"
                    return {"totalResults": 0, "vulnerabilities": [], "_note": msg}
                elif resp.status_code in (403, 429, 500, 502, 503, 504):
                    # 403 is NVD's usual rate-limit response.
                    last_error = f"HTTP {resp.status_code}"
                else:
                    raise CVELookupError(
                        f"NVD API error HTTP {resp.status_code}: {resp.headers.get('message', resp.text[:200])}"
                    )

            if attempt < self.max_retries:
                self._sleep(min(6 * (2 ** attempt), 60))

        hint = "" if self.api_key else " Setting NVD_API_KEY raises the rate limit tenfold."
        raise CVELookupError(f"NVD API request failed after {self.max_retries + 1} attempts ({last_error}).{hint}")

    # -- cache --------------------------------------------------------------

    @staticmethod
    def _cache_key(params: dict) -> str:
        blob = json.dumps(params, sort_keys=True)
        return hashlib.sha256(blob.encode()).hexdigest()[:32]

    def _read_disk_cache(self, key: str) -> Optional[dict]:
        if not self.use_cache:
            return None
        path = CACHE_DIR / f"{key}.json"
        try:
            if time.time() - path.stat().st_mtime > CACHE_TTL_SECONDS:
                return None
            return json.loads(path.read_text())
        except (OSError, ValueError):
            return None

    def _write_disk_cache(self, key: str, data: dict) -> None:
        if not self.use_cache:
            return
        try:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            (CACHE_DIR / f"{key}.json").write_text(json.dumps(data))
        except OSError:
            pass  # caching is best-effort


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_cve(item: dict) -> CVEFinding:
    cve = item.get("cve", item)
    cve_id = cve.get("id", "")

    description = next(
        (d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        "",
    )

    score, version, vector, severity = _best_cvss(cve.get("metrics", {}))
    refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]

    return CVEFinding(
        cve_id=cve_id,
        description=" ".join(description.split()),  # NVD text can contain stray newlines
        cvss_score=score,
        severity=severity or score_to_severity(score),
        cvss_version=version,
        vector=vector,
        published=(cve.get("published") or "")[:10],
        known_exploited=bool(cve.get("cisaExploitAdd")),
        url=NVD_CVE_URL.format(cve_id) if cve_id else "",
        references=refs[:5],
    )


def _best_cvss(metrics: dict) -> tuple[Optional[float], str, str, str]:
    """Prefer the newest CVSS version available, and NVD's Primary score within it."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData", {})
        score = data.get("baseScore")
        severity = (data.get("baseSeverity") or entry.get("baseSeverity") or "").upper()
        if key == "cvssMetricV2":
            # v2 had no Critical band; re-rate on the v3 scale so everything is comparable.
            severity = score_to_severity(score)
        return (
            float(score) if score is not None else None,
            data.get("version", ""),
            data.get("vectorString", ""),
            severity,
        )
    return None, "", "", "UNKNOWN"


# ---------------------------------------------------------------------------
# High-level lookup
# ---------------------------------------------------------------------------

def _iter_open_services(scan: dict) -> Iterable[tuple[str, dict]]:
    for host in scan.get("hosts", []):
        for port in host.get("ports", []):
            if port.get("state") == "open":
                yield host.get("address", ""), port


_DISTRO_RE = re.compile(
    r"\b(ubuntu|debian|red ?hat|rhel|centos|rocky|alma|fedora|suse|amazon linux|alpine|raspbian)\b",
    re.IGNORECASE,
)

# NVD returns up to 2,000 CVEs per request, so one request gets every match in practice.
NVD_MAX_PAGE = 2000


def detect_distro(port: dict) -> str:
    """Return the distro name if the banner shows a distro package (fixes are often backported)."""
    text = " ".join(port.get(k) or "" for k in ("version", "extra_info", "product"))
    m = _DISTRO_RE.search(text)
    if not m:
        return ""
    name = m.group(1).lower().replace(" ", "")
    return {"redhat": "Red Hat", "rhel": "Red Hat", "centos": "CentOS", "suse": "SUSE",
            "amazonlinux": "Amazon Linux"}.get(name, name.title())


def candidate_tiers(port: dict) -> list[list[tuple[str, str]]]:
    """
    NVD queries for one service, grouped into tiers from most to least precise.
    lookup_scan runs every query in a tier, merges the results, and stops at the
    first tier that finds anything.

    For "cpe:/a:openbsd:openssh:6.6.1p1":
      tier 1  cpe      cpe:2.3:a:openbsd:openssh:6.6.1:p1:...   exact version + update
              cpe      cpe:2.3:a:openbsd:openssh:6.6.1:*:...    same version, any update
      tier 2  keyword  OpenSSH 6.6.1p1                          text search (low confidence)

    Both tier-1 queries are needed: NVD mostly describes OpenSSH CVEs as ranges
    ("before 7.2") with the update field open, and a query pinned to "p1" misses
    those, while a few entries are written specifically against "p1".
    """
    product = (port.get("product") or "").strip()
    version = (port.get("version") or "").strip()
    tiers: list[list[tuple[str, str]]] = []
    seen: set[tuple[str, str]] = set()

    def tier(*items: tuple[str, Optional[str]]) -> None:
        group = [(m, q) for m, q in items if q and (m, q) not in seen]
        seen.update(group)
        if group:
            tiers.append(group)

    for cpe in port.get("cpe", []) or []:
        # Only application CPEs may inherit the service's version. nmap also attaches OS CPEs like
        # cpe:/o:linux:linux_kernel to a port; giving those the SSH version would query the wrong product.
        is_app = cpe.startswith("cpe:/a:") or cpe.startswith("cpe:2.3:a:")
        cpe23 = cpe22_to_23(cpe, fallback_version=version if is_app else "")
        # Only CPEs with a concrete version are specific enough to be useful.
        if not cpe23 or cpe23.split(":")[5] in ("*", "-", ""):
            continue
        fields = cpe23.split(":")
        any_update = ":".join(fields[:6] + ["*"] + fields[7:]) if fields[6] != "*" else None
        tier(("cpe", cpe23), ("cpe", any_update))
        tier(("cpe", _numeric_prefix_cpe(cpe23)))

    clean = _clean_version(version)
    if product and clean:
        tier(("keyword", f"{product} {clean}"))
    return tiers


def candidate_queries(port: dict) -> list[tuple[str, str]]:
    """Every query candidate_tiers would try, flattened, most precise first."""
    return [q for t in candidate_tiers(port) for q in t]


def plan_query(port: dict) -> tuple[str, str]:
    """The first (most specific) query for a service, or ("skipped", "")."""
    candidates = candidate_queries(port)
    return candidates[0] if candidates else ("skipped", "")


def lookup_scan(
    scan: dict,
    client: Optional[NVDClient] = None,
    max_per_service: int = 10,
    on_progress: Optional[Callable[[int, int, str], None]] = None,
    on_query: Optional[Callable[[str, str, int, str], None]] = None,
) -> CVEReport:
    """
    Look up CVEs for every open service in a scan (ScanResult.to_dict()).

    on_progress(done, total, label) lets the CLI drive a progress bar.
    on_query(method, query, result_count, nvd_message) reports each NVD query (for --verbose).
    """
    client = client or NVDClient()
    services = list(_iter_open_services(scan))
    report = CVEReport()

    for i, (address, port) in enumerate(services):
        label = f"{address}:{port.get('port')} {port.get('product') or port.get('service') or ''}".strip()
        if on_progress:
            on_progress(i, len(services), label)

        tiers = candidate_tiers(port)
        first = tiers[0][0] if tiers else ("skipped", "")
        entry = ServiceCVEs(
            host=address,
            port=int(port.get("port", 0)),
            protocol=port.get("protocol", ""),
            service=port.get("service", ""),
            product=port.get("product", ""),
            version=port.get("version", ""),
            query_method=first[0],
            query=first[1],
            distro=detect_distro(port),
        )

        if not tiers:
            entry.note = "no product version detected; nothing specific to look up"
            report.services.append(entry)
            continue

        merged: dict[str, dict] = {}  # cve_id -> raw NVD item, deduplicated across queries
        reported_total = 0
        for group in tiers:
            hits = []
            for method, query in group:
                key = "virtualMatchString" if method == "cpe" else "keywordSearch"
                data = client.search(max_results=NVD_MAX_PAGE, **{key: query})
                total = int(data.get("totalResults", 0) or 0)
                entry.queries_tried.append(query)
                if on_query:
                    on_query(method, query, total, data.get("_note", ""))
                if total:
                    hits.append(query)
                    reported_total = max(reported_total, total)
                    for item in data.get("vulnerabilities", []):
                        cve_id = item.get("cve", {}).get("id")
                        if cve_id:
                            merged.setdefault(cve_id, item)
            if merged:
                entry.query_method, entry.query = group[0][0], " | ".join(hits)
                break

        entry.confidence = {"cpe": "high", "keyword": "low"}[entry.query_method]
        entry.total_results = max(reported_total, len(merged))

        cves = [parse_cve(v) for v in merged.values()]
        cves.sort(key=lambda c: (severity_rank(c.severity), -(c.cvss_score or 0)))
        entry.all_matches = [
            {"cve_id": c.cve_id, "severity": c.severity, "cvss_score": c.cvss_score,
             "known_exploited": c.known_exploited}
            for c in cves
        ]

        shown = cves[:max_per_service]
        # Never hide an actively exploited CVE just because its CVSS score is lower.
        shown += [c for c in cves[max_per_service:] if c.known_exploited]
        entry.cves = shown

        notes = []
        if entry.query_method == "keyword" and first[0] == "cpe":
            notes.append("no exact version match in NVD; these came from a keyword search")
        if entry.total_results > len(cves):
            notes.append(f"{entry.total_results} total matches; the {len(cves)} returned are counted")
        if len(cves) > len(shown):
            notes.append(f"showing the {len(shown)} most severe of {len(cves)} matches")
        entry.note = "; ".join(notes)

        report.services.append(entry)

    if on_progress:
        on_progress(len(services), len(services), "done")
    return report
