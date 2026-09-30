"""
Port and service scanning via python-nmap.

This module only does scanning and parsing. It returns plain dataclasses and
leaves all terminal output to the caller (main.py), so the reporter and other
modules can reuse the same results.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

import nmap


# ---------------------------------------------------------------------------
# Scan profiles
# ---------------------------------------------------------------------------

# Every profile works without root/admin. Profiles marked requires_root use
# SYN scans (-sS) or OS detection (-O), and nmap won't run those without
# elevated privileges.
SCAN_PROFILES: dict[str, dict] = {
    "quick": {
        "description": "Top 100 ports, no version detection",
        "arguments": "-T4 -F",
        "requires_root": False,
    },
    "standard": {
        "description": "Top 1000 ports with service/version detection",
        "arguments": "-T4 -sV --version-light",
        "requires_root": False,
    },
    "full": {
        "description": "All 65535 TCP ports with service/version detection",
        "arguments": "-T4 -p- -sV",
        "requires_root": False,
    },
    "stealth": {
        "description": "SYN scan of top 1000 ports + OS detection",
        "arguments": "-T3 -sS -sV -O",
        "requires_root": True,
    },
}

DEFAULT_PROFILE = "standard"

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)
_PORT_SPEC_RE = re.compile(r"^[0-9,\-]+$")


class ScanError(Exception):
    """Raised for any error the CLI should show to the user cleanly."""


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------

@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    cpe: list[str] = field(default_factory=list)

    @property
    def banner(self) -> str:
        """Human-readable product/version string, e.g. 'OpenSSH 8.9p1'."""
        return " ".join(p for p in (self.product, self.version, self.extra_info) if p).strip()


@dataclass
class HostResult:
    address: str
    hostname: str = ""
    state: str = "unknown"
    os_matches: list[str] = field(default_factory=list)
    ports: list[PortResult] = field(default_factory=list)

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.state == "open"]


@dataclass
class ScanResult:
    target: str
    profile: str
    arguments: str
    started_at: str
    finished_at: str = ""
    elapsed_seconds: float = 0.0
    command_line: str = ""
    hosts: list[HostResult] = field(default_factory=list)

    @property
    def hosts_up(self) -> list[HostResult]:
        return [h for h in self.hosts if h.state == "up"]

    @property
    def total_open_ports(self) -> int:
        return sum(len(h.open_ports) for h in self.hosts)

    def to_dict(self) -> dict:
        """JSON-serializable form, used by --output and by reporter/report.py."""
        return asdict(self)


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def validate_target(target: str) -> str:
    """
    Accept a single IP, a CIDR range, an nmap-style octet range
    (192.168.1.1-50), or a hostname. Raise ScanError otherwise.
    """
    target = target.strip()
    if not target:
        raise ScanError("Target cannot be empty.")

    # IP or CIDR
    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass

    # nmap last-octet range, e.g. 10.0.0.1-25
    m = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$", target)
    if m:
        start, end = int(m.group(2)), int(m.group(3))
        try:
            ipaddress.ip_address(f"{m.group(1)}{start}")
        except ValueError:
            raise ScanError(f"Invalid IP range: {target}")
        if not (0 <= start <= end <= 255):
            raise ScanError(f"Invalid IP range: {target}")
        return target

    if _HOSTNAME_RE.match(target):
        return target

    raise ScanError(f"'{target}' is not a valid IP, CIDR range, or hostname.")


def validate_ports(ports: Optional[str]) -> Optional[str]:
    """Validate a port spec like '22,80,443' or '1-1024'."""
    if ports is None:
        return None
    ports = ports.replace(" ", "")
    if not _PORT_SPEC_RE.match(ports):
        raise ScanError(f"Invalid port specification: '{ports}'")
    for chunk in ports.split(","):
        for num in filter(None, chunk.split("-")):
            if not 1 <= int(num) <= 65535:
                raise ScanError(f"Port out of range (1-65535): {num}")
    return ports


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def parse_service_cpes(xml_output) -> dict[tuple[str, str, int], list[str]]:
    """
    Map (address, protocol, port) -> every CPE nmap reported for that service.

    python-nmap overwrites earlier <cpe> elements with later ones, so for an SSH
    port reporting both cpe:/a:openbsd:openssh:6.6.1p1 and cpe:/o:linux:linux_kernel
    it keeps only the kernel. We read nmap's XML directly to keep all of them.
    """
    if isinstance(xml_output, bytes):
        xml_output = xml_output.decode("utf-8", errors="replace")
    if not xml_output or "<nmaprun" not in xml_output:
        return {}
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        return {}

    out: dict[tuple[str, str, int], list[str]] = {}
    for host in root.iter("host"):
        addr_el = next((a for a in host.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")), None)
        if addr_el is None:
            continue
        address = addr_el.get("addr", "")
        for port in host.iter("port"):
            try:
                key = (address, port.get("protocol", ""), int(port.get("portid", 0)))
            except ValueError:
                continue
            out[key] = [c.text.strip() for c in port.findall("service/cpe") if c.text and c.text.strip()]
    return out


class NmapScanner:
    """Thin wrapper around nmap.PortScanner that returns typed results."""

    def __init__(self) -> None:
        if not nmap_available():
            raise ScanError(
                "The nmap binary was not found on PATH. python-nmap is only a wrapper; "
                "install nmap itself (https://nmap.org/download.html) and try again."
            )
        try:
            self._scanner = nmap.PortScanner()
        except nmap.PortScannerError as exc:
            raise ScanError(f"Could not initialise nmap: {exc}") from exc

    @staticmethod
    def build_arguments(
        profile: str = DEFAULT_PROFILE,
        ports: Optional[str] = None,
        extra_args: Optional[str] = None,
    ) -> str:
        if profile not in SCAN_PROFILES:
            raise ScanError(
                f"Unknown profile '{profile}'. Choose from: {', '.join(SCAN_PROFILES)}"
            )
        args = SCAN_PROFILES[profile]["arguments"]

        if ports:
            # An explicit port list overrides the profile's port selection.
            args = re.sub(r"\s*(-F|-p-|-p\s*\S+|--top-ports\s+\d+)", "", args).strip()
            args += f" -p {ports}"

        if extra_args:
            args += f" {extra_args.strip()}"
        return args

    def scan(
        self,
        target: str,
        profile: str = DEFAULT_PROFILE,
        ports: Optional[str] = None,
        extra_args: Optional[str] = None,
        timeout: Optional[int] = None,
        on_status: Optional[Callable[[str], None]] = None,
    ) -> ScanResult:
        """
        Run a scan and return a ScanResult.

        on_status is an optional callback the CLI can use to update a spinner.
        """
        target = validate_target(target)
        ports = validate_ports(ports)
        arguments = self.build_arguments(profile, ports, extra_args)

        result = ScanResult(
            target=target,
            profile=profile,
            arguments=arguments,
            started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )

        if on_status:
            on_status(f"nmap {arguments} {target}")

        try:
            raw = self._scanner.scan(hosts=target, arguments=arguments, timeout=timeout or 0)
        except nmap.PortScannerTimeout as exc:
            raise ScanError(f"Scan timed out after {timeout}s.") from exc
        except nmap.PortScannerError as exc:
            msg = str(exc)
            if "root" in msg.lower() or "privileged" in msg.lower():
                msg += (
                    "\nThis profile needs root/administrator privileges. "
                    "Re-run with sudo, or choose a non-root profile such as 'standard'."
                )
            raise ScanError(msg) from exc

        stats = raw.get("nmap", {}).get("scanstats", {})
        result.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        result.elapsed_seconds = float(stats.get("elapsed", 0) or 0)
        result.command_line = self._scanner.command_line()
        all_cpes = parse_service_cpes(self._scanner.get_nmap_last_output())
        result.hosts = [self._parse_host(h, all_cpes) for h in self._scanner.all_hosts()]
        return result

    # -- parsing ------------------------------------------------------------

    def _parse_host(self, address: str, all_cpes: Optional[dict] = None) -> HostResult:
        data = self._scanner[address]
        host = HostResult(
            address=address,
            hostname=data.hostname() or "",
            state=data.state(),
        )

        for match in data.get("osmatch", [])[:3]:
            name, accuracy = match.get("name"), match.get("accuracy")
            if name:
                host.os_matches.append(f"{name} ({accuracy}%)" if accuracy else name)

        for proto in data.all_protocols():
            for port in sorted(data[proto].keys()):
                info = data[proto][port]
                # Prefer CPEs from the raw XML: python-nmap keeps only the last <cpe> per port.
                cpes = (all_cpes or {}).get((address, proto, int(port)))
                if cpes is None:
                    cpes = [c for c in (info.get("cpe", "") or "").split() if c]
                host.ports.append(
                    PortResult(
                        port=int(port),
                        protocol=proto,
                        state=info.get("state", ""),
                        service=info.get("name", ""),
                        product=info.get("product", ""),
                        version=info.get("version", ""),
                        extra_info=info.get("extrainfo", ""),
                        cpe=cpes,
                    )
                )
        return host
