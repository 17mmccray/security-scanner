#!/usr/bin/env python3
"""
Security Scanner: an automated security audit CLI.

Pipeline: nmap scan -> (optional) Shodan recon -> CVE lookup -> report.

Usage:
    python main.py --target example.com --output report.html
    python main.py --target 192.168.1.1 --shodan --output report.html
    python main.py --target example.com --output report.md
    python main.py --target 10.0.0.0/24 --profile quick --output scan.json
    python main.py --list-profiles

Only scan systems you own or have written permission to test.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from reporter.report import ReportError, generate_report
from scanner.cve_lookup import (
    SEVERITY_ORDER,
    CVELookupError,
    CVEReport,
    NVDClient,
    lookup_scan,
)
from scanner.nmap_scan import (
    DEFAULT_PROFILE,
    SCAN_PROFILES,
    NmapScanner,
    ScanError,
    ScanResult,
)

try:  # load API keys from .env if python-dotenv is installed
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

__version__ = "0.3.1"

SEVERITY_STYLES = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "NONE": "dim",
    "UNKNOWN": "dim",
}

OUTPUT_FORMATS = {".html": "html", ".md": "markdown", ".json": "json"}

console = Console()
err_console = Console(stderr=True)

STATE_STYLES = {
    "open": "bold green",
    "closed": "red",
    "filtered": "yellow",
    "open|filtered": "yellow",
    "unfiltered": "cyan",
}


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def print_banner() -> None:
    console.print(
        Panel.fit(
            f"[bold cyan]Security Scanner[/] v{__version__}\n"
            "[dim]Automated security audit. Authorized use only.[/]",
            border_style="cyan",
        )
    )


def stage(number: int, title: str) -> None:
    console.print(Rule(f"[bold]Step {number}: {title}[/]", align="left", style="blue"))


def skipped(reason: str) -> None:
    console.print(f"[dim]Skipped: {reason}[/]\n")


def render_scan(result: ScanResult, show_closed: bool = False) -> None:
    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="bold")
    summary.add_column()
    summary.add_row("Target", result.target)
    summary.add_row("Profile", result.profile)
    summary.add_row("Command", f"[dim]{result.command_line}[/]")
    summary.add_row("Hosts up", f"{len(result.hosts_up)} / {len(result.hosts)}")
    summary.add_row("Open ports", str(result.total_open_ports))
    summary.add_row("Elapsed", f"{result.elapsed_seconds:.1f}s")
    console.print(Panel(summary, title="Scan summary", border_style="blue", expand=False))

    if not result.hosts:
        console.print("[yellow]No hosts responded. They may be down or blocking probes.[/]")
        console.print('[dim]Tip: try --extra-args "-Pn" to skip host discovery.[/]')
        return

    for host in result.hosts:
        title = host.address + (f" ({host.hostname})" if host.hostname else "")
        state_style = "green" if host.state == "up" else "red"
        ports = host.ports if show_closed else host.open_ports

        if not ports:
            console.print(f"\n[bold]{title}[/]  [{state_style}]{host.state}[/]")
            console.print("  [dim]No open ports found.[/]")
        else:
            table = Table(
                title=f"[bold]{title}[/]  [{state_style}]{host.state}[/]",
                title_justify="left",
                box=box.SIMPLE_HEAVY,
                header_style="bold magenta",
            )
            table.add_column("Port", justify="right", style="cyan", no_wrap=True)
            table.add_column("Proto")
            table.add_column("State")
            table.add_column("Service")
            table.add_column("Product / Version", overflow="fold")
            for p in ports:
                style = STATE_STYLES.get(p.state, "")
                table.add_row(
                    str(p.port),
                    p.protocol,
                    f"[{style}]{p.state}[/]" if style else p.state,
                    p.service or "-",
                    p.banner or "[dim]-[/]",
                )
            console.print(table)

        if host.os_matches:
            console.print(f"  [bold]OS guess:[/] {', '.join(host.os_matches)}")
        console.print()


def sev(severity: str) -> str:
    style = SEVERITY_STYLES.get(severity, "")
    return f"[{style}] {severity.title()} [/]" if style else severity.title()


def render_cves(report: CVEReport, verbose: bool = False) -> None:
    counts = report.severity_counts()
    parts = [f"{sev(s)} {counts[s]}" for s in SEVERITY_ORDER[:4]]
    kev = report.kev_count()
    if kev:
        parts.append(f"[bold red]⚠ {kev} known exploited (CISA KEV)[/]")
    console.print("  ".join(parts) + "\n")

    for svc in report.services:
        label = f"{svc.host}:{svc.port}/{svc.protocol}  {svc.product or svc.service} {svc.version}".rstrip()
        if svc.query_method == "skipped":
            console.print(f"[bold]{label}[/]  [dim]skipped: {svc.note}[/]\n")
            continue
        if not svc.cves:
            tried = len(svc.queries_tried)
            console.print(
                f"[bold]{label}[/]  [green]no CVEs found in NVD[/] "
                f"[dim]({tried} quer{'y' if tried == 1 else 'ies'} tried{'' if verbose else '; use -v to see them'})[/]\n"
            )
            continue

        conf = "" if svc.confidence == "high" else "  [yellow](keyword match, verify manually)[/]"
        caption = [f"[dim]{svc.note}[/]"] if svc.note else []
        if svc.distro:
            caption.append(
                f"[yellow]{svc.distro} package:[/] [dim]distros often backport fixes without changing the "
                f"version number, so some of these may already be patched.[/]"
            )
        table = Table(
            title=f"[bold]{label}[/]{conf}",
            title_justify="left",
            box=box.SIMPLE,
            header_style="bold magenta",
            caption="\n".join(caption) or None,
            caption_justify="left",
        )
        table.add_column("CVE", style="cyan", no_wrap=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("CVSS", justify="right")
        table.add_column("Description", overflow="fold", max_width=70)
        for c in svc.cves:
            desc = c.description if len(c.description) <= 160 else c.description[:157] + "..."
            cve_id = f"{c.cve_id} [bold red]⚠[/]" if c.known_exploited else c.cve_id
            score = f"{c.cvss_score:.1f}" if c.cvss_score is not None else "-"
            table.add_row(cve_id, sev(c.severity), score, desc)
        console.print(table)
        console.print()


def log_query(method: str, query: str, count: int, message: str) -> None:
    kind = "CPE    " if method == "cpe" else "keyword"
    noun = "match" if count == 1 else "matches"
    result = f"[green]{count} {noun}[/]" if count else "[yellow]0 matches[/]"
    extra = f" [red]({message})[/]" if message else ""
    console.print(f"  [dim]NVD {kind}[/] {query}  → {result}{extra}")


def list_profiles() -> None:
    table = Table(title="Scan profiles", box=box.ROUNDED, header_style="bold magenta")
    table.add_column("Name", style="cyan")
    table.add_column("Description")
    table.add_column("nmap arguments", style="dim")
    table.add_column("Root?", justify="center")
    for name, p in SCAN_PROFILES.items():
        label = f"{name} [dim](default)[/]" if name == DEFAULT_PROFILE else name
        table.add_row(label, p["description"], p["arguments"], "yes" if p["requires_root"] else "no")
    console.print(table)


def save_json(data: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))
    console.print(f"[green]✓[/] Results saved to [bold]{path}[/]")


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def confirm_authorization(target: str) -> bool:
    console.print(
        f"[yellow]You are about to scan [bold]{target}[/bold]. "
        "Only scan systems you own or are authorized to test.[/]"
    )
    return console.input("Continue? [y/N] ").strip().lower().startswith("y")


def run(args: argparse.Namespace) -> int:
    output_path = Path(args.output) if args.output else None
    output_format = OUTPUT_FORMATS.get(output_path.suffix.lower()) if output_path else None

    if not args.yes and not confirm_authorization(args.target):
        console.print("[dim]Aborted.[/]")
        return 1

    findings: dict = {"target": args.target, "tool_version": __version__}

    # Step 1: nmap scan
    stage(1, "Port & service scan")
    if SCAN_PROFILES[args.profile]["requires_root"]:
        console.print(f"[yellow]Note:[/] the '{args.profile}' profile needs root/administrator privileges.")

    scanner = NmapScanner()
    with console.status("[bold cyan]Starting scan...", spinner="dots") as status:
        scan = scanner.scan(
            target=args.target,
            profile=args.profile,
            ports=args.ports,
            extra_args=args.extra_args,
            timeout=args.timeout,
            on_status=lambda msg: status.update(f"[bold cyan]Running:[/] [dim]{msg}[/]"),
        )
    render_scan(scan, show_closed=args.show_closed)
    findings["scan"] = scan.to_dict()

    # Step 2: Shodan passive recon (opt-in)
    stage(2, "Shodan passive recon")
    if not args.shodan:
        skipped("pass --shodan to enable")
    else:
        # TODO: wire up scanner/shodan_recon.py
        skipped("Shodan module not implemented yet")

    # Step 3: CVE lookup
    stage(3, "CVE lookup (NVD)")
    if args.no_cve:
        skipped("--no-cve was set")
    elif scan.total_open_ports == 0:
        skipped("no open ports to check")
    else:
        client = NVDClient(use_cache=not args.no_cache)
        if not client.api_key:
            console.print(
                "[dim]No NVD_API_KEY set: limited to 5 requests per 30s, so this may take a while.[/]"
            )
        try:
            with console.status("[bold cyan]Querying NVD...", spinner="dots") as status:
                cve_report = lookup_scan(
                    findings["scan"],
                    client=client,
                    max_per_service=args.max_cves,
                    on_progress=lambda done, total, label: status.update(
                        f"[bold cyan]Querying NVD[/] [{done}/{total}] [dim]{label}[/]"
                    ),
                    on_query=log_query if args.verbose else None,
                )
        except CVELookupError as exc:
            console.print(f"[red]CVE lookup failed:[/] {exc}")
            console.print("[dim]Continuing without CVE data.[/]\n")
        else:
            render_cves(cve_report, verbose=args.verbose)
            findings["cves"] = cve_report.to_dict()

    # Step 4: Report
    stage(4, "Report")
    if not output_path:
        skipped("no --output given")
    elif output_format == "json":
        save_json(findings, output_path)
    else:
        try:
            path = generate_report(findings, output_path, fmt=output_format)
        except (ReportError, OSError) as exc:
            fallback = output_path.with_suffix(".json")
            console.print(f"[red]Report generation failed:[/] {exc}")
            console.print("[dim]Saving raw findings as JSON so the scan isn't lost.[/]")
            save_json(findings, fallback)
            return 1
        label = {"html": "HTML", "markdown": "Markdown"}.get(output_format, output_format)
        console.print(f"[green]✓[/] {label} report written to [bold]{path}[/]")
        if args.save_json:
            save_json(findings, output_path.with_suffix(".json"))

    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def positive_int(value: str) -> int:
    n = int(value)
    if n <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return n


def output_file(value: str) -> str:
    suffix = Path(value).suffix.lower()
    if suffix not in OUTPUT_FORMATS:
        raise argparse.ArgumentTypeError(
            f"unsupported extension '{suffix or '(none)'}'; use one of: {', '.join(OUTPUT_FORMATS)}"
        )
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Automated security audit: port scan, passive recon, CVE lookup, and reporting.",
        epilog="Only scan systems you own or have explicit permission to test.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    core = parser.add_argument_group("core options")
    core.add_argument("--target", "-t", help="domain, IP, CIDR range (10.0.0.0/24), or range (10.0.0.1-20)")
    core.add_argument(
        "--output", "-o", type=output_file,
        help="report file; format from extension: .html, .md, or .json",
    )
    core.add_argument("--shodan", action="store_true", help="include Shodan passive recon (needs SHODAN_API_KEY)")
    core.add_argument("--no-cve", action="store_true", help="skip the NVD CVE lookup")
    core.add_argument(
        "--save-json", action="store_true",
        help="also save raw findings as JSON next to an .html/.md report (re-render later with reporter.report)",
    )

    cve = parser.add_argument_group("CVE options")
    cve.add_argument(
        "--max-cves", type=positive_int, default=10,
        help="max CVEs to show per service, most severe first (default: 10)",
    )
    cve.add_argument("--no-cache", action="store_true", help="ignore the 24h NVD response cache")
    cve.add_argument("--verbose", "-v", action="store_true", help="show every NVD query and its result count")

    scan = parser.add_argument_group("scan options")
    scan.add_argument(
        "--profile", "-P", choices=SCAN_PROFILES.keys(), default=DEFAULT_PROFILE,
        help=f"nmap scan profile (default: {DEFAULT_PROFILE}); see --list-profiles",
    )
    scan.add_argument("--ports", "-p", help="port list/range, overrides the profile (e.g. 22,80,443 or 1-1024)")
    scan.add_argument("--extra-args", "-x", help='additional raw nmap arguments, e.g. "-Pn"')
    scan.add_argument("--timeout", type=positive_int, help="abort the scan after N seconds")
    scan.add_argument("--show-closed", action="store_true", help="also list closed/filtered ports")

    misc = parser.add_argument_group("other")
    misc.add_argument("--list-profiles", action="store_true", help="show available scan profiles and exit")
    misc.add_argument("--yes", "-y", action="store_true", help="skip the authorization confirmation prompt")
    misc.add_argument("--no-banner", action="store_true", help="suppress the startup banner")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.no_banner:
        print_banner()

    if args.list_profiles:
        list_profiles()
        return 0

    if not args.target:
        parser.error("--target is required")

    try:
        return run(args)
    except ScanError as exc:
        err_console.print(f"[bold red]Error:[/] {exc}")
        return 1
    except KeyboardInterrupt:
        err_console.print("\n[yellow]Interrupted.[/]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
