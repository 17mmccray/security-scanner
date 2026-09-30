"""
Offline tests for scanner/shodan_recon.py. No network access needed.

Run with:  python -m unittest discover -s tests -v
"""

import copy
import unittest
from unittest import mock

from reporter import report as rp
from scanner import shodan_recon as sr

INTERNETDB_SCANME = {
    "ip": "45.33.32.156",
    "ports": [22, 80, 123, 31337],
    "cpes": ["cpe:/a:apache:http_server:2.4.7", "cpe:/a:openbsd:openssh:6.6.1p1", "cpe:/o:canonical:ubuntu_linux"],
    "hostnames": ["scanme.nmap.org"],
    "tags": [],
    "vulns": ["CVE-2016-0777", "CVE-2017-3167", "CVE-2099-9999"],
}

SHODAN_API_SCANME = {
    "ip_str": "45.33.32.156",
    "ports": [22, 80, 31337],
    "hostnames": ["scanme.nmap.org"],
    "org": "Linode", "isp": "Akamai Connected Cloud", "os": None, "country_name": "United States",
    "last_update": "2026-09-28T11:22:33.000000",
    "vulns": ["CVE-2017-3167"],
    "data": [
        {"port": 80, "transport": "tcp", "product": "Apache httpd", "version": "2.4.7",
         "cpe": ["cpe:/a:apache:http_server:2.4.7"], "cpe23": ["cpe:2.3:a:apache:http_server:2.4.7"],
         "vulns": {"CVE-2017-7679": {"cvss": 9.8, "verified": False}},
         "_shodan": {"module": "http"}, "timestamp": "2026-09-28T11:22:33"},
        {"port": 22, "transport": "tcp", "product": "OpenSSH", "version": "6.6.1p1 Ubuntu-2ubuntu2.13",
         "cpe": ["cpe:/a:openbsd:openssh:6.6.1p1"], "_shodan": {"module": "ssh"}, "timestamp": "2026-09-27"},
    ],
}

SCAN = {
    "target": "scanme.nmap.org",
    "hosts": [{
        "address": "45.33.32.156", "state": "up",
        "ports": [
            {"port": 22, "protocol": "tcp", "state": "open"},
            {"port": 80, "protocol": "tcp", "state": "open"},
            {"port": 9929, "protocol": "tcp", "state": "open"},
        ],
    }],
}


class FakeResponse:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = payload
        self.text = ""

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.headers = {}

    def get(self, url, params=None, timeout=None):
        self.calls.append((url, dict(params or {})))
        return self.responses.pop(0)


def make_client(responses, api_key=""):
    session = FakeSession(responses)
    return sr.ShodanRecon(api_key=api_key, session=session, sleep=lambda s: None), session


class ParseTests(unittest.TestCase):
    def test_internetdb(self):
        h = sr.parse_internetdb("45.33.32.156", INTERNETDB_SCANME)
        self.assertTrue(h.found)
        self.assertEqual(h.source, "internetdb")
        self.assertEqual(h.ports, [22, 80, 123, 31337])
        self.assertEqual(h.hostnames, ["scanme.nmap.org"])
        self.assertEqual(len(h.vulns), 3)

    def test_full_api(self):
        h = sr.parse_shodan_host("45.33.32.156", SHODAN_API_SCANME)
        self.assertEqual(h.source, "shodan")
        self.assertEqual(h.org, "Linode")
        self.assertEqual(h.last_update, "2026-09-28")
        self.assertEqual([s.port for s in h.services], [22, 80])  # sorted
        self.assertEqual(h.services[1].module, "http")
        # top-level vulns merged with per-banner vulns
        self.assertEqual(h.vulns, ["CVE-2017-3167", "CVE-2017-7679"])
        self.assertIn("cpe:2.3:a:apache:http_server:2.4.7", h.cpes)
        self.assertEqual(h.os, "")  # null becomes empty string


class ClientTests(unittest.TestCase):
    def test_no_key_uses_internetdb(self):
        client, session = make_client([FakeResponse(200, INTERNETDB_SCANME)])
        h = client.lookup("45.33.32.156")
        self.assertEqual(h.source, "internetdb")
        self.assertIn("internetdb.shodan.io", session.calls[0][0])

    def test_key_uses_full_api(self):
        client, session = make_client([FakeResponse(200, SHODAN_API_SCANME)], api_key="k")
        h = client.lookup("45.33.32.156")
        self.assertEqual(h.source, "shodan")
        self.assertEqual(session.calls[0][1], {"key": "k"})

    def test_free_key_403_falls_back_and_stops_using_api(self):
        client, session = make_client([
            FakeResponse(403, {"error": "Access denied (403 Forbidden)"}),
            FakeResponse(200, INTERNETDB_SCANME),
            FakeResponse(200, INTERNETDB_SCANME),
        ], api_key="free-key")
        h1 = client.lookup("45.33.32.156")
        self.assertEqual(h1.source, "internetdb")
        self.assertIn("membership", client.api_problem)
        self.assertFalse(client.api_usable)
        client.lookup("45.33.32.157")
        self.assertEqual(len(session.calls), 3)  # second host went straight to InternetDB
        self.assertIn("internetdb", session.calls[2][0])

    def test_invalid_key_401(self):
        client, _ = make_client([FakeResponse(401, {"error": "Invalid API key"}),
                                 FakeResponse(200, INTERNETDB_SCANME)], api_key="bad")
        client.lookup("45.33.32.156")
        self.assertEqual(client.api_problem, "invalid API key")

    def test_not_found(self):
        client, _ = make_client([FakeResponse(404, {"detail": "No information available"})])
        h = client.lookup("45.33.32.156")
        self.assertFalse(h.found)
        self.assertIn("no data", h.note)

    def test_rate_limit_raises(self):
        client, _ = make_client([FakeResponse(429, {})])
        with self.assertRaises(sr.ShodanError):
            client.lookup("45.33.32.156")

    def test_throttles_between_requests(self):
        waits = []
        session = FakeSession([FakeResponse(200, INTERNETDB_SCANME)] * 2)
        client = sr.ShodanRecon(api_key="", session=session, sleep=waits.append)
        client.lookup("45.33.32.156")
        client.lookup("45.33.32.157")
        self.assertEqual(len(waits), 1)
        self.assertGreater(waits[0], 0.5)


class TargetTests(unittest.TestCase):
    def test_public_ip(self):
        self.assertTrue(sr.is_public_ip("45.33.32.156"))
        for ip in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1", "not-an-ip"):
            self.assertFalse(sr.is_public_ip(ip))

    def test_prefers_scan_hosts(self):
        self.assertEqual(sr.resolve_targets("scanme.nmap.org", SCAN), ["45.33.32.156"])

    def test_resolves_hostname_without_scan(self):
        with mock.patch("socket.gethostbyname", return_value="45.33.32.156"):
            self.assertEqual(sr.resolve_targets("scanme.nmap.org"), ["45.33.32.156"])
        with mock.patch("socket.gethostbyname", side_effect=sr.socket.gaierror):
            self.assertEqual(sr.resolve_targets("nope.invalid"), [])


class ReconTests(unittest.TestCase):
    def test_compares_ports_with_scan(self):
        client, _ = make_client([FakeResponse(200, INTERNETDB_SCANME)])
        report = sr.recon("scanme.nmap.org", scan=SCAN, client=client)
        h = report.hosts[0]
        # Real InternetDB data for scanme (Sept 2026): 22, 80, 123, 31337. nmap found 22, 80, 9929.
        self.assertEqual(h.ports_only_in_shodan, [123, 31337])
        self.assertEqual(h.likely_udp, [123])  # NTP: invisible to a TCP scan
        self.assertEqual(h.ports_only_in_scan, [9929])

    def test_private_targets_skipped_without_requests(self):
        client, session = make_client([])
        scan = {"hosts": [{"address": "127.0.0.1", "state": "up", "ports": []}]}
        report = sr.recon("127.0.0.1", scan=scan, client=client)
        self.assertEqual(report.hosts, [])
        self.assertIn("private", report.skipped[0]["reason"])
        self.assertEqual(session.calls, [])

    def test_host_cap(self):
        scan = {"hosts": [{"address": f"45.33.32.{i}", "state": "up", "ports": []} for i in range(1, 6)]}
        client, session = make_client([FakeResponse(404, {})] * 2)
        report = sr.recon("45.33.32.0/24", scan=scan, client=client, max_hosts=2)
        self.assertEqual(len(report.hosts), 2)
        self.assertEqual(len(report.skipped), 3)


class ShodanReportTests(unittest.TestCase):
    def findings(self):
        client, _ = make_client([FakeResponse(200, INTERNETDB_SCANME)])
        shodan = sr.recon("scanme.nmap.org", scan=SCAN, client=client).to_dict()
        scan = copy.deepcopy(SCAN)
        scan.update({"profile": "standard", "command_line": "nmap scanme", "started_at": "", "elapsed_seconds": 1})
        cves = {"services": [{
            "host": "45.33.32.156", "port": 80, "protocol": "tcp", "service": "http", "product": "Apache httpd",
            "version": "2.4.7", "query_method": "cpe", "query": "q", "confidence": "high", "note": "",
            "cves": [{"cve_id": "CVE-2017-3167", "severity": "CRITICAL", "cvss_score": 9.8, "description": "d",
                      "known_exploited": False, "url": "u", "published": "", "vector": "", "cvss_version": ""}],
            "all_matches": [{"cve_id": "CVE-2017-3167", "severity": "CRITICAL", "known_exploited": False},
                            {"cve_id": "CVE-2016-0777", "severity": "MEDIUM", "known_exploited": False}],
        }]}
        return {"target": "scanme.nmap.org", "tool_version": "t", "scan": scan, "cves": cves, "shodan": shodan}

    def test_context_and_recommendation(self):
        ctx = rp.build_context(self.findings())
        h = ctx["shodan"]["hosts"][0]
        self.assertEqual(h["extra_vulns"], ["CVE-2099-9999"])  # the two NVD already found are excluded
        recs = " ".join(ctx["recommendations"])
        self.assertIn("31337", recs)
        self.assertIn("nmap -sU", recs)
        self.assertEqual(ctx["shodan"]["extra_ports"], [("45.33.32.156", [31337])])

    def test_renders(self):
        ctx = rp.build_context(self.findings())
        html = rp.render_html(ctx)
        md = rp.render_markdown(ctx)
        for out in (html, md):
            self.assertIn("Passive recon (Shodan)", out)
            self.assertIn("31337", out)
            self.assertIn("UDP", out)
            self.assertIn("CVE-2099-9999", out)

    def test_no_shodan_section_without_flag(self):
        f = self.findings()
        del f["shodan"]
        ctx = rp.build_context(f)
        self.assertIsNone(ctx["shodan"])
        self.assertNotIn("Passive recon", rp.render_html(ctx))


if __name__ == "__main__":
    unittest.main()
