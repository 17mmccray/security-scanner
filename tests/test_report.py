"""
Tests for reporter/report.py. No network access needed.

Run with:  python -m unittest discover -s tests -v
"""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from reporter import report as rp


def cve(cve_id, score, severity, kev=False, desc="A vulnerability."):
    return {
        "cve_id": cve_id, "description": desc, "cvss_score": score, "severity": severity,
        "cvss_version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "published": "2021-10-05", "known_exploited": kev,
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}", "references": [],
    }


FINDINGS = {
    "target": "10.0.0.5",
    "tool_version": "0.3.0",
    "scan": {
        "target": "10.0.0.5", "profile": "standard", "arguments": "-T4 -sV",
        "started_at": "2026-09-30T04:00:00+00:00", "finished_at": "2026-09-30T04:00:09+00:00",
        "elapsed_seconds": 9.2, "command_line": "nmap -oX - -T4 -sV 10.0.0.5",
        "hosts": [{
            "address": "10.0.0.5", "hostname": "web01", "state": "up", "os_matches": [],
            "ports": [
                {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh",
                 "product": "OpenSSH", "version": "8.9p1", "extra_info": "", "cpe": []},
                {"port": 80, "protocol": "tcp", "state": "open", "service": "http",
                 "product": "Apache httpd", "version": "2.4.49", "extra_info": "", "cpe": []},
                {"port": 23, "protocol": "tcp", "state": "open", "service": "telnet",
                 "product": "", "version": "", "extra_info": "", "cpe": []},
                {"port": 443, "protocol": "tcp", "state": "closed", "service": "https",
                 "product": "", "version": "", "extra_info": "", "cpe": []},
            ],
        }],
    },
    "cves": {
        "services": [
            {"host": "10.0.0.5", "port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH",
             "version": "8.9p1", "query_method": "cpe", "query": "cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*",
             "confidence": "high", "total_results": 1, "note": "",
             "cves": [cve("CVE-2023-38408", 9.8, "CRITICAL")]},
            {"host": "10.0.0.5", "port": 80, "protocol": "tcp", "service": "http", "product": "Apache httpd",
             "version": "2.4.49", "query_method": "keyword", "query": "Apache httpd 2.4.49",
             "confidence": "low", "total_results": 2, "note": "",
             "cves": [cve("CVE-2021-41773", 7.5, "HIGH", kev=True), cve("CVE-2021-0001", 5.0, "MEDIUM")]},
            {"host": "10.0.0.5", "port": 23, "protocol": "tcp", "service": "telnet", "product": "",
             "version": "", "query_method": "skipped", "query": "", "confidence": "", "total_results": 0,
             "note": "no product version detected; nothing specific to look up", "cves": []},
        ],
        "severity_counts": {},
    },
}


class ContextTests(unittest.TestCase):
    def setUp(self):
        self.ctx = rp.build_context(copy.deepcopy(FINDINGS))

    def test_stats(self):
        self.assertEqual(self.ctx["stats"]["hosts_up"], 1)
        self.assertEqual(self.ctx["stats"]["open_ports"], 3)  # closed port excluded
        self.assertEqual(self.ctx["stats"]["cves_total"], 3)
        self.assertEqual(self.ctx["stats"]["kev_count"], 1)

    def test_overall_risk_is_worst(self):
        self.assertEqual(self.ctx["overall_risk"], "CRITICAL")

    def test_top_findings_sorted_and_filtered(self):
        ids = [c["cve_id"] for c in self.ctx["top_findings"]]
        self.assertEqual(ids, ["CVE-2023-38408", "CVE-2021-41773"])  # medium excluded
        self.assertTrue(self.ctx["top_findings"][1]["low_confidence"])

    def test_exposures(self):
        self.assertEqual([e["service"] for e in self.ctx["exposures"]], ["telnet"])

    def test_skipped_and_recommendations(self):
        self.assertEqual(len(self.ctx["skipped"]), 1)
        recs = " ".join(self.ctx["recommendations"])
        self.assertIn("CVE-2021-41773", recs)  # KEV called out first
        self.assertIn("Manually verify", recs)

    def test_no_cve_step(self):
        f = copy.deepcopy(FINDINGS)
        del f["cves"]
        ctx = rp.build_context(f)
        self.assertEqual(ctx["overall_risk"], "NOT_ASSESSED")
        self.assertFalse(ctx["cve_assessed"])

    def test_clean_but_exposed_is_medium(self):
        f = copy.deepcopy(FINDINGS)
        for s in f["cves"]["services"]:
            s["cves"] = []
        self.assertEqual(rp.build_context(f)["overall_risk"], "MEDIUM")  # telnet exposure


class AllMatchesTests(unittest.TestCase):
    """Totals must reflect every NVD match, not only the CVEs displayed per service."""

    def setUp(self):
        f = copy.deepcopy(FINDINGS)
        ssh = f["cves"]["services"][0]
        ssh["distro"] = "Ubuntu"
        ssh["all_matches"] = [
            {"cve_id": "CVE-2023-38408", "severity": "CRITICAL", "cvss_score": 9.8, "known_exploited": False},
        ] + [{"cve_id": f"CVE-HIDDEN-{i}", "severity": "HIGH", "cvss_score": 7.0, "known_exploited": i == 0}
             for i in range(40)]
        self.ctx = rp.build_context(f)

    def test_totals_include_hidden_matches(self):
        self.assertEqual(self.ctx["stats"]["cves_total"], 3 + 40)  # 1 + 40 on ssh, 2 on http
        self.assertEqual(self.ctx["severity_counts"]["HIGH"], 41)
        self.assertEqual(self.ctx["stats"]["kev_count"], 2)
        ssh_port = self.ctx["hosts"][0]["ports"][0]
        self.assertEqual(ssh_port["cve_count"], 41)

    def test_backport_recommendation(self):
        self.assertEqual(len(self.ctx["backported"]), 1)
        self.assertIn("backport", " ".join(self.ctx["recommendations"]))
        self.assertIn("Ubuntu package", rp.render_html(self.ctx))
        self.assertIn("Ubuntu package", rp.render_markdown(self.ctx))


class RenderTests(unittest.TestCase):
    def test_html_renders(self):
        html = rp.render_html(rp.build_context(copy.deepcopy(FINDINGS)))
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("CVE-2023-38408", html)
        self.assertIn("Critical", html)
        self.assertIn("KEV", html)
        self.assertIn("telnet", html)

    def test_markdown_renders(self):
        md = rp.render_markdown(rp.build_context(copy.deepcopy(FINDINGS)))
        self.assertTrue(md.startswith("# Security Audit Report: 10.0.0.5"))
        self.assertIn("**Overall risk: Critical**", md)
        self.assertIn("[CVE-2021-41773](https://nvd.nist.gov/vuln/detail/CVE-2021-41773) ⚠ KEV", md)

    def test_hostile_banner_is_escaped(self):
        # Banners come from the scanned host, so a malicious server controls this text.
        f = copy.deepcopy(FINDINGS)
        evil = '<script>alert("x")</script>|'
        f["scan"]["hosts"][0]["ports"][0]["product"] = evil
        f["cves"]["services"][0]["cves"][0]["description"] = evil
        ctx = rp.build_context(f)
        html = rp.render_html(ctx)
        md = rp.render_markdown(ctx)
        self.assertNotIn("<script>alert", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>alert", md)
        self.assertIn("\\|", md)  # pipe escaped so it can't break table columns

    def test_generate_report_files(self):
        with tempfile.TemporaryDirectory() as d:
            for name in ("r.html", "r.md"):
                path = rp.generate_report(copy.deepcopy(FINDINGS), Path(d) / name)
                self.assertGreater(path.stat().st_size, 500)
            with self.assertRaises(rp.ReportError):
                rp.generate_report(copy.deepcopy(FINDINGS), Path(d) / "r.pdf")
            with self.assertRaises(rp.ReportError):
                rp.generate_report({"target": "x"}, Path(d) / "r.html")

    def test_standalone_cli(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "f.json"
            src.write_text(json.dumps(FINDINGS))
            self.assertEqual(rp.main([str(src), "-o", str(Path(d) / "out.md")]), 0)
            self.assertTrue((Path(d) / "out.md").exists())


if __name__ == "__main__":
    unittest.main()
