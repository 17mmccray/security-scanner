"""
Offline tests for scanner/cve_lookup.py. No network access needed.

Run with:  python -m unittest discover -s tests -v
"""

import unittest
from unittest import mock

from scanner import cve_lookup as cl


def nvd_item(cve_id, score=None, version="3.1", severity=None, kev=False, desc="Test vuln."):
    metrics = {}
    if score is not None:
        key = {"4.0": "cvssMetricV40", "3.1": "cvssMetricV31", "3.0": "cvssMetricV30", "2.0": "cvssMetricV2"}[version]
        data = {"version": version, "vectorString": "AV:N/AC:L", "baseScore": score}
        entry = {"source": "nvd@nist.gov", "type": "Primary", "cvssData": data}
        if version == "2.0":
            entry["baseSeverity"] = severity or "HIGH"
        else:
            data["baseSeverity"] = severity or cl.score_to_severity(score)
        metrics[key] = [entry]
    cve = {
        "id": cve_id,
        "published": "2023-07-19T00:15:10.000",
        "descriptions": [{"lang": "es", "value": "No."}, {"lang": "en", "value": desc}],
        "metrics": metrics,
        "references": [{"url": f"https://example.com/{cve_id}"}],
    }
    if kev:
        cve["cisaExploitAdd"] = "2023-08-01"
    return {"cve": cve}


def nvd_response(items, total=None):
    return {"resultsPerPage": len(items), "startIndex": 0, "totalResults": total if total is not None else len(items),
            "format": "NVD_CVE", "version": "2.0", "vulnerabilities": items}


class FakeResponse:
    def __init__(self, status=200, payload=None, headers=None):
        self.status_code = status
        self._payload = payload
        self.headers = headers or {}
        self.text = ""

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.headers = {}

    def get(self, url, params=None, timeout=None):
        self.calls.append(dict(params))
        return self.responses.pop(0)


def make_client(responses, **kwargs):
    session = FakeSession(responses)
    client = cl.NVDClient(api_key="", use_cache=False, session=session, sleep=lambda s: None, **kwargs)
    return client, session


class SeverityTests(unittest.TestCase):
    def test_bands(self):
        self.assertEqual(cl.score_to_severity(9.8), "CRITICAL")
        self.assertEqual(cl.score_to_severity(9.0), "CRITICAL")
        self.assertEqual(cl.score_to_severity(7.0), "HIGH")
        self.assertEqual(cl.score_to_severity(6.9), "MEDIUM")
        self.assertEqual(cl.score_to_severity(4.0), "MEDIUM")
        self.assertEqual(cl.score_to_severity(0.1), "LOW")
        self.assertEqual(cl.score_to_severity(0.0), "NONE")
        self.assertEqual(cl.score_to_severity(None), "UNKNOWN")


class CPETests(unittest.TestCase):
    def test_openssh_splits_update(self):
        self.assertEqual(
            cl.cpe22_to_23("cpe:/a:openbsd:openssh:8.9p1"),
            "cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*",
        )

    def test_version_filled_from_nmap(self):
        self.assertEqual(
            cl.cpe22_to_23("cpe:/a:apache:http_server", fallback_version="2.4.49"),
            "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        )

    def test_no_version_anywhere(self):
        self.assertIsNone(cl.cpe22_to_23("cpe:/o:linux:linux_kernel"))

    def test_garbage(self):
        self.assertIsNone(cl.cpe22_to_23("not-a-cpe"))

    def test_numeric_prefix_retry(self):
        self.assertEqual(
            cl._numeric_prefix_cpe("cpe:2.3:a:x:y:1.2.3-ubuntu1:*:*:*:*:*:*:*"),
            "cpe:2.3:a:x:y:1.2.3:*:*:*:*:*:*:*",
        )
        self.assertIsNone(cl._numeric_prefix_cpe("cpe:2.3:a:x:y:1.2.3:*:*:*:*:*:*:*"))


class PlanQueryTests(unittest.TestCase):
    def test_prefers_cpe(self):
        port = {"product": "OpenSSH", "version": "8.9p1", "cpe": ["cpe:/a:openbsd:openssh:8.9p1"]}
        self.assertEqual(cl.plan_query(port)[0], "cpe")

    def test_keyword_fallback(self):
        port = {"product": "SimpleHTTPServer", "version": "0.6", "cpe": []}
        self.assertEqual(cl.plan_query(port), ("keyword", "SimpleHTTPServer 0.6"))

    def test_skip_without_version(self):
        port = {"product": "nginx", "version": "", "cpe": ["cpe:/a:igor_sysoev:nginx"]}
        self.assertEqual(cl.plan_query(port)[0], "skipped")


class ParseTests(unittest.TestCase):
    def test_parse_basic(self):
        f = cl.parse_cve(nvd_item("CVE-2023-1", score=9.8, kev=True, desc="Bad thing."))
        self.assertEqual(f.cve_id, "CVE-2023-1")
        self.assertEqual(f.severity, "CRITICAL")
        self.assertEqual(f.cvss_score, 9.8)
        self.assertEqual(f.description, "Bad thing.")
        self.assertTrue(f.known_exploited)
        self.assertEqual(f.published, "2023-07-19")
        self.assertEqual(f.url, "https://nvd.nist.gov/vuln/detail/CVE-2023-1")

    def test_v2_rerated_on_v3_scale(self):
        f = cl.parse_cve(nvd_item("CVE-2010-1", score=10.0, version="2.0", severity="HIGH"))
        self.assertEqual(f.severity, "CRITICAL")

    def test_no_metrics(self):
        f = cl.parse_cve(nvd_item("CVE-2024-1"))
        self.assertIsNone(f.cvss_score)
        self.assertEqual(f.severity, "UNKNOWN")


class ClientTests(unittest.TestCase):
    def test_retries_on_rate_limit(self):
        client, session = make_client([FakeResponse(403), FakeResponse(200, nvd_response([]))])
        client.search(keywordSearch="x")
        self.assertEqual(len(session.calls), 2)

    def test_gives_up(self):
        client, _ = make_client([FakeResponse(503)] * 3, max_retries=2)
        with self.assertRaises(cl.CVELookupError):
            client.search(keywordSearch="x")

    def test_404_is_empty(self):
        client, _ = make_client([FakeResponse(404, headers={"message": "Invalid cpe"})])
        self.assertEqual(client.search(virtualMatchString="bad")["totalResults"], 0)

    def test_memory_cache(self):
        client, session = make_client([FakeResponse(200, nvd_response([]))])
        client.search(keywordSearch="x")
        client.search(keywordSearch="x")
        self.assertEqual(len(session.calls), 1)

    def test_throttle_waits_when_window_full(self):
        waits = []
        client, _ = make_client([])
        client._sleep = waits.append
        for _ in range(5):
            client._throttle()
        self.assertEqual(waits, [])
        client._throttle()
        self.assertEqual(len(waits), 1)
        self.assertGreater(waits[0], 29)

    def test_api_key_header(self):
        session = FakeSession([])
        client = cl.NVDClient(api_key="abc", use_cache=False, session=session)
        self.assertEqual(session.headers["apiKey"], "abc")
        self.assertEqual(client._limit, 50)


class LookupScanTests(unittest.TestCase):
    SCAN = {
        "hosts": [{
            "address": "10.0.0.5",
            "ports": [
                {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh",
                 "product": "OpenSSH", "version": "8.9p1", "cpe": ["cpe:/a:openbsd:openssh:8.9p1"]},
                {"port": 80, "protocol": "tcp", "state": "open", "service": "http",
                 "product": "nginx", "version": "", "cpe": ["cpe:/a:igor_sysoev:nginx"]},
                {"port": 443, "protocol": "tcp", "state": "closed", "service": "https",
                 "product": "", "version": "", "cpe": []},
            ],
        }]
    }

    def test_end_to_end(self):
        items = [nvd_item("CVE-A", 5.3), nvd_item("CVE-B", 9.8, kev=True), nvd_item("CVE-C", 7.5)]
        client, session = make_client([FakeResponse(200, nvd_response(items)), FakeResponse(200, nvd_response(items))])
        progress = []
        report = cl.lookup_scan(self.SCAN, client=client, max_per_service=2,
                                on_progress=lambda d, t, l: progress.append((d, t)))

        self.assertEqual(len(report.services), 2)  # closed port excluded
        ssh, http = report.services
        self.assertEqual(ssh.query_method, "cpe")
        self.assertEqual(session.calls[0]["virtualMatchString"], "cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*")
        self.assertEqual([c.cve_id for c in ssh.cves], ["CVE-B", "CVE-C"])  # most severe first, capped at 2
        self.assertEqual(ssh.worst_severity, "CRITICAL")
        self.assertIn("most severe", ssh.note)
        self.assertEqual(http.query_method, "skipped")
        self.assertEqual(len(session.calls), 2)  # exact + any-update; skipped service made no request
        self.assertEqual(len(report.services[0].all_matches), 3)  # duplicates across queries merged
        self.assertEqual(progress[-1], (2, 2))

        counts = report.to_dict()["severity_counts"]
        self.assertEqual(counts["CRITICAL"], 1)
        self.assertEqual(counts["HIGH"], 1)

    def test_retries_numeric_version(self):
        scan = {"hosts": [{"address": "h", "ports": [
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http",
             "product": "Apache httpd", "version": "2.4.49-custom", "cpe": ["cpe:/a:apache:http_server:2.4.49-custom"]},
        ]}]}
        client, session = make_client([
            FakeResponse(200, nvd_response([])),
            FakeResponse(200, nvd_response([nvd_item("CVE-2021-41773", 7.5)])),
        ])
        report = cl.lookup_scan(scan, client=client)
        self.assertEqual(len(session.calls), 2)
        self.assertEqual(session.calls[1]["virtualMatchString"], "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
        self.assertEqual(report.services[0].cves[0].cve_id, "CVE-2021-41773")


class RealScanRegressionTests(unittest.TestCase):
    """Cases from the first live scan of scanme.nmap.org."""

    SSH = {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "product": "OpenSSH",
           "version": "6.6.1p1 Ubuntu 2ubuntu2.13", "extra_info": "Ubuntu Linux; protocol 2.0",
           "cpe": ["cpe:/a:openbsd:openssh:6.6.1p1", "cpe:/o:linux:linux_kernel"]}

    def scan(self, *ports):
        return {"hosts": [{"address": "45.33.32.156", "ports": list(ports)}]}

    def test_candidate_order_for_openssh(self):
        self.assertEqual(cl.candidate_queries(self.SSH), [
            ("cpe", "cpe:2.3:a:openbsd:openssh:6.6.1:p1:*:*:*:*:*:*"),
            ("cpe", "cpe:2.3:a:openbsd:openssh:6.6.1:*:*:*:*:*:*:*"),
            ("keyword", "OpenSSH 6.6.1p1"),
        ])

    def test_falls_back_when_exact_cpe_has_no_matches(self):
        client, session = make_client([
            FakeResponse(200, nvd_response([])),
            FakeResponse(200, nvd_response([nvd_item("CVE-2016-0777", 6.5)])),
        ])
        queries = []
        report = cl.lookup_scan(self.scan(self.SSH), client=client,
                                on_query=lambda m, q, n, msg: queries.append((q, n)))
        svc = report.services[0]
        self.assertEqual(svc.query, "cpe:2.3:a:openbsd:openssh:6.6.1:*:*:*:*:*:*:*")
        self.assertEqual(svc.confidence, "high")
        self.assertEqual([c.cve_id for c in svc.cves], ["CVE-2016-0777"])
        self.assertEqual([n for _, n in queries], [0, 1])
        self.assertEqual(len(svc.queries_tried), 2)

    def test_exact_and_any_update_results_are_merged(self):
        # What scanme showed: pinning "p1" found 1 CVE; the any-update query finds the range-based ones.
        client, session = make_client([
            FakeResponse(200, nvd_response([nvd_item("CVE-2016-3115", 6.4)])),
            FakeResponse(200, nvd_response([nvd_item("CVE-2016-3115", 6.4), nvd_item("CVE-2016-0777", 6.5),
                                            nvd_item("CVE-2023-38408", 9.8)])),
        ])
        svc = cl.lookup_scan(self.scan(self.SSH), client=client).services[0]
        self.assertEqual(len(session.calls), 2)
        self.assertEqual(sorted(m["cve_id"] for m in svc.all_matches),
                         ["CVE-2016-0777", "CVE-2016-3115", "CVE-2023-38408"])
        self.assertEqual(svc.cves[0].cve_id, "CVE-2023-38408")
        self.assertEqual(svc.confidence, "high")
        self.assertIn(" | ", svc.query)

    def test_keyword_last_resort_is_low_confidence(self):
        client, _ = make_client([
            FakeResponse(200, nvd_response([])),
            FakeResponse(200, nvd_response([])),
            FakeResponse(200, nvd_response([nvd_item("CVE-X", 7.0)])),
        ])
        svc = cl.lookup_scan(self.scan(self.SSH), client=client).services[0]
        self.assertEqual(svc.query_method, "keyword")
        self.assertEqual(svc.confidence, "low")
        self.assertIn("keyword search", svc.note)

    def test_nothing_found_anywhere(self):
        client, session = make_client([FakeResponse(200, nvd_response([]))] * 3)
        svc = cl.lookup_scan(self.scan(self.SSH), client=client).services[0]
        self.assertEqual(svc.cves, [])
        self.assertEqual(len(session.calls), 3)
        self.assertEqual(svc.query_method, "cpe")  # records the most specific query

    def test_counts_cover_all_matches_not_just_displayed(self):
        items = [nvd_item(f"CVE-A-{i}", 7.5) for i in range(20)] + [nvd_item("CVE-C-1", 9.8)]
        client, session = make_client([FakeResponse(200, nvd_response(items, total=21)),
                                       FakeResponse(200, nvd_response([]))])
        report = cl.lookup_scan(self.scan(self.SSH), client=client, max_per_service=5)
        svc = report.services[0]
        self.assertEqual(session.calls[0]["resultsPerPage"], 2000)  # one request fetches everything
        self.assertEqual(len(svc.cves), 5)
        self.assertEqual(svc.cves[0].cve_id, "CVE-C-1")
        counts = report.severity_counts()
        self.assertEqual((counts["CRITICAL"], counts["HIGH"]), (1, 20))
        self.assertIn("showing the 5 most severe of 21", svc.note)

    def test_kev_never_hidden_by_display_cap(self):
        items = [nvd_item(f"CVE-H-{i}", 9.0) for i in range(5)] + [nvd_item("CVE-KEV", 5.0, kev=True)]
        client, _ = make_client([FakeResponse(200, nvd_response(items)), FakeResponse(200, nvd_response([]))])
        report = cl.lookup_scan(self.scan(self.SSH), client=client, max_per_service=3)
        ids = [c.cve_id for c in report.services[0].cves]
        self.assertIn("CVE-KEV", ids)
        self.assertEqual(len(ids), 4)
        self.assertEqual(report.kev_count(), 1)

    def test_distro_detection(self):
        self.assertEqual(cl.detect_distro(self.SSH), "Ubuntu")
        self.assertEqual(cl.detect_distro({"product": "Apache httpd", "version": "2.4.7", "extra_info": "(Ubuntu)"}), "Ubuntu")
        self.assertEqual(cl.detect_distro({"product": "nginx", "version": "1.25.3", "extra_info": ""}), "")
        self.assertEqual(cl.detect_distro({"product": "OpenSSH", "version": "7.4", "extra_info": "protocol 2.0; RHEL"}), "Red Hat")

    def test_rejected_query_message_reported(self):
        client, _ = make_client([FakeResponse(404, headers={"message": "Invalid cpe match string"})] * 3)
        seen = []
        cl.lookup_scan(self.scan(self.SSH), client=client, on_query=lambda m, q, n, msg: seen.append(msg))
        self.assertEqual(seen[0], "Invalid cpe match string")


if __name__ == "__main__":
    unittest.main()
