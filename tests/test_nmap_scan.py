"""
Tests for scanner/nmap_scan.py that don't need nmap installed.

Run with:  python -m unittest discover -s tests -v
"""

import unittest

from scanner import nmap_scan as ns

# Trimmed from a real `nmap -oX - -sV scanme.nmap.org` run
SCANME_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -oX - -T4 -sV scanme.nmap.org">
<host><status state="up"/>
<address addr="45.33.32.156" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="open"/>
  <service name="ssh" product="OpenSSH" version="6.6.1p1 Ubuntu 2ubuntu2.13" extrainfo="Ubuntu Linux; protocol 2.0" ostype="Linux">
    <cpe>cpe:/a:openbsd:openssh:6.6.1p1</cpe><cpe>cpe:/o:linux:linux_kernel</cpe>
  </service></port>
<port protocol="tcp" portid="80"><state state="open"/>
  <service name="http" product="Apache httpd" version="2.4.7" extrainfo="(Ubuntu)">
    <cpe>cpe:/a:apache:http_server:2.4.7</cpe>
  </service></port>
<port protocol="tcp" portid="9929"><state state="open"/>
  <service name="nping-echo" product="Nping echo"/></port>
</ports></host>
</nmaprun>"""


class ParseServiceCpesTests(unittest.TestCase):
    def test_keeps_every_cpe(self):
        cpes = ns.parse_service_cpes(SCANME_XML)
        # python-nmap would only have kept cpe:/o:linux:linux_kernel here
        self.assertEqual(cpes[("45.33.32.156", "tcp", 22)],
                         ["cpe:/a:openbsd:openssh:6.6.1p1", "cpe:/o:linux:linux_kernel"])
        self.assertEqual(cpes[("45.33.32.156", "tcp", 80)], ["cpe:/a:apache:http_server:2.4.7"])
        self.assertEqual(cpes[("45.33.32.156", "tcp", 9929)], [])

    def test_bytes_and_bad_input(self):
        self.assertIn(("45.33.32.156", "tcp", 22), ns.parse_service_cpes(SCANME_XML.encode()))
        self.assertEqual(ns.parse_service_cpes(""), {})
        self.assertEqual(ns.parse_service_cpes("<nmaprun><host>broken"), {})

    def test_feeds_cve_lookup_correctly(self):
        from scanner import cve_lookup as cl
        port = {"product": "OpenSSH", "version": "6.6.1p1 Ubuntu 2ubuntu2.13",
                "cpe": ns.parse_service_cpes(SCANME_XML)[("45.33.32.156", "tcp", 22)]}
        self.assertEqual(cl.candidate_queries(port)[0],
                         ("cpe", "cpe:2.3:a:openbsd:openssh:6.6.1:p1:*:*:*:*:*:*"))


class ValidationTests(unittest.TestCase):
    def test_targets(self):
        for ok in ("45.33.32.156", "10.0.0.0/24", "10.0.0.1-20", "scanme.nmap.org"):
            self.assertEqual(ns.validate_target(ok), ok)
        for bad in ("", "a;rm -rf /", "10.0.0.20-5", "999.1.1.1-3"):
            with self.assertRaises(ns.ScanError):
                ns.validate_target(bad)

    def test_ports(self):
        self.assertEqual(ns.validate_ports("22, 80,443"), "22,80,443")
        self.assertEqual(ns.validate_ports("1-1024"), "1-1024")
        for bad in ("70000", "22;ls", "abc"):
            with self.assertRaises(ns.ScanError):
                ns.validate_ports(bad)

    def test_explicit_ports_override_profile(self):
        self.assertEqual(ns.NmapScanner.build_arguments("quick", ports="22,80"), "-T4 -p 22,80")
        self.assertEqual(ns.NmapScanner.build_arguments("full", ports="443"), "-T4 -sV -p 443")


if __name__ == "__main__":
    unittest.main()
