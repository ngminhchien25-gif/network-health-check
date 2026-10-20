"""Unit tests (stdlib unittest, also runnable with pytest):  python -m unittest -v"""
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

from netcheck.collector import check_device
from netcheck.config import ConfigError, load_config
from netcheck.connector import DemoConnector
from netcheck.models import Severity
from netcheck.parsers import parse_interfaces, parse_ping, parse_routes, parse_traceroute
from netcheck.report import render_html, summarize

DEMO_CFG = Path(__file__).resolve().parents[1] / "config" / "config.demo.yaml"


class ParserTests(unittest.TestCase):
    def test_ping_full_success(self):
        r = parse_ping("1.1.1.1", "Success rate is 100 percent (5/5), round-trip min/avg/max = 2/3/5 ms")
        self.assertEqual((r.sent, r.received, r.loss_pct, r.rtt_avg), (5, 5, 0.0, 3))

    def test_ping_partial_and_total_loss(self):
        self.assertEqual(parse_ping("x", "Success rate is 60 percent (3/5), round-trip min/avg/max = 1/2/3 ms").loss_pct, 40.0)
        total = parse_ping("x", "Success rate is 0 percent (0/5)")
        self.assertEqual((total.loss_pct, total.rtt_avg, total.error), (100.0, None, ""))

    def test_ping_unparsable(self):
        self.assertTrue(parse_ping("x", "garbage").error)

    def test_traceroute(self):
        raw = "Tracing the route to 2.2.2.2\n  1 10.0.0.2 4 msec 3 msec 2 msec\n  2 2.2.2.2 5 msec *  4 msec\n"
        t = parse_traceroute("2.2.2.2", raw)
        self.assertEqual(t.hops, [(1, "10.0.0.2"), (2, "2.2.2.2")])
        self.assertTrue(t.reached)
        self.assertFalse(parse_traceroute("9.9.9.9", "  1 10.0.0.2 1 msec\n  2 *  *  *\n").reached)

    def test_traceroute_target_answers_from_other_address(self):
        self.assertTrue(parse_traceroute("10.30.30.1", "  1 10.0.12.2 12 msec 8 msec 8 msec\n").reached)

    def test_traceroute_unreachable_markers_and_ttl_exhausted(self):
        self.assertFalse(parse_traceroute("10.30.30.1", "  1 10.0.12.1 !H  *  !H\n").reached)
        looping = "".join(f"  {n} 10.0.0.{n % 2 + 1} 5 msec\n" for n in range(1, 31))
        self.assertFalse(parse_traceroute("10.30.30.1", looping).reached)

    def test_real_c3745_interface_brief(self):
        raw = ("Interface                  IP-Address      OK? Method Status                Protocol\n"
               "FastEthernet0/0            192.168.195.129 YES DHCP   up                    up      \n"
               "Serial0/0                  unassigned      YES NVRAM  administratively down down    \n"
               "Loopback10                 10.10.10.1      YES NVRAM  up                    up      \n")
        i = parse_interfaces(raw)
        self.assertEqual([(x.name, x.status, x.ip) for x in i],
                         [("FastEthernet0/0", "connected", "192.168.195.129"),
                          ("Serial0/0", "disabled", ""), ("Loopback10", "connected", "10.10.10.1")])

    def test_interfaces_switch_with_empty_name(self):
        raw = ("Port      Name               Status       Vlan       Duplex  Speed Type\n"
               "Gi0/1     TO-R1              connected    1          a-full  a-1000 unknown\n"
               "Gi0/3                        notconnect   1            auto   auto unknown\n"
               "Gi1/2     TEST PORT          err-disabled 1            auto   auto unknown\n")
        i = {x.name: x for x in parse_interfaces(raw)}
        self.assertEqual((i["Gi0/1"].duplex, i["Gi0/1"].speed, i["Gi0/1"].description), ("full", "1000", "TO-R1"))
        self.assertEqual((i["Gi0/3"].status, i["Gi0/3"].description), ("notconnect", ""))
        self.assertEqual((i["Gi1/2"].status, i["Gi1/2"].description), ("err-disabled", "TEST PORT"))

    def test_interfaces_router_brief(self):
        raw = ("Interface                  IP-Address      OK? Method Status                Protocol\n"
               "GigabitEthernet0/0         10.0.0.1        YES NVRAM  up                    up\n"
               "GigabitEthernet0/1         unassigned      YES NVRAM  administratively down down\n"
               "GigabitEthernet0/2         10.0.2.1        YES NVRAM  up                    down\n"
               "GigabitEthernet0/3         unassigned      YES unset  down                  down\n")
        self.assertEqual([x.status for x in parse_interfaces(raw)],
                         ["connected", "disabled", "protocol-down", "notconnect"])

    def test_routes(self):
        raw = ("Gateway of last resort is 10.0.0.254 to network 0.0.0.0\n"
               "S*    0.0.0.0/0 [1/0] via 10.0.0.254\n"
               "O E2     10.1.0.0/16 [110/20] via 10.0.0.2, 00:00:10, Gi0/0\n"
               "C        10.0.0.0/24 is directly connected, Gi0/0\n")
        s = parse_routes(raw, ["10.1.0.0/16", "172.16.0.0/16"])
        self.assertEqual((s.total, s.default_route, s.gateway), (3, True, "10.0.0.254"))
        self.assertEqual(s.by_protocol, {"Static": 1, "OSPF": 1, "Connected": 1})
        self.assertEqual(s.missing, ["172.16.0.0/16"])


class PathTests(unittest.TestCase):
    def test_compact_path_collapses_stars(self):
        from netcheck.report import compact_path
        hops = [(1, "10.0.0.1")] + [(n, "*") for n in range(2, 31)]
        self.assertEqual(compact_path(hops), "10.0.0.1 \u2192 * (x29)")
        self.assertEqual(compact_path([(1, "a"), (2, "*"), (3, "b")]), "a \u2192 * \u2192 b")


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cfg = load_config(DEMO_CFG)
        cls.reports = {d.name: check_device(d, cls.cfg, DemoConnector) for d in cls.cfg.devices}

    def test_expected_statuses(self):
        got = {n: r.status for n, r in self.reports.items()}
        self.assertEqual(got, {"R1": Severity.OK, "R2": Severity.WARNING,
                               "SW1": Severity.CRITICAL, "R3": Severity.CRITICAL})

    def test_unreachable_device(self):
        r = self.reports["R3"]
        self.assertFalse(r.reachable)
        self.assertIn("Timeout", r.error)

    def test_critical_interface_matching_uses_short_names(self):
        # Gi0/1 (config) must match GigabitEthernet0/1 and vice versa -> no false positives on healthy R1
        self.assertEqual([f for f in self.reports["R1"].findings if f.severity >= Severity.WARNING], [])

    def test_report_renders(self):
        reports = list(self.reports.values())
        html = render_html(reports, self.cfg, datetime(2026, 1, 1))
        self.assertIn("SW1", html)
        self.assertIn("err-disabled", html)
        self.assertIn("Raw output", html)
        self.assertNotIn("Raw output", render_html(reports, self.cfg, datetime(2026, 1, 1), compact=True))
        self.assertEqual(summarize(reports)["critical"], 2)


class LabConfigTests(unittest.TestCase):
    def test_lab_config_loads_with_telnet(self):
        cfg = load_config(Path(__file__).resolve().parents[1] / "config" / "config.yaml")
        self.assertEqual({d.device_type for d in cfg.devices}, {"cisco_ios_telnet"})
        self.assertEqual({d.port for d in cfg.devices}, {23})


class MailerTests(unittest.TestCase):
    def test_message_built_with_attachment(self):
        from netcheck.config import SmtpConfig
        from netcheck.mailer import send_report
        import tempfile

        sent = {}

        class FakeSMTP:
            def __init__(self, *a, **k): pass
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def starttls(self, **k): sent["tls"] = True
            def login(self, u, p): sent["login"] = (u, p)
            def send_message(self, msg): sent["msg"] = msg

        with tempfile.TemporaryDirectory() as tmp, mock.patch("smtplib.SMTP", FakeSMTP):
            att = Path(tmp) / "report.html"
            att.write_text("<html></html>")
            cfg = SmtpConfig(host="h", port=587, use_starttls=True, username="u", password="p",
                             sender="a@x", recipients=["b@x", "c@x"])
            send_report(cfg, "subj", "text", "<b>html</b>", [att])
        msg = sent["msg"]
        self.assertEqual((msg["To"], msg["Subject"]), ("b@x, c@x", "subj"))
        self.assertEqual([p.get_filename() for p in msg.iter_attachments()], ["report.html"])
        self.assertTrue(sent["tls"])
        self.assertEqual(sent["login"], ("u", "p"))


class ConfigTests(unittest.TestCase):
    def test_env_expansion_and_defaults(self):
        import os, tempfile
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {"X_PASS": "s3cret"}):
            p = Path(tmp) / "c.yaml"
            p.write_text("defaults: {password: '${X_PASS}', username: '${NOPE:-admin}'}\n"
                         "devices: [{name: A, host: 1.1.1.1}]\n")
            d = load_config(p).devices[0]
            self.assertEqual((d.password, d.username), ("s3cret", "admin"))

    def test_invalid_key_reports_device(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "c.yaml"
            p.write_text("devices: [{name: A, host: 1.1.1.1, bogus: 1}]\n")
            with self.assertRaises(ConfigError):
                load_config(p)


if __name__ == "__main__":
    unittest.main()
