#!/usr/bin/env python3
"""Add-ons: vendors, ARP/ND evidence, notifications, reports, metrics, traces, WoL, XML, tags."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pingme


def result(ip: str, alive: bool = False, **extra) -> dict:
    row = pingme._build_probe_result(ip, alive, 64 if alive else None, [])
    row.update(extra)
    return row


class VendorTests(unittest.TestCase):
    def test_database_formats(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oui.txt"
            path.write_text(
                "5C-A6-E6   (hex)\t\tTP-Link Systems Inc.\n"
                "5CA6E6     (base 16)\t\tTP-Link Systems Inc.\n"
                "B827EB Raspberry Pi Foundation\n"
                "00:0C:29\tVMware\tVMware, Inc.\n", encoding="utf-8")
            table = pingme._parse_oui_file(path)
        self.assertEqual(table["5CA6E6"], "TP-Link Systems Inc.")
        self.assertEqual(table["B827EB"], "Raspberry Pi Foundation")
        self.assertEqual(table["000C29"], "VMware, Inc.")

    def test_randomized_and_docker_macs(self) -> None:
        self.assertEqual(pingme.mac_vendor("e6:d4:87:71:a9:38"), "Private (randomized MAC)")
        self.assertEqual(pingme.mac_vendor("02:42:ac:11:00:02"), "Docker (virtual)")
        self.assertEqual(pingme._normalise_mac("0:1c:42:a:b:c"), "00:1c:42:0a:0b:0c")


class NeighborTests(unittest.TestCase):
    def _entries(self, platform: str, tool: str, output: str, family: int):
        with (
            patch.object(pingme.sys, "platform", platform),
            patch.object(pingme.shutil, "which", side_effect=lambda name: name if name.startswith(tool) else None),
            patch.object(pingme, "_run_resolution_command", return_value=output),
        ):
            return pingme.read_neighbor_entries(family)

    def test_linux_ipv4_states(self) -> None:
        rows = self._entries("linux", "ip", (
            "192.168.0.1 dev wlan0 lladdr 5c:a6:e6:cc:0e:fb REACHABLE\n"
            "192.168.0.85 dev wlan0 FAILED\n"
            "192.168.0.9 dev wlan0 lladdr aa:bb:cc:dd:ee:01 router STALE\n"), 4)
        self.assertEqual(rows, [
            ("192.168.0.1", "wlan0", "5c:a6:e6:cc:0e:fb", "REACHABLE"),
            ("192.168.0.85", "wlan0", "", "FAILED"),
            ("192.168.0.9", "wlan0", "aa:bb:cc:dd:ee:01", "STALE"),
        ])

    def test_windows_ipv4_neighbors(self) -> None:
        rows = self._entries("win32", "netsh", (
            "Interface 7: Wi-Fi\n\nInternet Address   Physical Address   Type\n"
            "192.168.1.1        5c-a6-e6-cc-0e-fb  Reachable (Router)\n"
            "192.168.1.50                          Unreachable\n"), 4)
        self.assertEqual(rows[0], ("192.168.1.1", "7", "5c-a6-e6-cc-0e-fb", "REACHABLE"))
        self.assertEqual(rows[1][3], "FAILED")

    def test_macos_arp_has_no_state(self) -> None:
        rows = self._entries("darwin", "arp", (
            "? (192.168.1.1) at 5c:a6:e6:cc:e:fb on en0 ifscope [ethernet]\n"
            "? (192.168.1.9) at (incomplete) on en0 ifscope [ethernet]\n"), 4)
        self.assertEqual(rows, [("192.168.1.1", "en0", "5c:a6:e6:cc:e:fb", "")])

    def _evidence(self, table: dict, target: dict) -> dict:
        evidence = pingme.NeighborEvidence()
        evidence.table = table
        evidence.read_at = float("inf")
        evidence.use_as_evidence = True
        return evidence.enrich(target)

    def test_fresh_arp_reply_is_evidence_but_stale_entry_is_not(self) -> None:
        fresh = self._evidence({"10.0.0.5": ("aa:bb:cc:00:00:05", "REACHABLE")}, result("10.0.0.5"))
        self.assertEqual((fresh["status"], fresh["evidence"], fresh["mac"]), ("REACHABLE", "ARP/ND reply", "aa:bb:cc:00:00:05"))
        stale = self._evidence({"10.0.0.6": ("aa:bb:cc:00:00:06", "STALE")}, result("10.0.0.6"))
        self.assertEqual(stale["status"], "NO RESPONSE")
        self.assertEqual(stale["mac"], "aa:bb:cc:00:00:06")

    def test_entry_still_being_verified_is_settled_after_the_scan(self) -> None:
        evidence = pingme.NeighborEvidence()
        evidence.use_as_evidence = True
        tables = iter([
            [("10.0.0.7", "", "aa:bb:cc:00:00:07", "DELAY"), ("10.0.0.8", "", "aa:bb:cc:00:00:08", "DELAY")],
            [("10.0.0.7", "", "aa:bb:cc:00:00:07", "PROBE"), ("10.0.0.8", "", "aa:bb:cc:00:00:08", "FAILED")],
            [("10.0.0.7", "", "aa:bb:cc:00:00:07", "REACHABLE"), ("10.0.0.8", "", "aa:bb:cc:00:00:08", "FAILED")],
        ])
        latest: list = []

        def read(family: int) -> list:
            if family == 4:
                latest[:] = next(tables, latest)
                return list(latest)
            return []

        with patch.object(pingme, "read_neighbor_entries", side_effect=read), patch.object(pingme.time, "sleep"):
            silent, gone = evidence.enrich(result("10.0.0.7")), evidence.enrich(result("10.0.0.8"))
            self.assertEqual(silent["status"], "NO RESPONSE")
            upgraded = evidence.settle(timeout=5)
        self.assertEqual([r["ip"] for r in upgraded], ["10.0.0.7"])
        self.assertEqual((silent["status"], silent["evidence"]), ("REACHABLE", "ARP/ND reply"))
        self.assertEqual(gone["status"], "NO RESPONSE")
        self.assertEqual(evidence.pending, {})

    def test_proxy_arp_mac_is_not_evidence(self) -> None:
        table = {f"10.0.0.{n}": ("00:11:22:33:44:55", "REACHABLE") for n in range(1, 6)}
        self.assertEqual(self._evidence(table, result("10.0.0.3"))["status"], "NO RESPONSE")


class NotificationTests(unittest.TestCase):
    events = {"went_offline": [{"host": "db01", "ip": "10.0.0.5"}], "newly_online": []}

    def _payload(self, target: str) -> tuple[str, dict]:
        with patch.object(pingme, "_post_json") as post:
            pingme.send_notification(target, "PingMe", "text", self.events)
        url, payload = post.call_args.args
        return url, payload

    def test_formats_per_service(self) -> None:
        self.assertEqual(self._payload("https://hooks.slack.com/services/T/B/X")[1], {"text": "text"})
        self.assertEqual(self._payload("https://discord.com/api/webhooks/1/abc")[1], {"content": "text"})
        url, payload = self._payload("telegram://123:ABC@-100555")
        self.assertEqual((url, payload), ("https://api.telegram.org/bot123:ABC/sendMessage", {"chat_id": "-100555", "text": "text"}))
        generic = self._payload("https://example.com/hook")[1]
        self.assertEqual(generic["events"]["went_offline"][0]["ip"], "10.0.0.5")
        self.assertNotIn("newly_online", generic["events"])

    def test_message_text(self) -> None:
        text = pingme.build_notification("PingMe · hosts.txt", self.events)
        self.assertIn("Went offline (1)", text)
        self.assertIn("db01 10.0.0.5", text)

    def test_failures_never_abort_and_nothing_is_sent_without_events(self) -> None:
        with patch.object(pingme, "send_notification", side_effect=OSError("down")), patch("sys.stderr"):
            self.assertEqual(pingme.notify_all(["https://example.com/x"], "t", self.events, quiet=True), 1)
        with patch.object(pingme, "send_notification") as send:
            pingme.notify_all(["https://example.com/x"], "t", {"went_offline": []}, quiet=True)
        send.assert_not_called()

    def test_scan_events_modes(self) -> None:
        results = [result("10.0.0.1", True), result("10.0.0.2")]
        rows = [{"host": "a", "ip": "10.0.0.1"}, {"host": "b", "ip": "10.0.0.2"}, {"host": "c", "ip": "UNRESOLVED"}]
        down = pingme.scan_events("down", results, rows, None, None)
        self.assertEqual(([e["host"] for e in down["down"]], [e["host"] for e in down["unresolved"]]), (["b"], ["c"]))
        previous = {"alive": ["10.0.0.2"], "dead": ["10.0.0.1"]}
        changes = pingme.scan_events("changes", results, rows, None, previous)
        self.assertEqual([e["ip"] for e in changes["went_offline"]], ["10.0.0.2"])
        self.assertEqual([e["ip"] for e in changes["newly_online"]], ["10.0.0.1"])


class ReportTests(unittest.TestCase):
    def test_html_report_escapes_and_includes_uptime(self) -> None:
        records = pingme.build_file_status_records(
            [{"host": "<script>x</script>", "ip": "10.0.0.1", "type": "DNS"}], [result("10.0.0.1", True)])
        page = pingme.render_html_report("T", records, [{"ip": "10.0.0.1", "availability": 99.5}], "meta")
        self.assertNotIn("<script>x</script>", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("99.5%", page)

    def test_prometheus_metrics(self) -> None:
        rows = [result("10.0.0.1", True, rtt_avg=1.5, loss_pct=0), result("10.0.0.2", loss_pct=100)]
        text = pingme.render_metrics(rows, {"10.0.0.1": 'we"b'}, 1.0, 1700000000)
        self.assertIn('pingme_up{ip="10.0.0.1",host="we\\"b"} 1', text)
        self.assertIn('pingme_packet_loss_ratio{ip="10.0.0.2"} 1.0000', text)
        self.assertIn("pingme_scan_duration_seconds 1.000", text)

    def test_nmap_xml_round_trip(self) -> None:
        rows = [result("10.0.0.1", True, hostname="gw.lan", mac="aa:bb:cc:dd:ee:ff", vendor="Acme"),
                result("2001:db8::5")]
        with tempfile.TemporaryDirectory() as directory:
            path = pingme.write_nmap_xml(rows, str(Path(directory) / "scan.xml"), "pingme x", 0)
            pairs = pingme.read_nmap_xml_targets(path.read_text())
        self.assertEqual(pairs, [("gw.lan", "10.0.0.1"), ("2001:db8::5", "2001:db8::5")])

    def test_nmap_doctype_is_accepted_but_entities_are_not(self) -> None:
        real = '<?xml version="1.0"?>\n<!DOCTYPE nmaprun>\n<nmaprun><host><address addr="10.1.1.1" addrtype="ipv4"/></host></nmaprun>'
        self.assertEqual(pingme.read_nmap_xml_targets(real), [("10.1.1.1", "10.1.1.1")])
        with self.assertRaises(ValueError):
            pingme.read_nmap_xml_targets('<!DOCTYPE x [<!ENTITY a "b">]><nmaprun/>')

    def test_uptime_ignores_probe_errors(self) -> None:
        history = [
            {"timestamp": "2026-01-01T00:00", "alive": ["10.0.0.1"], "dead": [], "errors": []},
            {"timestamp": "2026-01-02T00:00", "alive": [], "dead": ["10.0.0.1"], "errors": []},
            {"timestamp": "2026-01-03T00:00", "alive": [], "dead": [], "errors": ["10.0.0.1"]},
            {"timestamp": "2026-01-04T00:00", "alive": ["10.0.0.1"], "dead": [], "errors": []},
        ]
        row = pingme.compute_uptime(history)[0]
        self.assertEqual((row["availability"], row["changes"], row["error"]), (66.7, 2, 1))


class ToolTests(unittest.TestCase):
    def test_port_presets(self) -> None:
        self.assertEqual(pingme.parse_tcp_ports(pingme.expand_port_presets("web,22")), [80, 443, 8080, 8443, 22])
        with self.assertRaisesRegex(ValueError, "presets"):
            pingme.expand_port_presets("webz")

    def test_trace_parsing(self) -> None:
        linux = "traceroute to 10.9.9.9\n 1  192.168.0.1  1.0 ms\n 2  10.0.0.1  5.0 ms\n 3  *\n"
        self.assertEqual(pingme.parse_trace_output("10.9.9.9", linux)["last_hop"], "10.0.0.1")
        windows = ("Tracing route to 10.9.9.9\n  1    <1 ms    <1 ms    <1 ms  192.168.1.1\n"
                   "  2     2 ms     2 ms     2 ms  10.9.9.9\n")
        self.assertTrue(pingme.parse_trace_output("10.9.9.9", windows)["reached"])
        self.assertEqual(pingme.parse_trace_output("10.9.9.9", "")["hop"], 0)

    def test_magic_packet(self) -> None:
        packet = pingme.magic_packet("AA-BB-CC-DD-EE-FF")
        self.assertEqual((len(packet), packet[:6], packet[-6:].hex()), (102, b"\xff" * 6, "aabbccddeeff"))
        with self.assertRaises(ValueError):
            pingme.magic_packet("zz:bb:cc:dd:ee:ff")


class TargetFileTests(unittest.TestCase):
    def _read(self, text: str, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / kwargs.pop("name", "hosts.txt")
            path.write_text(text, encoding="utf-8")
            with patch.object(pingme, "resolve_hostname", return_value=[]), patch("builtins.print"):
                return pingme.read_target_file(str(path), str(Path(directory) / "h.txt"), quiet=True, **kwargs)

    def test_tags_filter_and_are_kept(self) -> None:
        targets, rows = self._read("10.0.0.1 gw @lan @core\n10.0.0.2 @lan\n10.0.0.3 @dmz\n", only_tags={"core", "dmz"})
        self.assertEqual(targets, ["10.0.0.1", "10.0.0.3"])
        self.assertEqual(rows[0]["tags"], ["lan", "core"])

    def test_csv_column(self) -> None:
        targets, rows = self._read("name,address\nrouter,10.0.0.1\n", name="inv.csv", column="Address")
        self.assertEqual(targets, ["10.0.0.1"])

    def test_names_are_resolved_in_parallel(self) -> None:
        import threading
        import time
        active, peak = [0], [0]
        lock = threading.Lock()

        def slow(name):
            with lock:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            time.sleep(0.05)
            with lock:
                active[0] -= 1
            return ["10.0.0.9"]

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hosts.txt"
            path.write_text("".join(f"host{n}\n" for n in range(8)), encoding="utf-8")
            with patch.object(pingme, "resolve_hostname", side_effect=slow), patch("builtins.print"):
                pingme.read_target_file(str(path), str(Path(directory) / "h.txt"), quiet=True)
        self.assertGreater(peak[0], 1)


class ChangeTests(unittest.TestCase):
    def test_mac_and_name_changes_are_reported(self) -> None:
        previous = {"timestamp": "2026-01-01T00:00", "records": [
            {"host": "pc", "ip": "10.0.0.5", "status": "REACHABLE", "mac": "aa:aa:aa:aa:aa:aa", "name": "pc.lan"}]}
        current = [{"host": "pc", "ip": "10.0.0.5", "status": "REACHABLE", "mac": "bb:bb:bb:bb:bb:bb", "name": "pc2.lan"}]
        report, groups = pingme.create_changes_report(previous, current, "hosts.txt")
        self.assertEqual(groups["mac_changed"][0]["new"], "bb:bb:bb:bb:bb:bb")
        self.assertEqual(groups["name_changed"][0]["old"], "pc.lan")
        self.assertIn("MAC ADDRESS CHANGED", report)


class FpingStreamTests(unittest.TestCase):
    def test_positives_are_handed_over_while_fping_runs(self) -> None:
        class FakePopen:
            def __init__(self, *args, **kwargs):
                self.stdin = self
                self.stdout = iter([b"10.0.0.2\n", b"203.0.113.9\n", b"10.0.0.3\n"])
                self.stderr = self
            def write(self, data): pass
            def close(self): pass
            def read(self): return b""
            def wait(self): return 0
            def kill(self): pass

        seen: list[str] = []
        with patch.object(pingme, "_FPING_PATH", "fping"), patch.object(pingme.subprocess, "Popen", FakePopen):
            alive = pingme._fping_batch_alive(["10.0.0.1", "10.0.0.2", "10.0.0.3"], 1, 1, on_alive=seen.append)
        self.assertEqual((seen, alive), (["10.0.0.2", "10.0.0.3"], {"10.0.0.2", "10.0.0.3"}))


if __name__ == "__main__":
    unittest.main()
