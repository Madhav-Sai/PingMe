#!/usr/bin/env python3
"""Regression tests for the 3.3 reliability fixes and new features."""

from __future__ import annotations

import json
import os
import shutil
import socket
import sys
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import pingme


class StateDirTestCase(unittest.TestCase):
    """Keep every test's history, resume, and baseline files in a private directory."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.state = Path(self._tmp.name) / "state"
        override = patch.object(pingme, "_DATA_DIR_OVERRIDE", self.state)
        override.start()
        self.addCleanup(override.stop)
        self.addCleanup(self._tmp.cleanup)


class RateLimiterTests(unittest.TestCase):
    def test_request_larger_than_rate_does_not_hang(self) -> None:
        limiter = pingme.RateLimiter(1)
        finished = threading.Event()

        def take() -> None:
            limiter.acquire(3)
            finished.set()

        threading.Thread(target=take, daemon=True).start()
        self.assertTrue(finished.wait(2), "acquire(n > rate) never returned")

    def test_borrowed_tokens_delay_the_next_caller(self) -> None:
        limiter = pingme.RateLimiter(10)
        limiter.acquire(20)  # one second of debt
        started = time.monotonic()
        limiter.acquire(1)
        self.assertGreater(time.monotonic() - started, 0.5)


class PlatformPingTests(unittest.TestCase):
    def test_macos_wait_time_is_milliseconds(self) -> None:
        with patch.object(pingme.sys, "platform", "darwin"), patch.object(pingme, "_PING_PATH", "/sbin/ping"):
            commands, _deadline, no_reply, _ = pingme._system_ping_commands("10.0.0.8", 2, 1)
        self.assertEqual(commands[0][commands[0].index("-W") + 1], "2000")
        self.assertEqual(no_reply, (2,))

    def test_macos_exit_two_is_no_response_not_probe_error(self) -> None:
        silent = subprocess.CompletedProcess(["ping"], 2, b"1 packets transmitted, 0 packets received", b"")
        with (
            patch.object(pingme.sys, "platform", "darwin"),
            patch.object(pingme, "_PING_PATH", "/sbin/ping"),
            patch.object(pingme.subprocess, "run", return_value=silent) as run_mock,
        ):
            self.assertEqual(pingme._ping_via_system("10.0.0.8", 1, 1), (False, None))
        self.assertEqual(run_mock.call_count, 1)

    def test_linux_exit_two_is_still_a_command_error(self) -> None:
        broken = subprocess.CompletedProcess(["ping"], 2, b"", b"ping: connect: Network is unreachable")
        with (
            patch.object(pingme.sys, "platform", "linux"),
            patch.object(pingme, "_PING_PATH", "ping"),
            patch.object(pingme.subprocess, "run", return_value=broken),
        ):
            with self.assertRaises(pingme.ProbeExecutionError):
                pingme._ping_via_system("10.0.0.8", 1, 1)

    def test_fractional_timeout_is_passed_to_linux_ping(self) -> None:
        with patch.object(pingme.sys, "platform", "linux"), patch.object(pingme, "_PING_PATH", "ping"):
            commands, *_ = pingme._system_ping_commands("10.0.0.8", 0.5, 1)
        self.assertEqual(commands[0][commands[0].index("-W") + 1], "0.5")
        self.assertEqual(commands[1][commands[1].index("-W") + 1], "1")

    def test_windows_timeout_uses_milliseconds(self) -> None:
        with patch.object(pingme.sys, "platform", "win32"), patch.object(pingme, "_PING_PATH", "ping"):
            commands, *_ = pingme._system_ping_commands("10.0.0.8", 1.5, 1)
        self.assertEqual(commands[0][commands[0].index("-w") + 1], "1500")


class ConfirmationTests(unittest.TestCase):
    def test_lossy_host_passes_with_two_of_five_replies(self) -> None:
        replies = [(False, None), (True, 64), (False, None), (True, 64)]
        with patch.object(pingme, "_ping_via_system", side_effect=replies) as ping_mock:
            outcome = pingme._confirm_direct_echo("10.0.0.8", 1, attempts=5, min_replies=2)
        self.assertEqual(outcome, (True, 64))
        self.assertEqual(ping_mock.call_count, 4)  # stops once two replies are in
        self.assertEqual((outcome.sent, outcome.received), (4, 2))

    def test_silent_host_gets_exactly_count_attempts(self) -> None:
        with patch.object(pingme, "_ping_via_system", return_value=(False, None)) as ping_mock:
            self.assertEqual(pingme._confirm_direct_echo("10.0.0.8", 1, attempts=3, min_replies=2), (False, None))
        self.assertEqual(ping_mock.call_count, 3)

    def test_one_lost_packet_does_not_hide_a_live_host(self) -> None:
        replies = [(True, 64), (False, None), (True, 64)]
        with patch.object(pingme, "_ping_via_system", side_effect=replies):
            self.assertEqual(pingme._confirm_direct_echo("10.0.0.8", 1, attempts=2, min_replies=2), (True, 64))

    def test_count_one_still_requires_two_independent_replies(self) -> None:
        with patch.object(pingme, "_ping_via_system", return_value=(True, 64)) as ping_mock:
            self.assertEqual(pingme._confirm_direct_echo("10.0.0.8", 1, attempts=1), (True, 64))
        self.assertEqual(ping_mock.call_count, 2)

    def test_rtt_and_loss_are_reported(self) -> None:
        line = "64 bytes from 10.0.0.8: icmp_seq=1 ttl=63 time=4.50 ms"
        reply = pingme._parse_system_ping_output("10.0.0.8", line, False)
        self.assertEqual(reply.rtts, [4.5])
        echo = pingme.EchoResult(True, 63, [4.5, 5.5], sent=3, received=2)
        result = pingme._build_probe_result("10.0.0.8", True, 63, [], echo=echo)
        self.assertEqual((result["rtt_min"], result["rtt_avg"], result["loss_pct"]), (4.5, 5.0, 33))


class ScanEngineTests(StateDirTestCase):
    def test_retries_run_inside_workers(self) -> None:
        calls: list[str] = []

        def fake_ping(ip, *_args, **_kwargs):
            calls.append(threading.current_thread().name)
            return pingme._build_probe_result(ip, len(calls) >= 2, 64, [])

        with (
            patch.object(pingme, "_use_fping", return_value=False),
            patch.object(pingme, "_ping_one", side_effect=fake_ping),
        ):
            results = pingme.run_scan(["10.0.0.1"], retry=2, quiet=True)
        self.assertTrue(results[0]["alive"])
        self.assertEqual(len(calls), 2)
        self.assertNotIn(threading.main_thread().name, calls)

    def test_fping_scan_is_split_into_chunks(self) -> None:
        addresses = [f"10.0.{index // 250}.{index % 250 + 1}" for index in range(600)]
        chunks: list[int] = []

        def fake_batch(chunk, *_args, **_kwargs):
            chunks.append(len(chunk))
            return [pingme._build_probe_result(ip, False, None, []) for ip in chunk]

        with (
            patch.object(pingme, "_use_fping", return_value=True),
            patch.object(pingme, "_scan_fping_batch", side_effect=fake_batch),
        ):
            results = pingme.run_scan(addresses, quiet=True)
        self.assertEqual(sum(chunks), 600)
        self.assertGreater(len(chunks), 1)
        self.assertEqual(len(results), 600)

    def test_tcp_ports_are_checked_concurrently(self) -> None:
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        open_port = listener.getsockname()[1]
        try:
            # 192.0.2.1 (TEST-NET) never answers, so a serial check would take ports × timeout.
            started = time.monotonic()
            found = pingme.tcp_open_ports("127.0.0.1", [open_port, 1, 2, 3], 1)
            self.assertIn(open_port, found)
            pingme.tcp_open_ports("192.0.2.1", [80, 81, 82, 83, 84], 0.5)
            self.assertLess(time.monotonic() - started, 2.5)
        finally:
            listener.close()


class ResolutionTests(unittest.TestCase):
    def test_option_like_hostnames_never_reach_a_resolver(self) -> None:
        with patch.object(pingme.subprocess, "run", side_effect=AssertionError("resolver executed")):
            for name in ("-t", "--help", "bad name", "tab\tname"):
                with self.subTest(name=name):
                    self.assertEqual(pingme.resolve_hostname(name), [])

    def test_localized_output_is_not_decoded_as_utf16(self) -> None:
        raw = "Réponse de 10.1.2.3 : octets=32 temps<1ms TTL=128".encode("cp1252")
        self.assertIn("10.1.2.3", pingme._decode_probe_output(raw))
        self.assertIn("10.1.2.3", pingme._decode_probe_output("10.1.2.3 ok".encode("utf-16")))

    def test_reverse_lookup_uses_netbios_for_lan_hosts(self) -> None:
        pingme._dns_cache.clear()
        with (
            patch.object(pingme, "_reverse_with_system", return_value=""),
            patch.object(pingme, "_reverse_with_mdns", return_value=""),
            patch.object(pingme, "_reverse_with_netbios", return_value="DESKTOP-42"),
        ):
            self.assertEqual(pingme.reverse_lookup("192.168.1.20", deep=True), ("DESKTOP-42", "netbios"))
            self.assertEqual(pingme.reverse_lookup("192.168.1.21", deep=False), ("", ""))
            self.assertEqual(pingme.reverse_lookup("8.8.4.4", deep=True), ("", ""))
        pingme._dns_cache.clear()


class ReportTests(StateDirTestCase):
    def test_failed_file_writes_the_requested_hostnames_report(self) -> None:
        directory = Path(self._tmp.name)
        targets = directory / "targets.txt"
        targets.write_text("nothing.invalid\n", encoding="utf-8")
        report = directory / "reports" / "names.txt"
        with (
            patch.object(pingme, "resolve_hostname", return_value=[]),
            patch("builtins.print"),
            self.assertRaises(SystemExit),
        ):
            pingme.read_target_file(str(targets), str(report), quiet=True)
        self.assertTrue(report.is_file())

    def test_changes_report_detects_an_ip_change(self) -> None:
        previous = {"timestamp": "2026-09-01T10:00:00", "records": [
            {"host": "pc1", "ip": "10.0.0.5", "status": "REACHABLE"},
        ]}
        current = [{"host": "pc1", "ip": "10.0.0.9", "status": "REACHABLE"}]
        report, groups = pingme.create_changes_report(previous, current, "hosts.txt")
        self.assertEqual(groups["new_targets"], [])
        self.assertEqual(groups["removed_targets"], [])
        self.assertEqual(groups["ip_changed"][0]["old_ip"], "10.0.0.5")
        self.assertIn("IP ADDRESS CHANGED", report)

    def test_compare_does_not_count_probe_errors_as_down(self) -> None:
        previous = {"alive": ["10.0.0.1", "10.0.0.2"], "dead": []}
        changes = pingme.history_changes(previous, [], ["10.0.0.1"], ["10.0.0.2"])
        self.assertEqual(changes["newly_down"], ["10.0.0.1"])
        self.assertEqual(changes["indeterminate"], ["10.0.0.2"])

    def test_diff_reads_csv_and_json_results(self) -> None:
        directory = Path(self._tmp.name)
        results = [pingme._build_probe_result("10.0.0.1", True, 64, [])]
        csv_file, json_file = directory / "a.csv", directory / "b.json"
        with patch("builtins.print"):
            pingme.write_results(results, str(csv_file), str(directory / "d.csv"), "csv", str(directory / "e.csv"))
        json_file.write_text(json.dumps(results), encoding="utf-8")
        self.assertEqual(pingme.read_snapshot_ips(str(csv_file)), {"10.0.0.1"})
        self.assertEqual(pingme.read_snapshot_ips(str(json_file)), {"10.0.0.1"})


class StateTests(StateDirTestCase):
    def test_history_is_rotated(self) -> None:
        result = [pingme._build_probe_result("10.0.0.1", True, 64, [])]
        for _ in range(5):
            pingme.save_scan("office", result, announce=False, keep=3)
        self.assertEqual(len(pingme.load_history("office")), 3)

    def test_default_data_dir_is_local_data_folder(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PINGME_DATA_DIR", None)
            self.assertEqual(pingme._default_data_dir(), Path.cwd() / "data")

    def test_output_files_are_archived_per_scan(self) -> None:
        alive = Path(self._tmp.name) / "alive.txt"
        alive.write_text("10.0.0.1\n", encoding="utf-8")
        stamps = iter(["2026-01-01_00-00-0%d" % n for n in range(5)])
        with patch.object(pingme, "datetime") as fake:
            fake.now.return_value.strftime.side_effect = lambda _fmt: next(stamps)
            for _ in range(5):
                pingme.archive_outputs("office", [str(alive), None], keep=3, announce=False)
        snapshots = pingme._snapshot_dirs("office")
        self.assertEqual([path.name for path in snapshots],
                         ["2026-01-01_00-00-02", "2026-01-01_00-00-03", "2026-01-01_00-00-04"])
        self.assertEqual((snapshots[-1] / "alive.txt").read_text(encoding="utf-8"), "10.0.0.1\n")

    def test_report_lists_live_hosts_only_with_notes(self) -> None:
        base = {"ttl": "64", "rtt": "1.2", "loss": "0%", "os_guess": "Likely Unix (≤64)", "mac": "", "vendor": ""}
        records = [
            {**base, "host": "web01", "ip": "10.0.0.1", "status": "REACHABLE", "method": "ICMP", "name": ""},
            {**base, "host": "www", "ip": "10.0.0.1", "status": "REACHABLE", "method": "ICMP", "name": ""},
            {**base, "host": "10.0.0.2", "ip": "10.0.0.2", "status": "REACHABLE", "method": "ARP/ND", "name": "cam.lan",
             "ttl": "?", "rtt": "-", "mac": "aa:bb:cc:00:00:02", "vendor": "Private (randomized MAC)"},
            {**base, "host": "db01", "ip": "10.0.0.3", "status": "NO RESPONSE", "method": "-", "name": ""},
            {**base, "host": "gone", "ip": "UNRESOLVED", "status": "UNRESOLVED", "method": "-", "name": ""},
        ]
        report = pingme.render_hosts_report(records, {"scope": "hosts.txt", "list_missing": True})
        live = report.split("LIVE HOSTS", 1)[1].split("IN-SCOPE", 1)[0]
        self.assertIn("web01, www", live)
        self.assertEqual(live.count("10.0.0.1"), 1)
        self.assertNotIn("10.0.0.3", live)
        self.assertIn("ARP reply (ICMP blocked)", live)
        self.assertIn("db01 (10.0.0.3)", report.split("WITHOUT RESPONSE", 1)[1])
        self.assertIn("UNRESOLVED NAMES (1)", report)
        self.assertIn("randomized", report.split("NOTES", 1)[1])
        names = pingme.render_hosts_report(records, {"scope": "hosts.txt"}, names_only=True)
        self.assertIn("| # | IP ADDRESS | HOSTNAME   |", names)
        self.assertNotIn("DETECTED BY", names)

    def test_legacy_cwd_state_is_still_read(self) -> None:
        legacy = Path(self._tmp.name) / "legacy"
        (legacy / "data").mkdir(parents=True)
        (legacy / "data" / ".hosts_changes.json").write_text(json.dumps({"records": [], "timestamp": "x"}))
        cwd = os.getcwd()
        os.chdir(legacy)
        try:
            with patch.dict(pingme._LEGACY_LABELS, {"hosts-abcd1234": "hosts"}):
                self.assertEqual(pingme.load_changes_state("hosts-abcd1234")["timestamp"], "x")
        finally:
            os.chdir(cwd)

    def test_same_file_name_in_two_folders_gets_two_labels(self) -> None:
        root = Path(self._tmp.name)
        (root / "a").mkdir()
        (root / "b").mkdir()
        self.assertNotEqual(pingme._file_label(str(root / "a" / "hosts.txt")),
                            pingme._file_label(str(root / "b" / "hosts.txt")))


class CliTests(StateDirTestCase):
    def test_positional_targets_are_classified(self) -> None:
        target_file = Path(self._tmp.name) / "hosts.txt"
        target_file.write_text("10.0.0.1\n", encoding="utf-8")
        subnets, files, hosts = pingme.classify_targets(["10.0.0.0/30", str(target_file), "server01", "10.0.0.9"])
        self.assertEqual((subnets, files, hosts), (["10.0.0.0/30"], [str(target_file)], ["server01", "10.0.0.9"]))
        with self.assertRaises(ValueError):
            pingme.classify_targets(["missing.txt"])

    def test_simple_toml_parser_and_validation(self) -> None:
        text = 'threads = 50\ntimeout = 0.5  # fast LAN\ntcp_ports = [22, 443]\ndns = true\nping_tool = "ping"\n'
        self.assertEqual(pingme.parse_simple_toml(text)["tcp_ports"], [22, 443])
        config_file = Path(self._tmp.name) / "config.toml"
        config_file.write_text(text, encoding="utf-8")
        config = pingme.load_config(config_file)
        self.assertEqual(config["tcp_ports"], "22,443")
        self.assertEqual(config["timeout"], 0.5)
        config_file.write_text("thread = 5\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "did you mean 'threads'"):
            pingme.load_config(config_file)

    def test_exit_codes(self) -> None:
        up = pingme._build_probe_result("10.0.0.1", True, 64, [])
        down = pingme._build_probe_result("10.0.0.2", False, None, [])
        broken = pingme._build_probe_result("10.0.0.3", False, None, [], "failed")
        self.assertEqual(pingme.scan_exit_code([up], {"10.0.0.1"}, 0), 0)
        self.assertEqual(pingme.scan_exit_code([up, down], {"10.0.0.1", "10.0.0.2"}, 0), 1)
        self.assertEqual(pingme.scan_exit_code([up], {"10.0.0.1"}, 1), 1)
        self.assertEqual(pingme.scan_exit_code([up, down], set(), 0), 0)  # subnet discovery found a host
        self.assertEqual(pingme.scan_exit_code([down], set(), 0), 1)
        self.assertEqual(pingme.scan_exit_code([up, broken], {"10.0.0.1"}, 0), 4)

    def test_unknown_option_suggests_the_closest_flag(self) -> None:
        with patch("sys.stderr") as stderr, self.assertRaises(SystemExit) as exited:
            pingme.main(["--no-config", "10.0.0.1", "--tpc-ports", "22"])
        self.assertEqual(exited.exception.code, 2)
        written = "".join(call.args[0] for call in stderr.write.call_args_list)
        self.assertIn("--tcp-ports", written)

    def test_every_option_completes_with_its_values(self) -> None:
        import install

        spec = install.completion_spec()
        options = {option for action in pingme.build_parser()._actions for option in action.option_strings}
        self.assertEqual({name for entry in spec for name in entry["names"]}, options)
        for entry in spec:
            if entry["takes_value"]:
                self.assertTrue(entry["kind"] in {"file", "dir", "iface", "subnet", "choice"} or entry["values"],
                                f"{entry['names']} has no value completion")
        scripts = {shell: getattr(install, f"{shell}_completion")() for shell in ("zsh", "bash", "fish", "powershell")}
        for shell, script in scripts.items():
            for name in options:
                spelled = (f"-l {name[2:]}" if name.startswith("--") else f"-s {name[1:]}") if shell == "fish" else name
                self.assertIn(spelled, script, f"{name} missing from {shell} completion")

    @unittest.skipUnless(shutil.which("bash"), "bash not installed")
    def test_bash_completion_offers_values_for_the_previous_flag(self) -> None:
        import install

        script = Path(self._tmp.name) / "pingme.bash"
        script.write_text(install.bash_completion(), encoding="utf-8")

        def complete(*words: str) -> list[str]:
            line = " ".join(["pingme", *words])
            probe = (f"source {script}; COMP_WORDS=(pingme {' '.join(repr(w) for w in words)}); "
                     f"COMP_CWORD={len(words)}; COMP_LINE={line!r}; _pingme_completion; printf '%s\\n' \"${{COMPREPLY[@]}}\"")
            output = subprocess.run(["bash", "-c", probe], capture_output=True, text=True, cwd=self._tmp.name)
            return output.stdout.split()

        self.assertEqual(complete("--ping-tool", ""), ["auto", "native", "fping", "ping", "ask"])
        self.assertIn("hostnames.csv", complete("--sub", "10.0.0.0/24", "--scan", "--hostnames-out", ""))
        self.assertIn("web", complete("--tcp-ports", ""))
        self.assertIn("lo", complete("-I", ""))
        self.assertIn("examples", complete("--help-topic", ""))
        self.assertIn("--interface", complete("--int"))

    def test_every_help_topic_renders(self) -> None:
        with patch("builtins.print"):
            for topic in pingme.HELP_TOPICS:
                with self.subTest(topic=topic):
                    self.assertEqual(pingme.print_topic_help(topic), 0)
            self.assertEqual(pingme.print_topic_help("exmaples"), 2)


if __name__ == "__main__":
    unittest.main()


class InterfaceTests(unittest.TestCase):
    """-I/--interface pins probes and name lookups to one adapter."""

    def setUp(self) -> None:
        self.addCleanup(setattr, pingme, "_BOUND", None)

    def test_unknown_adapter_lists_the_real_ones(self) -> None:
        with self.assertRaises(ValueError) as caught:
            pingme.resolve_interface("definitely-not-an-adapter0")
        self.assertIn("Available:", str(caught.exception))

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux device binding")
    def test_loopback_binding_is_enforced(self) -> None:
        pingme._BOUND = pingme.resolve_interface("lo")
        self.assertEqual(pingme.ping_interface_args(False), ["-I", "lo"])
        self.assertEqual(pingme.fping_interface_args(False), ["-I", "lo"])
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        self.addCleanup(listener.close)
        port = listener.getsockname()[1]
        self.assertEqual(pingme.tcp_open_ports("127.0.0.1", [port], 1), [port])
        self.assertEqual(pingme.route_mismatches(["127.0.0.1"]), [])
        self.assertTrue(pingme.route_mismatches(["192.0.2.1"]))  # normally leaves via the default route

    def test_neighbor_entries_from_other_adapters_are_not_evidence(self) -> None:
        pingme._BOUND = pingme.BoundInterface("wlan0", 3, {4: ["10.0.0.30"]}, "device")
        rows = [("10.0.0.5", "eth0", "aa:bb:cc:00:00:05", "REACHABLE"),
                ("10.0.0.6", "wlan0", "aa:bb:cc:00:00:06", "REACHABLE")]
        with patch.object(pingme, "read_neighbor_entries", side_effect=lambda family: rows if family == 4 else []):
            evidence = pingme.NeighborEvidence()
            evidence.use_as_evidence = True
            other = evidence.enrich(pingme._build_probe_result("10.0.0.5", False, None, []))
            same = evidence.enrich(pingme._build_probe_result("10.0.0.6", False, None, []))
        self.assertEqual((other["status"], same["status"]), ("NO RESPONSE", "REACHABLE"))

    def test_dns_client_parses_compressed_answers(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        self.addCleanup(server.close)

        def answer() -> None:
            query, peer = server.recvfrom(512)
            question_end = 12 + query[12:].index(b"\0") + 5
            ptr = b"\xc0\x0c" + b"\x00\x0c\x00\x01\x00\x00\x00\x3c"
            rdata = b"\x07printer\x03lan\x00"
            reply = query[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + query[12:question_end]
            server.sendto(reply + ptr + len(rdata).to_bytes(2, "big") + rdata, peer)

        threading.Thread(target=answer, daemon=True).start()
        names = pingme.dns_query("5.0.0.10.in-addr.arpa", "PTR", "127.0.0.1", port=server.getsockname()[1])
        self.assertEqual(names, ["printer.lan"])

    def test_report_records_the_interface_and_lookup_path(self) -> None:
        pingme._BOUND = pingme.BoundInterface("wlan0", 3, {4: ["10.0.0.30"]}, "device")
        pingme._BOUND.dns_servers = ["10.0.0.1"]
        self.assertEqual(pingme.name_lookup_description(),
                         "DNS 10.0.0.1 via wlan0; mDNS/NetBIOS queries sent to targets via wlan0")
        pingme._BOUND.dns_servers = []
        report = pingme.render_hosts_report([], {"scope": "x", "name_lookups": pingme.name_lookup_description()})
        self.assertIn("system resolver", report.split("LIMITATIONS", 1)[1])


class FlagHelpTests(unittest.TestCase):
    """`pingme ... FLAG -h` explains that flag."""

    def test_nearest_flag_before_help_is_explained(self) -> None:
        parser = pingme.build_parser()
        target = pingme.flag_help_target(["--sub", "10.0.0.0/24", "--scan", "--hostnames-out", "-h"], parser)
        self.assertEqual(target, "--hostnames-out")
        self.assertEqual(pingme.flag_help_target(["--timeout", "2", "--help"], parser), "--timeout")
        self.assertEqual(pingme.flag_help_target(["--hostn", "-h"], parser), "--hostnames-out")
        self.assertIsNone(pingme.flag_help_target(["10.0.0.0/24", "-h"], parser))
        self.assertIsNone(pingme.flag_help_target(["--scan"], parser))

    def test_every_option_has_working_help_with_an_example(self) -> None:
        import contextlib
        import io
        parser = pingme.build_parser()
        for entry in pingme.option_spec(parser):
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                self.assertEqual(pingme.print_flag_help(entry["names"][0], parser), pingme.EXIT_OK)
            text = pingme.ANSI_RE.sub("", buffer.getvalue()) if hasattr(pingme, "ANSI_RE") else buffer.getvalue()
            self.assertIn("$ pingme", text, entry["names"])

    def test_hostnames_help_points_to_names_only(self) -> None:
        import contextlib
        import io
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = pingme.main(["--sub", "10.0.0.0/24", "--scan", "--hostnames-out", "-h", "--color", "never"])
        self.assertEqual(code, pingme.EXIT_OK)
        self.assertIn("--names-only", buffer.getvalue())
        self.assertIn("hostnames.csv", buffer.getvalue())
