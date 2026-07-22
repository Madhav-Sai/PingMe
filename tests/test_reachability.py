#!/usr/bin/env python3
"""Fail-closed reachability regression tests."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pingme


WINDOWS_REPLY = """
Pinging 192.168.24.105 with 32 bytes of data:
Reply from 192.168.24.105: bytes=32 time=2ms TTL=122
Ping statistics for 192.168.24.105:
    Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),
"""

WINDOWS_UNREACHABLE = """
Pinging 192.168.24.101 with 32 bytes of data:
Reply from 192.168.24.1: Destination host unreachable.
Reply from 192.168.24.1: Destination host unreachable.
Ping statistics for 192.168.24.101:
    Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),
"""


class ParserTests(unittest.TestCase):
    def test_resolution_error_syntax_does_not_become_ipv6_target(self) -> None:
        output = "Exception calling [System.Net.Dns]::GetHostAddresses with 1 argument"
        self.assertEqual(pingme._extract_ip_addresses(output), [])

    def test_non_host_destinations_are_rejected(self) -> None:
        for address in ("0.0.0.0", "::", "224.0.0.1", "ff02::1", "255.255.255.255"):
            with self.subTest(address=address):
                self.assertIsNone(pingme._normalise_probe_address(address))
        self.assertEqual(pingme._normalise_probe_address("fe80::1%12"), "fe80::1%12")

    def test_windows_direct_ipv4_reply_is_reachable(self) -> None:
        self.assertEqual(
            pingme._parse_system_ping_output("192.168.24.105", WINDOWS_REPLY, True),
            (True, 122),
        )

    def test_windows_destination_unreachable_is_not_reachable(self) -> None:
        self.assertEqual(
            pingme._parse_system_ping_output("192.168.24.101", WINDOWS_UNREACHABLE, True),
            (False, None),
        )

    def test_windows_received_summary_without_echo_is_not_reachable(self) -> None:
        output = "Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)"
        self.assertEqual(pingme._parse_system_ping_output("10.0.0.8", output, True), (False, None))

    def test_windows_error_claiming_to_come_from_target_is_not_reachable(self) -> None:
        output = "Reply from 10.0.0.8: Destination host unreachable."
        self.assertEqual(pingme._parse_system_ping_output("10.0.0.8", output, True), (False, None))

    def test_windows_direct_ipv6_reply_is_reachable(self) -> None:
        output = "Reply from ::1: time<1ms"
        self.assertEqual(pingme._parse_system_ping_output("::1", output, True), (True, None))

    def test_windows_reply_from_different_ip_is_not_reachable(self) -> None:
        output = "Reply from 10.0.0.1: bytes=32 time=1ms TTL=64"
        self.assertEqual(pingme._parse_system_ping_output("10.0.0.8", output, True), (False, None))

    def test_unix_direct_echo_reply_is_reachable(self) -> None:
        output = "64 bytes from 10.0.0.8: icmp_seq=1 ttl=61 time=1.23 ms"
        self.assertEqual(pingme._parse_system_ping_output("10.0.0.8", output, False), (True, 61))

    def test_unix_icmp_error_is_not_reachable(self) -> None:
        output = "From 10.0.0.1 icmp_seq=1 Destination Host Unreachable\n1 packets transmitted, 1 received"
        self.assertEqual(pingme._parse_system_ping_output("10.0.0.8", output, False), (False, None))

    def test_fping_requires_exact_target_response_line(self) -> None:
        stdout = "10.0.0.8 : [0], 64 bytes, 1.20 ms (1.20 avg, 0% loss)"
        stderr = "10.0.0.8 : xmt/rcv/%loss = 1/1/0%, min/avg/max = 1.20/1.20/1.20"
        self.assertEqual(pingme._parse_fping_output("10.0.0.8", stdout, stderr), (True, None))
        self.assertEqual(pingme._parse_fping_output("10.0.0.9", stdout, stderr), (False, None))

    def test_fping_timeout_line_is_not_reachable(self) -> None:
        stdout = "10.0.0.8 : [0], timed out (NaN avg, 100% loss)"
        stderr = "10.0.0.8 : xmt/rcv/%loss = 1/0/100%"
        self.assertEqual(pingme._parse_fping_output("10.0.0.8", stdout, stderr), (False, None))

    def test_fping_icmp_error_byte_line_with_zero_received_is_not_reachable(self) -> None:
        stdout = "10.0.0.8 : [0], 84 bytes, 0.42 ms (0.42 avg, 0% loss)"
        stderr = "10.0.0.8 : xmt/rcv/%loss = 1/0/100%"
        self.assertEqual(pingme._parse_fping_output("10.0.0.8", stdout, stderr), (False, None))

    def test_ttl_hint_uses_next_common_initial_ttl(self) -> None:
        self.assertEqual(pingme.ttl_to_os(64), "Likely Unix (≤64)")
        self.assertEqual(pingme.ttl_to_os(122), "Likely Windows (≤128)")
        self.assertEqual(pingme.ttl_to_os(250), "Likely network (≤255)")
        self.assertEqual(pingme.ttl_to_os(None), "Unknown")


class BackendTests(unittest.TestCase):
    def test_fping_exit_one_overrides_deceptive_packet_text(self) -> None:
        stdout = b"10.0.0.8 : [0], 84 bytes, 0.42 ms (0.42 avg, 0% loss)"
        stderr = b"10.0.0.8 : xmt/rcv/%loss = 1/1/0%, min/avg/max = 0.42/0.42/0.42"
        completed = subprocess.CompletedProcess(["fping"], 1, stdout, stderr)
        with (
            patch.object(pingme, "_FPING_PATH", "fping"),
            patch.object(pingme.subprocess, "run", return_value=completed),
        ):
            self.assertEqual(pingme._ping_via_fping("10.0.0.8", 1, 1), (False, None))

    def test_fping_requires_success_exit_summary_and_packet_evidence(self) -> None:
        stdout = b"10.0.0.8 : [0], 64 bytes, 0.42 ms (0.42 avg, 0% loss)"
        stderr = b"10.0.0.8 : xmt/rcv/%loss = 1/1/0%, min/avg/max = 0.42/0.42/0.42"
        completed = subprocess.CompletedProcess(["fping"], 0, stdout, stderr)
        with (
            patch.object(pingme, "_FPING_PATH", "fping"),
            patch.object(pingme.subprocess, "run", return_value=completed),
        ):
            self.assertEqual(pingme._ping_via_fping("10.0.0.8", 1, 1), (True, None))

    def test_failed_resolution_command_output_is_discarded(self) -> None:
        failed = subprocess.CompletedProcess(["resolver"], 1, b"Address: 8.8.8.8", b"")
        with patch.object(pingme.subprocess, "run", return_value=failed):
            self.assertEqual(pingme._run_resolution_command(["resolver"]), "")

    def test_windows_backend_rejects_unreachable_received_packets(self) -> None:
        completed = subprocess.CompletedProcess(["ping"], 0, WINDOWS_UNREACHABLE.encode(), b"")
        with (
            patch.object(pingme.sys, "platform", "win32"),
            patch.object(pingme, "_PING_PATH", "ping"),
            patch.object(pingme.subprocess, "run", return_value=completed),
        ):
            self.assertEqual(pingme._ping_via_system("192.168.24.101", 1, 2), (False, None))

    def test_unix_backend_retries_compatible_command_after_usage_error(self) -> None:
        failed = subprocess.CompletedProcess(["ping"], 2, b"", b"invalid option")
        replied = subprocess.CompletedProcess(
            ["ping"], 0, b"64 bytes from 10.0.0.8: icmp_seq=1 ttl=63 time=1 ms", b""
        )
        with (
            patch.object(pingme.sys, "platform", "linux"),
            patch.object(pingme, "_PING_PATH", "ping"),
            patch.object(pingme.subprocess, "run", side_effect=[failed, replied]) as run_mock,
        ):
            self.assertEqual(pingme._ping_via_system("10.0.0.8", 1, 1), (True, 63))
            self.assertEqual(run_mock.call_count, 2)

    def test_command_failure_becomes_probe_error(self) -> None:
        with (
            patch.object(pingme, "_use_fping", return_value=False),
            patch.object(pingme, "_PING_PATH", "ping"),
            patch.object(pingme, "_PING6_PATH", None),
            patch.object(pingme, "_ping_via_system", side_effect=pingme.ProbeExecutionError("broken ping")),
        ):
            result = pingme._ping_one("10.0.0.8", count=1)
        self.assertFalse(result["alive"])
        self.assertEqual(result["status"], "PROBE ERROR")
        self.assertIn("broken ping", result["probe_error"])

    def test_tcp_acceptance_is_explicit_reachability_evidence(self) -> None:
        with (
            patch.object(pingme, "_use_fping", return_value=False),
            patch.object(pingme, "_PING_PATH", "ping"),
            patch.object(pingme, "_ping_via_system", return_value=(False, None)),
            patch.object(pingme, "tcp_open_ports", return_value=[443]),
        ):
            result = pingme._ping_one("10.0.0.8", count=1, tcp_ports=[443])
        self.assertTrue(result["alive"])
        self.assertEqual(result["status"], "REACHABLE")
        self.assertEqual(result["evidence"], "TCP connection accepted")


class ReportingTests(unittest.TestCase):
    def test_probe_errors_are_not_written_as_no_response(self) -> None:
        base = {
            "ttl": None,
            "os_guess": "",
            "hostname": "",
            "scope": "Private",
            "rfc": "RFC 1918",
            "icmp_alive": False,
            "tcp_open": [],
            "evidence": "",
            "probe_error": "",
        }
        results = [
            {**base, "ip": "10.0.0.1", "alive": True, "status": "REACHABLE"},
            {**base, "ip": "10.0.0.2", "alive": False, "status": "NO RESPONSE"},
            {**base, "ip": "10.0.0.3", "alive": False, "status": "PROBE ERROR", "probe_error": "failed"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch("builtins.print"):
                pingme.write_results(
                    results,
                    alive_file=str(root / "alive.txt"),
                    dead_file=str(root / "dead.txt"),
                    error_file=str(root / "errors.txt"),
                )
            self.assertEqual((root / "alive.txt").read_text().strip(), "10.0.0.1")
            self.assertEqual((root / "dead.txt").read_text().strip(), "10.0.0.2")
            self.assertEqual((root / "errors.txt").read_text().strip(), "10.0.0.3")

    def test_probe_error_never_generates_went_offline_alert(self) -> None:
        previous = {
            "timestamp": "2026-07-21T12:00:00",
            "records": [{"host": "node", "ip": "10.0.0.8", "status": "REACHABLE"}],
        }
        current = [{"host": "node", "ip": "10.0.0.8", "status": "PROBE ERROR"}]
        _report, groups = pingme.create_changes_report(previous, current, "targets.txt")
        self.assertEqual(groups["went_offline"], [])
        self.assertEqual(current, groups["indeterminate"])


if __name__ == "__main__":
    unittest.main()
