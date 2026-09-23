#!/usr/bin/env python3
"""Accuracy guarantees: false-negative rate under packet loss and false-positive guards."""

from __future__ import annotations

import random
import socket
import unittest
from unittest.mock import patch

import pingme


def miss_rate(loss: float, attempts: int, required: int = 2, trials: int = 60000) -> float:
    rng = random.Random(1234)
    misses = 0
    for _ in range(trials):
        replies = sent = 0
        while pingme.echo_attempt_allowed(replies, sent, attempts, required):
            sent += 1
            if rng.random() >= loss:
                replies += 1
        misses += replies < required
    return misses / trials


class FalseNegativeTests(unittest.TestCase):
    """A live host must not be reported down just because a few packets were lost."""

    def test_default_schedule_keeps_misses_below_one_in_a_thousand(self) -> None:
        self.assertLess(miss_rate(0.01, 3), 0.0001)   # typical wired LAN
        self.assertLess(miss_rate(0.05, 3), 0.001)    # busy LAN
        self.assertLess(miss_rate(0.10, 4), 0.001)    # Wi-Fi/VPN with --count 4

    def test_silent_host_costs_exactly_count_attempts(self) -> None:
        sent = 0
        while pingme.echo_attempt_allowed(0, sent, 3, 2):
            sent += 1
        self.assertEqual(sent, 3)

    def test_one_reply_is_never_enough_when_two_are_required(self) -> None:
        self.assertTrue(pingme.echo_attempt_allowed(1, 3, 3, 2))       # still confirming
        self.assertFalse(pingme.echo_attempt_allowed(1, 5, 3, 2))      # budget spent → not reachable
        self.assertFalse(pingme.echo_attempt_allowed(2, 2, 3, 2))      # confirmed, stop sending


class FalsePositiveTests(unittest.TestCase):
    """A dead address must never be reported reachable."""

    def test_firewall_accepting_every_port_is_not_evidence(self) -> None:
        with patch.object(pingme, "tcp_open_ports", side_effect=lambda ip, ports, timeout: list(ports)):
            ports, suspicious = pingme.tcp_evidence("10.0.0.9", [80, 443], 1)
        self.assertTrue(suspicious)
        result = pingme._build_probe_result("10.0.0.9", False, None, ports, "", False, None, suspicious)
        self.assertFalse(result["alive"])
        self.assertEqual(result["status"], "PROBE ERROR")

    def test_real_listener_is_evidence(self) -> None:
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        try:
            port = listener.getsockname()[1]
            ports, suspicious = pingme.tcp_evidence("127.0.0.1", [port], 1)
        finally:
            listener.close()
        self.assertEqual((ports, suspicious), ([port], False))

    def test_icmp_still_counts_behind_a_tcp_proxy(self) -> None:
        result = pingme._build_probe_result("10.0.0.9", True, 64, [80], "", False, None, True)
        self.assertTrue(result["alive"])

    def test_blanket_tcp_answers_across_a_subnet_are_refused(self) -> None:
        results = [pingme._build_probe_result(f"10.0.0.{n}", False, None, [443]) for n in range(1, 21)]
        results.append(pingme._build_probe_result("10.0.0.99", True, 64, []))
        self.assertEqual(pingme.downgrade_blanket_tcp(results), 20)
        self.assertEqual(sum(r["alive"] for r in results), 1)

    def test_a_few_tcp_only_hosts_are_kept(self) -> None:
        results = [pingme._build_probe_result(f"10.0.0.{n}", n <= 15, 64 if n <= 15 else None, []) for n in range(1, 21)]
        results.append(pingme._build_probe_result("10.0.0.50", False, None, [3389]))
        self.assertEqual(pingme.downgrade_blanket_tcp(results), 0)
        self.assertTrue(results[-1]["alive"])


if __name__ == "__main__":
    unittest.main()
