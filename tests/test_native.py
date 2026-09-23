#!/usr/bin/env python3
"""Native ICMP engine: reply matching rules and engine selection."""

from __future__ import annotations

import socket
import unittest
from unittest.mock import patch

import pingme


def echo_reply(pinger: pingme.NativePinger, counter: int, payload: bytes | None = None) -> bytes:
    body = payload if payload is not None else pinger._payload(counter)
    return bytes([0, 0, 0, 0]) + pinger.ident.to_bytes(2, "big") + (counter & 0xFFFF).to_bytes(2, "big") + body


class ReplyMatchingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pinger = pingme.NativePinger()
        self.target = pingme._TargetState("10.0.0.8")
        self.pinger.outstanding[7] = (self.target, 0.0, 0)

    def test_exact_reply_from_target_counts(self) -> None:
        self.pinger._handle(4, "dgram", echo_reply(self.pinger, 7), [], ("10.0.0.8", 0))
        self.assertEqual(self.target.received, {7})

    def test_reply_from_another_address_never_counts(self) -> None:
        self.pinger._handle(4, "dgram", echo_reply(self.pinger, 7), [], ("10.0.0.1", 0))
        self.assertEqual(self.target.received, set())

    def test_foreign_token_is_ignored(self) -> None:
        other = pingme.NativePinger()
        self.pinger._handle(4, "dgram", echo_reply(other, 7), [], ("10.0.0.8", 0))
        self.assertEqual(self.target.received, set())
        self.assertEqual(self.target.error, "")

    def test_altered_payload_is_an_integrity_error(self) -> None:
        corrupted = bytearray(self.pinger._payload(7))
        corrupted[-1] ^= 0xFF
        self.pinger._handle(4, "dgram", echo_reply(self.pinger, 7, bytes(corrupted)), [], ("10.0.0.8", 0))
        self.assertEqual(self.target.received, set())
        self.assertIn("payload", self.target.error)

    def test_duplicate_reply_counts_once(self) -> None:
        for _ in range(3):
            self.pinger._handle(4, "dgram", echo_reply(self.pinger, 7), [], ("10.0.0.8", 0))
        self.assertEqual(len(self.target.rtts), 1)

    def test_raw_socket_reads_ttl_from_ip_header_and_checks_identifier(self) -> None:
        header = bytes([0x45, 0, 0, 0, 0, 0, 0, 0, 57, 1]) + bytes(10)
        self.pinger._handle(4, "raw", header + echo_reply(self.pinger, 7), [], ("10.0.0.8", 0))
        self.assertEqual(self.target.ttl, 57)
        stranger = bytearray(echo_reply(self.pinger, 7))
        stranger[4:6] = ((self.pinger.ident + 1) & 0xFFFF).to_bytes(2, "big")
        target = pingme._TargetState("10.0.0.9")
        self.pinger.outstanding[8] = (target, 0.0, 0)
        self.pinger._handle(4, "raw", header + bytes(stranger), [], ("10.0.0.9", 0))
        self.assertEqual(target.received, set())

    def test_ipv6_hop_limit_from_ancillary_data(self) -> None:
        target = pingme._TargetState("2001:db8::5")
        self.pinger.outstanding[9] = (target, 0.0, 0)
        reply = bytes([129]) + echo_reply(self.pinger, 9)[1:]
        ancillary = [(socket.IPPROTO_IPV6, pingme._IPV6_HOPLIMIT, (61).to_bytes(4, "little"))]
        self.pinger._handle(6, "dgram", reply, ancillary, ("2001:db8::5", 0, 0, 0))
        self.assertEqual((target.received, target.ttl), ({9}, 61))


class SweepTests(unittest.TestCase):
    def test_lossy_target_reaches_threshold_and_silent_target_costs_one_round(self) -> None:
        answers = {"10.0.0.1": [False, True, True], "10.0.0.2": [False, False, False]}
        sent_to: list[str] = []

        def fake_send(pinger, target, round_index):
            sent_to.append(target.ip)
            target.sent += 1
            if answers[target.ip][round_index]:
                target.received.add(round_index)
                target.rtts.append(1.0)
                target.ttl = 64
                target.round_seen = round_index

        with (
            patch.object(pingme.NativePinger, "send", fake_send),
            patch.object(pingme.NativePinger, "_socket", return_value=(None, "dgram")),
            patch.object(pingme.NativePinger, "receive_loop", lambda self: None),
            patch.object(pingme.NativePinger, "close", lambda self: None),
        ):
            results = pingme.native_icmp_sweep(["10.0.0.1", "10.0.0.2"], 0.05, attempts=3, min_replies=2)
        self.assertEqual(results["10.0.0.1"][0], (True, 64))
        self.assertEqual(results["10.0.0.2"][0], (False, None))
        # The silent host is dropped once two replies are out of reach (after round 2).
        self.assertEqual(sent_to.count("10.0.0.2"), 2)


class EngineSelectionTests(unittest.TestCase):
    def test_auto_prefers_native_on_linux(self) -> None:
        with (
            patch.object(pingme.sys, "platform", "linux"),
            patch.object(pingme, "native_engine_available", return_value=True),
            patch.object(pingme, "_FPING_PATH", "fping"),
        ):
            self.assertEqual(pingme.check_deps("auto"), "native")

    def test_auto_keeps_process_engines_on_macos(self) -> None:
        with (
            patch.object(pingme.sys, "platform", "darwin"),
            patch.object(pingme, "native_engine_available", return_value=True),
            patch.object(pingme, "_FPING_PATH", None),
            patch.object(pingme, "_PING_PATH", "/sbin/ping"),
        ):
            self.assertEqual(pingme.check_deps("auto"), "ping")

    def test_timeout_argument_accepts_auto(self) -> None:
        self.assertIsNone(pingme._timeout_argument("auto"))
        self.assertEqual(pingme._timeout_argument("0.5"), 0.5)


@unittest.skipUnless(pingme.native_engine_available(), "ICMP sockets not permitted here")
class LiveNativeTests(unittest.TestCase):
    def test_loopback_answers_and_documentation_address_does_not(self) -> None:
        results = pingme.native_icmp_sweep(["127.0.0.1", "192.0.2.1"], 0.5, 2, 2)
        self.assertTrue(results["127.0.0.1"][0][0])
        self.assertEqual(results["127.0.0.1"][0].received, 2)
        self.assertFalse(results["192.0.2.1"][0][0])
        self.assertEqual(results["192.0.2.1"][1], "")  # silent, not an error


if __name__ == "__main__":
    unittest.main()
