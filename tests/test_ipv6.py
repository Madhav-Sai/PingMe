#!/usr/bin/env python3
"""IPv6 support: classification, zones, discovery parsing, and family filters."""

from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

import pingme


class ClassificationTests(unittest.TestCase):
    def test_special_ipv6_ranges(self) -> None:
        expected = {
            "2001:db8::1": "Documentation",
            "2606:4700::1111": "Public",
            "2002:c000:204::1": "6to4",
            "64:ff9b::808:808": "NAT64",
            "::ffff:1.2.3.4": "IPv4-mapped",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2": "Teredo",
            "fd12:3456::1": "Private",
            "fe80::1": "Link-Local",
            "[2001:db8::5]": "Documentation",
            "fe80::1%eth0": "Link-Local",
        }
        for address, scope in expected.items():
            with self.subTest(address=address):
                self.assertEqual(pingme.ip_classify(address)["scope"], scope)

    def test_embedded_ipv4_and_eui64_mac(self) -> None:
        self.assertEqual(pingme.ip_classify("64:ff9b::808:808")["details"]["Embedded IPv4"], "8.8.8.8 (Public)")
        self.assertEqual(
            pingme.ip_classify("fe80::34de:75ff:fe8e:8955")["details"]["Interface ID"],
            "EUI-64 · MAC 36:de:75:8e:89:55",
        )


class AddressHandlingTests(unittest.TestCase):
    def test_brackets_and_zones_are_normalised(self) -> None:
        self.assertEqual(pingme._normalise_probe_address("[2001:DB8::0001]"), "2001:db8::1")
        self.assertEqual(pingme._normalise_probe_address("fe80::1%wlan0"), "fe80::1%wlan0")
        self.assertIsNone(pingme._normalise_probe_address("[ff02::1]"))

    def test_bsd_hop_limit_is_read_as_ttl(self) -> None:
        line = "16 bytes from 2001:db8::5, icmp_seq=0 hlim=57 time=12.1 ms"
        self.assertEqual(pingme._parse_system_ping_output("2001:db8::5", line, False), (True, 57))

    def test_mixed_families_sort_numerically(self) -> None:
        addresses = ["2001:db8::10", "10.0.0.10", "2001:db8::9", "10.0.0.9"]
        self.assertEqual(sorted(addresses, key=pingme.ip_sort_key),
                         ["10.0.0.9", "10.0.0.10", "2001:db8::9", "2001:db8::10"])

    def test_zoneless_link_local_is_explained_not_probed(self) -> None:
        with (
            patch.object(pingme.sys, "platform", "linux"),
            patch.object(pingme, "ipv6_interfaces", return_value=["wlan0"]),
            patch.object(pingme, "_use_fping", return_value=False),
            patch.object(pingme, "_ping_one", side_effect=AssertionError("probed")),
            patch.object(pingme, "clear_partial"),
        ):
            results = pingme.run_scan(["fe80::1"], quiet=True)
        self.assertEqual(results[0]["status"], "PROBE ERROR")
        self.assertIn("fe80::1%wlan0", results[0]["probe_error"])

    def test_family_filter_applies_to_resolution(self) -> None:
        with (
            patch.object(pingme.sys, "platform", "linux"),
            patch.object(pingme.shutil, "which", return_value="/usr/bin/getent"),
            patch.object(pingme, "_resolve_with_getent", return_value=["10.0.0.5", "2001:db8::5"]),
            patch.object(pingme, "_ADDRESS_FAMILY", 6),
        ):
            self.assertEqual(pingme.resolve_hostname("dual-stack"), ["2001:db8::5"])


class DiscoveryParsingTests(unittest.TestCase):
    def _neighbors(self, platform: str, tool: str, output: str, interfaces=None) -> dict[str, str]:
        with (
            patch.object(pingme.sys, "platform", platform),
            patch.object(pingme.shutil, "which", side_effect=lambda name: name if name.startswith(tool) else None),
            patch.object(pingme, "_run_resolution_command", return_value=output),
        ):
            return pingme.ipv6_neighbor_cache(interfaces)

    def test_linux_neighbor_cache(self) -> None:
        output = (
            "fe80::5ea6:e6ff:fecc:efb dev wlan0 lladdr 5c:a6:e6:cc:0e:fb router REACHABLE\n"
            "2001:db8::20 dev wlan0 lladdr aa:bb:cc:dd:ee:ff STALE\n"
            "fe80::99 dev wlan0 FAILED\n"
            "fe80::7 dev eth1 lladdr 00:11:22:33:44:55 DELAY\n"
        )
        self.assertEqual(self._neighbors("linux", "ip", output, ["wlan0"]), {
            "fe80::5ea6:e6ff:fecc:efb%wlan0": "5c:a6:e6:cc:0e:fb",
            "2001:db8::20": "aa:bb:cc:dd:ee:ff",
        })

    def test_windows_neighbor_cache(self) -> None:
        output = (
            "Interface 12: Ethernet\n\n"
            "Internet Address                              Physical Address   Type\n"
            "--------------------------------------------  -----------------  -----------\n"
            "fe80::1                                       00-11-22-33-44-55  Reachable (Router)\n"
            "fe80::2                                                          Unreachable\n"
            "ff02::1                                       33-33-00-00-00-01  Permanent\n"
        )
        self.assertEqual(self._neighbors("win32", "netsh", output), {"fe80::1%12": "00:11:22:33:44:55"})

    def test_macos_neighbor_cache(self) -> None:
        output = (
            "Neighbor                        Linklayer Address  Netif Expire    St Flgs Prbs\n"
            "fe80::1%en0                     0:11:22:33:44:55   en0 23h59m58s S  R\n"
            "fe80::9%en0                     (incomplete)       en0 expired   N\n"
        )
        self.assertEqual(self._neighbors("darwin", "ndp", output), {"fe80::1%en0": "0:11:22:33:44:55"})

    def test_multicast_replies_become_zoned_candidates(self) -> None:
        output = (
            b"PING ff02::1%wlan0 (ff02::1%wlan0) 56 data bytes\n"
            b"64 bytes from fe80::5ea6:e6ff:fecc:efb%wlan0: icmp_seq=1 ttl=64 time=1.4 ms\n"
            b"64 bytes from fe80::c21:b67b:ddc:9ffc%wlan0: icmp_seq=1 ttl=64 time=16 ms\n"
        )
        with (
            patch.object(pingme.sys, "platform", "linux"),
            patch.object(pingme.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, output, b"")),
        ):
            found = pingme._multicast_echo_replies("wlan0", 1)
        self.assertEqual(found, {"fe80::5ea6:e6ff:fecc:efb%wlan0", "fe80::c21:b67b:ddc:9ffc%wlan0"})


class LabelTests(unittest.TestCase):
    def test_long_labels_fit_in_a_filename(self) -> None:
        label = "_".join(f"host{index}.example.com" for index in range(100))
        safe = pingme._safe_label(label)
        self.assertLessEqual(len(safe), 80)
        self.assertNotEqual(safe, pingme._safe_label(label + "x"))


if __name__ == "__main__":
    unittest.main()
