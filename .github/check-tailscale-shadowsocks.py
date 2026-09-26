#!/usr/bin/env python3
"""Check the bounded example policy and, optionally, a combined-feature binary."""

import argparse
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "docs/examples/tailscale-shadowsocks.json"
BINARY = None


class ExampleTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(EXAMPLE.is_file(), f"missing combined example: {EXAMPLE}")
        self.config = json.loads(EXAMPLE.read_text(encoding="utf-8"))

    def assert_policy(self, config):
        self.assertEqual(set(config), {"dns", "inbounds", "endpoints", "outbounds", "route"})
        self.assertEqual(config["inbounds"], [{
            "type": "mixed", "tag": "local-proxy", "listen": "127.0.0.1",
            "listen_port": 2080, "set_system_proxy": False,
        }], "only an explicit loopback mixed proxy is allowed")
        self.assertEqual(len(config["endpoints"]), 1)
        endpoint = config["endpoints"][0]
        self.assertEqual(endpoint["type"], "tailscale")
        self.assertEqual(endpoint["tag"], "tailnet")
        self.assertTrue(endpoint["state_directory"], "persistent node state needs a directory")
        for field in ("system_interface", "accept_routes", "advertise_exit_node"):
            self.assertIs(endpoint[field], False, f"{field} must remain disabled")
        self.assertFalse(endpoint.get("exit_node"), "no exit node")
        self.assertFalse(endpoint.get("advertise_routes"), "no advertised subnets")
        self.assertNotIn("auth_key", endpoint, "never commit a Tailscale auth key")
        outbounds = {item["tag"]: item for item in config["outbounds"]}
        self.assertEqual(len(config["outbounds"]), 2)
        self.assertEqual(set(outbounds), {"shadowsocks", "direct"})
        self.assertEqual(outbounds["direct"], {"type": "direct", "tag": "direct"})
        proxy = outbounds["shadowsocks"]
        self.assertEqual(proxy["type"], "shadowsocks")
        self.assertEqual(proxy["server"], "proxy.example")
        self.assertEqual(proxy["server_port"], 8388)
        self.assertEqual(proxy["method"], "chacha20-ietf-poly1305")
        self.assertEqual(proxy["password"], "INSECURE-EXAMPLE-ONLY-REPLACE-ME")
        for item in [endpoint, *config["outbounds"]]:
            self.assertNotIn("detour", item, "Tailscale and Shadowsocks must not be chained")
        self.assertEqual(config["dns"], {"servers": [{"type": "local", "tag": "local"}]})
        route = config["route"]
        self.assertEqual(route["default_domain_resolver"], "local")
        self.assertEqual(route["final"], "direct", "unmatched traffic must default to direct")
        self.assertEqual(len(route["rules"]), 2, "only tailnet and selected Internet rules")
        tailnet, selected = route["rules"]
        self.assertEqual(tailnet.get("outbound"), "tailnet", "tailnet rule must come first")
        self.assertEqual(set(tailnet.get("ip_cidr", [])),
                         {"100.64.0.0/10", "fd7a:115c:a1e0::/48"},
                         "tailnet rule must cover IPv4 and IPv6, not all private networks")
        self.assertEqual(set(tailnet), {"ip_cidr", "action", "outbound"})
        self.assertEqual(tailnet["action"], "route")
        self.assertEqual(selected, {
            "domain": ["selected.example"], "action": "route", "outbound": "shadowsocks",
        }, "only the selected exact domain should use Shadowsocks")
        self.assertEqual(set(route), {"rules", "final", "default_domain_resolver"})

    def test_example_policy(self):
        self.assert_policy(self.config)

    def test_missing_tailnet_ipv6_is_rejected(self):
        self.config["route"]["rules"][0]["ip_cidr"].remove("fd7a:115c:a1e0::/48")
        with self.assertRaisesRegex(AssertionError, "IPv4 and IPv6"):
            self.assert_policy(self.config)

    def test_wrong_routing_order_is_rejected(self):
        self.config["route"]["rules"].reverse()
        with self.assertRaisesRegex(AssertionError, "tailnet rule must come first"):
            self.assert_policy(self.config)

    def test_proxy_default_is_rejected(self):
        self.config["route"]["final"] = "shadowsocks"
        with self.assertRaisesRegex(AssertionError, "default to direct"):
            self.assert_policy(self.config)

    def test_chaining_is_rejected(self):
        self.config["outbounds"][0]["detour"] = "tailnet"
        with self.assertRaisesRegex(AssertionError, "must not be chained"):
            self.assert_policy(self.config)

    def test_non_loopback_listener_is_rejected(self):
        self.config["inbounds"][0]["listen"] = "0.0.0.0"
        with self.assertRaisesRegex(AssertionError, "loopback"):
            self.assert_policy(self.config)

    def run_binary(self, *args, cwd):
        if BINARY is None:
            self.skipTest("supply --binary for version and actual sing-box check")
        return subprocess.run(
            [str(BINARY), *args], cwd=cwd, capture_output=True, text=True, timeout=30,
        )

    def test_binary_has_tailscale(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_binary("version", cwd=directory)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        print(result.stdout, end="")
        tags = next((line[6:] for line in result.stdout.splitlines()
                     if line.startswith("Tags: ")), "")
        self.assertIn("with_tailscale", tags.split(","), "binary must include with_tailscale")

    def test_binary_check(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_binary("check", "-c", str(EXAMPLE), cwd=directory)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(list(Path(directory).iterdir()), [],
                             "check must not create runtime node state")

    def test_binary_rejects_unknown_schema_field(self):
        invalid = copy.deepcopy(self.config)
        invalid["endpoints"][0]["not_a_tailscale_option"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            path.write_text(json.dumps(invalid), encoding="utf-8")
            result = self.run_binary("check", "-c", str(path), cwd=directory)
        self.assertNotEqual(result.returncode, 0, "unknown schema field must fail check")
        self.assertIn('unknown field "not_a_tailscale_option"', result.stdout + result.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, help="path to a native combined-feature sing-box")
    args = parser.parse_args()
    if args.binary is not None:
        BINARY = args.binary.resolve()
        if not BINARY.is_file():
            parser.error(f"binary does not exist: {BINARY}")
    unittest.main(argv=[__file__], verbosity=2)
