#!/usr/bin/env python3
"""Check the bounded example policy and, optionally, a combined-feature binary."""

import argparse
import copy
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "docs/examples/tailscale-shadowsocks.json"
BINARY = None
SRS_URLS = {
    "geosite-cn": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
    "geoip-cn": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
}
DNS_RULES = [
    {"preferred_by": "tailnet-dns", "action": "route", "server": "tailnet-dns"},
    {
        "type": "logical", "mode": "or",
        "rules": [{"domain_suffix": ["ts.net"]}, {"domain_regex": ["^[^.]+\\.?$"]}],
        "action": "route", "server": "tailnet-dns",
    },
    {
        "domain_suffix": ["local", "lan", "home.arpa", "internal", "in-addr.arpa", "ip6.arpa"],
        "action": "reject",
    },
    {"rule_set": ["geosite-cn"], "action": "route", "server": "cn-dns"},
]
ROUTE_RULES = [
    {"inbound": ["tailnet"], "action": "reject"},
    {"inbound": ["local-proxy"], "port": [53], "action": "hijack-dns"},
    {"action": "resolve"},
    {"preferred_by": "tailnet", "action": "route", "outbound": "tailnet"},
    {
        "ip_cidr": ["100.64.0.0/10", "fd7a:115c:a1e0::/48"],
        "action": "route", "outbound": "tailnet",
    },
    {"ip_is_private": True, "action": "route", "outbound": "direct"},
    {"rule_set": ["geosite-cn"], "action": "route", "outbound": "direct"},
    {"rule_set": ["geoip-cn"], "action": "route", "outbound": "direct"},
]


class ExampleTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(EXAMPLE.is_file(), f"missing combined example: {EXAMPLE}")
        self.config = json.loads(EXAMPLE.read_text(encoding="utf-8"))

    def assert_policy(self, config):
        self.assertEqual(config["route"]["final"], "shadowsocks",
                         "overseas/unmatched traffic must default to Shadowsocks")
        self.assertEqual(set(config), {
            "dns", "inbounds", "endpoints", "outbounds", "route", "http_clients", "experimental",
        })
        self.assertEqual(config["inbounds"], [{
            "type": "mixed", "tag": "local-proxy", "listen": "127.0.0.1",
            "listen_port": 2080, "set_system_proxy": False,
        }], "only an explicit loopback mixed proxy is allowed")
        self.assertEqual(len(config["endpoints"]), 1)
        endpoint = config["endpoints"][0]
        self.assertEqual(endpoint["type"], "tailscale")
        self.assertEqual(endpoint["tag"], "tailnet")
        self.assertEqual(endpoint["state_directory"], "./private-state/tailscale",
                         "persistent node state needs an explicit private deployment path")
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
        self.assertEqual(proxy["domain_resolver"], "cn-dns",
                         "proxy bootstrap must not recursively use encrypted DNS through itself")
        for item in [endpoint, *config["outbounds"]]:
            self.assertNotIn("detour", item, "Tailscale and Shadowsocks must not be chained")
        self.assertEqual(config["dns"]["servers"], [
            {
                "type": "tailscale", "tag": "tailnet-dns", "endpoint": "tailnet",
                "accept_default_resolvers": False, "accept_search_domain": True,
            },
            {"type": "udp", "tag": "cn-dns", "server": "223.5.5.5", "server_port": 53},
            {
                "type": "https", "tag": "external-dns", "server": "1.1.1.1",
                "server_port": 443, "path": "/dns-query",
                "tls": {"enabled": True, "server_name": "cloudflare-dns.com"},
                "detour": "shadowsocks",
            },
        ], "encrypted DNS must use Shadowsocks with an IP bootstrap")
        self.assertEqual(config["dns"]["rules"], DNS_RULES,
                         "dynamic tailnet DNS and private-name guards must precede public DNS")
        self.assertEqual(config["dns"]["final"], "external-dns")
        self.assertEqual(config["dns"]["strategy"], "prefer_ipv4")
        self.assertEqual(set(config["dns"]), {"servers", "rules", "final", "strategy"})
        self.assertEqual(config["http_clients"], [{"tag": "rule-download", "detour": "shadowsocks"}],
                         "rule downloads must use Shadowsocks")
        self.assertEqual(config["experimental"], {
            "cache_file": {"enabled": True, "path": "./private-state/cache.db"},
        }, "remote rules require persistent cache storage")
        route = config["route"]
        self.assertEqual(route["default_domain_resolver"], "cn-dns")
        self.assertEqual(route["rules"], ROUTE_RULES,
                         "route order: reject ingress, hijack DNS, resolve, tailnet IPv4 and IPv6, "
                         "private direct, CN domains, CN IPs")
        self.assertEqual(route["rule_set"], [
            {
                "type": "remote", "tag": tag, "format": "binary", "url": url,
                "http_client": "rule-download", "update_interval": "1d",
            } for tag, url in SRS_URLS.items()
        ], "maintained binary rule sets must use the proxy HTTP client")
        self.assertEqual(set(route), {"rules", "rule_set", "final", "default_domain_resolver"})

    def test_example_policy(self):
        self.assert_policy(self.config)

    def test_missing_tailnet_ipv6_is_rejected(self):
        self.config["route"]["rules"][4]["ip_cidr"].remove("fd7a:115c:a1e0::/48")
        with self.assertRaisesRegex(AssertionError, "IPv4 and IPv6"):
            self.assert_policy(self.config)

    def test_wrong_routing_order_is_rejected(self):
        rules = self.config["route"]["rules"]
        rules[4], rules[5] = rules[5], rules[4]
        with self.assertRaisesRegex(AssertionError, "route order"):
            self.assert_policy(self.config)

    def test_direct_default_is_rejected(self):
        self.config["route"]["final"] = "direct"
        with self.assertRaisesRegex(AssertionError, "default to Shadowsocks"):
            self.assert_policy(self.config)

    def test_missing_resolve_or_ingress_reject_is_rejected(self):
        for index in (0, 2):
            with self.subTest(index=index):
                invalid = copy.deepcopy(self.config)
                del invalid["route"]["rules"][index]
                with self.assertRaisesRegex(AssertionError, "route order"):
                    self.assert_policy(invalid)

    def test_resolve_server_override_is_rejected(self):
        self.config["route"]["rules"][2]["server"] = "cn-dns"
        with self.assertRaisesRegex(AssertionError, "route order"):
            self.assert_policy(self.config)

    def test_missing_private_dns_guards_is_rejected(self):
        for index in (0, 1, 2):
            with self.subTest(index=index):
                invalid = copy.deepcopy(self.config)
                del invalid["dns"]["rules"][index]
                with self.assertRaisesRegex(AssertionError, "private-name guards"):
                    self.assert_policy(invalid)

    def test_short_name_guard(self):
        pattern = self.config["dns"]["rules"][1]["rules"][1]["domain_regex"][0]
        for name in ("peer", "peer.", "printer", "printer."):
            self.assertIsNotNone(re.fullmatch(pattern, name), name)
        for name in ("www.example.com", "peer.ts.net", ".", ""):
            self.assertIsNone(re.fullmatch(pattern, name), name)

    def test_direct_encrypted_dns_is_rejected(self):
        self.config["dns"]["servers"][2]["detour"] = "direct"
        with self.assertRaisesRegex(AssertionError, "encrypted DNS"):
            self.assert_policy(self.config)

    def test_recursive_proxy_dns_is_rejected(self):
        self.config["outbounds"][0]["domain_resolver"] = "external-dns"
        with self.assertRaisesRegex(AssertionError, "proxy bootstrap"):
            self.assert_policy(self.config)

    def test_direct_rule_downloads_is_rejected(self):
        self.config["http_clients"][0]["detour"] = "direct"
        with self.assertRaisesRegex(AssertionError, "rule downloads"):
            self.assert_policy(self.config)

    def test_rule_set_client_bypass_is_rejected(self):
        for index in range(2):
            with self.subTest(index=index):
                invalid = copy.deepcopy(self.config)
                invalid["route"]["rule_set"][index]["http_client"] = {"detour": "direct"}
                with self.assertRaisesRegex(AssertionError, "proxy HTTP client"):
                    self.assert_policy(invalid)

    def test_missing_persistent_cache_is_rejected(self):
        self.config["experimental"]["cache_file"]["enabled"] = False
        with self.assertRaisesRegex(AssertionError, "persistent cache"):
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
