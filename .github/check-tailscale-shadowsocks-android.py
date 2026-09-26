#!/usr/bin/env python3
"""Check the documentation-only SFA 1.14.2 profile, not a deployed configuration."""

import argparse
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "docs/examples/tailscale-shadowsocks-android-1.14.2.json"
TARGET_VERSION = "1.14.2"
TARGET_REVISION = "af6e64c3b69e6132ebaee0e1a3d24e93903f6709"
BINARY = None
FORK_BINARY = None
spec = importlib.util.spec_from_file_location(
    "cli_policy", ROOT / ".github/check-tailscale-shadowsocks.py",
)
cli_policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli_policy)
TUN = {
    "type": "tun", "tag": "tun-in",
    "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
    "auto_route": True, "stack": "mixed",
}


def validate_references(config):
    """Validate tag links independently of construction-time sing-box check."""
    def tags(items):
        result = [item["tag"] for item in items]
        if any(not isinstance(tag, str) or not tag for tag in result):
            raise ValueError("invalid tag")
        if len(set(result)) != len(result):
            raise ValueError("duplicate tag")
        return set(result)

    endpoints = tags(config["endpoints"])
    outbounds = tags(config["outbounds"] + config["endpoints"])
    inbounds = tags(config["inbounds"] + config["endpoints"])
    dns = tags(config["dns"]["servers"])
    rulesets = tags(config["route"]["rule_set"])
    clients = tags(config["http_clients"])

    def reference(value, available, label):
        for tag in value if isinstance(value, list) else [value]:
            if not isinstance(tag, str) or tag not in available:
                raise ValueError(f"dangling {label} reference: {tag!r}")

    def walk(value, dns_rule=False):
        if isinstance(value, list):
            for item in value:
                walk(item, dns_rule)
        elif isinstance(value, dict):
            for key, item in value.items():
                if key in ("detour", "outbound", "outbounds"):
                    reference(item, outbounds, key)
                elif key == "endpoint":
                    reference(item, endpoints, key)
                elif key == "inbound":
                    reference(item, inbounds, key)
                elif key == "rule_set":
                    reference(item, rulesets, key)
                elif key == "preferred_by":
                    reference(item, dns if dns_rule else endpoints, key)
                elif key in ("domain_resolver", "default_domain_resolver"):
                    reference(item["server"] if isinstance(item, dict) else item, dns, key)
                elif key == "http_client" and isinstance(item, str):
                    reference(item, clients, key)
                elif key == "server" and (dns_rule or value.get("action") == "resolve"):
                    reference(item, dns, key)
                if isinstance(item, (dict, list)):
                    walk(item, dns_rule)

    for section in ("endpoints", "inbounds", "outbounds", "http_clients"):
        walk(config[section])
    walk(config["dns"]["servers"])
    walk(config["dns"]["rules"], dns_rule=True)
    walk(config["route"]["rules"])
    walk(config["route"]["rule_set"])
    reference(config["dns"]["final"], dns, "dns.final")
    reference(config["route"]["final"], outbounds, "route.final")
    walk({"default_domain_resolver": config["route"]["default_domain_resolver"]})


class AndroidTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(EXAMPLE.is_file(), f"missing SFA {TARGET_VERSION} profile: {EXAMPLE}")
        self.config = json.loads(EXAMPLE.read_text(encoding="utf-8"))

    def assert_policy(self, config):
        validate_references(config)
        self.assertEqual(config["inbounds"], [TUN], "Android TUN policy")
        self.assertIs(config["dns"]["reverse_mapping"], True, "TUN reverse mapping")
        self.assertEqual(config["endpoints"][0]["state_directory"], "tailscale-android",
                         "app-relative persistent node state")
        self.assertEqual(config["endpoints"][0]["hostname"], "sing-box-android")
        self.assertEqual(config["experimental"]["cache_file"]["path"], "cache-android.db",
                         "app-relative persistent cache")
        self.assertEqual(config["route"]["rules"][1], {
            "inbound": ["tun-in"], "port": [53], "action": "hijack-dns",
        }, "capture DNS only from tun-in")
        self.assertEqual(set(config["endpoints"][0]), {
            "type", "tag", "state_directory", "hostname", "system_interface",
            "accept_routes", "advertise_routes", "advertise_exit_node",
        }, "no endpoint chaining, auth key or exit node")

        # Reuse the unchanged CLI policy oracle only after checking every Android delta.
        normalized = copy.deepcopy(config)
        normalized["inbounds"] = [{
            "type": "mixed", "tag": "local-proxy", "listen": "127.0.0.1",
            "listen_port": 2080, "set_system_proxy": False,
        }]
        del normalized["dns"]["reverse_mapping"]
        normalized["endpoints"][0]["state_directory"] = "./private-state/tailscale"
        normalized["experimental"]["cache_file"]["path"] = "./private-state/cache.db"
        normalized["route"]["rules"][1]["inbound"] = ["local-proxy"]
        cli_policy.ExampleTests().assert_policy(normalized)

    def test_android_policy(self):
        self.assert_policy(self.config)

    def test_all_references(self):
        for path in (EXAMPLE, cli_policy.EXAMPLE):
            with self.subTest(path=path):
                validate_references(json.loads(path.read_text(encoding="utf-8")))

    def test_dangling_references_independently(self):
        paths = [
            ("endpoints", 0, "detour"),
            ("dns", "servers", 0, "endpoint"),
            ("dns", "servers", 2, "detour"),
            ("dns", "rules", 0, "preferred_by"),
            ("dns", "rules", 0, "server"),
            ("dns", "rules", 1, "rules", 0, "rule_set"),
            ("dns", "final"),
            ("route", "rules", 0, "inbound"),
            ("route", "rules", 2, "server"),
            ("route", "rules", 3, "preferred_by"),
            ("route", "rules", 3, "outbound"),
            ("route", "rules", 6, "rule_set"),
            ("route", "rule_set", 0, "http_client"),
            ("route", "rule_set", 1, "http_client"),
            ("route", "default_domain_resolver"),
            ("route", "final"),
            ("http_clients", 0, "detour"),
            ("outbounds", 0, "detour"),
            ("outbounds", 0, "domain_resolver"),
        ]
        for path in paths:
            with self.subTest(path=path):
                invalid = copy.deepcopy(self.config)
                target = invalid
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = "does-not-exist"
                with self.assertRaisesRegex(ValueError, "dangling"):
                    validate_references(invalid)

    def test_duplicate_tags_rejected(self):
        for path in (
            ("endpoints",), ("outbounds",), ("inbounds",), ("http_clients",),
            ("dns", "servers"), ("route", "rule_set"),
        ):
            with self.subTest(path=path):
                invalid = copy.deepcopy(self.config)
                target = invalid
                for key in path:
                    target = target[key]
                target.append(copy.deepcopy(target[0]))
                with self.assertRaisesRegex(ValueError, "duplicate"):
                    validate_references(invalid)

    def test_android_policy_regressions(self):
        changes = [
            (("inbounds", 0, "auto_route"), None),
            (("inbounds", 0, "auto_route"), False),
            (("inbounds", 0, "stack"), "system"),
            (("inbounds", 0, "interface_name"), "tun0"),
            (("inbounds", 0, "strict_route"), True),
            (("inbounds", 0, "auto_redirect"), True),
            (("inbounds", 0, "route_exclude_address"), ["100.64.0.0/10"]),
            (("inbounds", 0, "exclude_package"), ["com.example.app"]),
            (("route", "rules", 1, "inbound"), ["tailnet"]),
            (("route", "final"), "direct"),
            (("route", "rules", 2, "server"), "cn-dns"),
            (("dns", "reverse_mapping"), False),
            (("dns", "strategy"), "ipv6_only"),
            (("endpoints", 0, "state_directory"), "./private-state/tailscale"),
            (("endpoints", 0, "state_directory"), "/data/user/0/app/tailscale"),
            (("endpoints", 0, "accept_routes"), True),
            (("endpoints", 0, "system_interface"), True),
            (("endpoints", 0, "detour"), "shadowsocks"),
            (("endpoints", 0, "auth_key"), "EXAMPLE-NOT-A-KEY"),
            (("experimental", "cache_file", "path"), "./private-state/cache.db"),
            (("experimental", "cache_file", "enabled"), False),
            (("outbounds", 0, "server"), "192.0.2.1"),
            (("outbounds", 0, "domain_resolver"), "cn-dns"),
            (("http_clients", 0, "detour"), "direct"),
        ]
        for path, value in changes:
            with self.subTest(path=path, value=value):
                invalid = copy.deepcopy(self.config)
                target = invalid
                for key in path[:-1]:
                    target = target[key]
                if value is None:
                    del target[path[-1]]
                else:
                    target[path[-1]] = value
                with self.assertRaises(AssertionError):
                    self.assert_policy(invalid)

    def test_route_order_and_dns_guards(self):
        invalids = []
        for index in range(len(self.config["route"]["rules"])):
            invalid = copy.deepcopy(self.config)
            del invalid["route"]["rules"][index]
            invalids.append(invalid)
        invalid = copy.deepcopy(self.config)
        rules = invalid["route"]["rules"]
        rules[4], rules[5] = rules[5], rules[4]
        invalids.append(invalid)
        invalid = copy.deepcopy(self.config)
        invalid["route"]["rules"][4]["ip_cidr"].remove("fd7a:115c:a1e0::/48")
        invalids.append(invalid)
        for index in range(4):
            invalid = copy.deepcopy(self.config)
            del invalid["dns"]["rules"][index]
            invalids.append(invalid)
        for index, invalid in enumerate(invalids):
            with self.subTest(index=index), self.assertRaises(AssertionError):
                self.assert_policy(invalid)

    def check_binary(self, binary, pinned):
        if binary is None:
            self.skipTest("supply --binary / --fork-binary for non-starting binary checks")
        with tempfile.TemporaryDirectory() as directory:
            def run(*args):
                return subprocess.run(
                    [str(binary), *args], cwd=directory, capture_output=True,
                    text=True, timeout=30,
                )

            version = run("version")
            self.assertEqual(version.returncode, 0, version.stdout + version.stderr)
            print(version.stdout, end="")
            if pinned:
                self.assertEqual(version.stdout.splitlines()[0],
                                 f"sing-box version {TARGET_VERSION}")
                self.assertIn(f"Revision: {TARGET_REVISION}", version.stdout)
            tags = next(line[6:] for line in version.stdout.splitlines()
                        if line.startswith("Tags: ")).split(",")
            for tag in ("with_tailscale", "with_gvisor") if pinned else ("with_tailscale",):
                self.assertIn(tag, tags)
            if not pinned:
                print("Fork CLI comparison only, not Android target validation; "
                      f"with_gvisor present: {'with_gvisor' in tags}")
            result = run("check", "-c", str(EXAMPLE))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            print(result.stdout + result.stderr, end="")
            self.assertEqual(list(Path(directory).iterdir()), [], "no runtime state")
            invalid = copy.deepcopy(self.config)
            invalid["inbounds"][0]["not_a_tun_option"] = True
            path = Path(directory) / "invalid.json"
            path.write_text(json.dumps(invalid), encoding="utf-8")
            result = run("check", "-c", str(path))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('unknown field "not_a_tun_option"', result.stdout + result.stderr)

    def test_official_1_14_2_schema(self):
        self.check_binary(BINARY, pinned=True)

    def test_fork_schema(self):
        self.check_binary(FORK_BINARY, pinned=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, help="official native core 1.14.2 binary")
    parser.add_argument("--fork-binary", type=Path, help="optional existing fork CLI binary")
    args = parser.parse_args()
    for binary in (args.binary, args.fork_binary):
        if binary is not None and not binary.is_file():
            parser.error(f"binary does not exist: {binary}")
    BINARY = args.binary.resolve() if args.binary else None
    FORK_BINARY = args.fork_binary.resolve() if args.fork_binary else None
    unittest.main(argv=[__file__], verbosity=2)
