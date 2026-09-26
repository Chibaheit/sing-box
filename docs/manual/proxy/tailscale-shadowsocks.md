# China direct, overseas Shadowsocks, independent Tailscale

Use [this combined JSON example](../../examples/tailscale-shadowsocks.json) with
one sing-box CLI binary. Tailnet destinations use embedded Tailscale, ordinary
LAN/private destinations and mainland China domain/IP matches go `direct`, and
**overseas/unmatched destinations use Shadowsocks**. Tailscale and Shadowsocks
are independent: neither protocol outbound has a `detour` through the other.
Only encrypted public DNS and rule downloads explicitly detour through Shadowsocks.

This is an **application opt-in proxy**, not a system-wide VPN, a geography
oracle, or a firewall/privacy kill switch. The unauthenticated mixed HTTP/SOCKS
listener stays on `127.0.0.1:2080`, with `set_system_proxy: false`. Other local
processes/users can use it; do not expose it on a LAN or wildcard address.
There is no system TUN, system DNS capture, route/firewall change, accepted
subnet route, exit node, or advertised route.

## Binary and non-starting validation

Shadowsocks is registered unconditionally. Tailscale requires `with_tailscale`,
already included in `release/DEFAULT_BUILD_TAGS_OTHERS` and the fork's existing
[Build Release workflow](https://github.com/Chibaheit/sing-box/blob/testing/.github/workflows/release.yml).
No second client binary or new protocol implementation is needed.

The fork's `build-2-1` release provides CLI archives for Linux, macOS, and Windows,
each for amd64 and arm64. Choose the matching archive and verify it against
the release's `SHA256SUMS`. These are not mobile/GUI packages. Use this fork's
schema: the example uses `http_clients`, rule-set `http_client`, and Tailscale
DNS `accept_search_domain`, not deprecated `download_detour`.

From the repository root, with a verified native binary:

```sh
/path/to/sing-box version
/path/to/sing-box check -c docs/examples/tailscale-shadowsocks.json
python3 .github/check-tailscale-shadowsocks.py --binary /path/to/sing-box
```

`version` must report `with_tailscale`. `check` constructs and closes the
configuration without starting services, logging in, resolving placeholders,
downloading remote rules, or creating runtime state. Therefore it validates
schema and construction-time references, **not rule contents or connectivity**. The Python
standard-library checks assert exact policy/order, private DNS guards,
nonrecursive proxy bootstrap, proxy-only rule downloads, and persistent cache.
Negative mutations include direct-final, missing tailnet IPv6, private-before-
tailnet order, missing resolve/ingress rejection, and DNS/download bypasses.
The binary tests also require unknown schema fields to fail.
Omit `--binary` for policy-only checks; binary checks are explicitly skipped.

Actions integration remains deferred to a separate optional patch. No workflow
is changed here; the existing six-platform release matrix remains unchanged.

## Replace placeholders and provide private persistent storage

Copy the JSON outside the checkout into a private configuration directory.
Replace `proxy.example`, port `8388`, cipher, and password with your authorized
Shadowsocks settings. `.example` is reserved and is not a working server.
`INSECURE-EXAMPLE-ONLY-REPLACE-ME` is a format-valid, public, test-only password
for `chacha20-ietf-poly1305`, **not a credential to deploy**. A 2022 cipher
instead needs its correctly sized base64 key.

The strongest bootstrap option is your real Shadowsocks server's IP address.
If you retain a hostname, its explicit `domain_resolver: cn-dns` uses domestic
UDP DNS directly, avoiding encrypted DNS -> Shadowsocks -> encrypted DNS
recursion. The route's `default_domain_resolver: cn-dns` is also explicit, but
does not replace the pre-routing `resolve` action or the DNS rules.

Set both `endpoints[0].state_directory` and `experimental.cache_file.path` to
private, persistent, writable deployment paths **outside the checkout**.
The example's `./private-state/tailscale` and `./private-state/cache.db` are
relative to the process working directory, not the JSON file's directory.
Create the private parent directory and use absolute paths to avoid accidental
new nodes/cache files. Restrict access to the configuration and state to the
account running sing-box. On Windows use native paths, escaping backslashes
in JSON, and `sing-box.exe`. Each device/instance needs its own state.

One binary and one JSON still require Tailscale enrollment, persistent identity,
and cached rule data. No `auth_key` is included. On an intentional first runtime
start, use the login URL logged by the endpoint and complete device approval.
Alternatively, privately provision an auth key per the
[endpoint documentation](../../configuration/endpoint/tailscale.md); never
commit it. Protect node state as credentials, retain it across restarts, and
never share it between devices or concurrent instances.

Tailnet ACLs/grants must permit the chosen peers/ports. `system_interface: false`
and `accept_routes: false` remain set; no exit node or advertisements are enabled.
Tailscale control/DERP connectivity remains direct and independent of Shadowsocks.
Its reachability from China is **unverified**; a working Shadowsocks server does
not establish that Tailscale login/control/DERP will work.

## Route order and classification limits

For traffic entering sing-box, the first terminal matching route wins:

| Priority | Match/action | Result |
| --- | --- | --- |
| 1 | Inbound `tailnet` | Reject new inbound peer connections; this node is not an unrestricted proxy for peers |
| 2 | Inbound `local-proxy`, destination port 53 | `hijack-dns` to this configuration's DNS policy |
| 3 | `resolve`, without a server override | Resolve submitted hostnames using `dns.rules` before IP matching |
| 4 | `preferred_by: tailnet` | Tailnet-preferred destinations use Tailscale |
| 5 | `100.64.0.0/10`, `fd7a:115c:a1e0::/48` | Tailscale |
| 6 | `ip_is_private: true` | Direct for ordinary private/non-public destinations |
| 7 | `geosite-cn` | Mainland China domain-list match goes direct |
| 8 | `geoip-cn` | Mainland China registered-country IP-list match goes direct |
| Final | Anything unmatched | Shadowsocks |

The tailnet IPv6 prefix is inside ULA, so it must precede `ip_is_private`.
Do not send all RFC1918 ranges through Tailscale. Ordinary LAN IPs go direct;
Tailscale subnet-router access requires a separate deliberate route/ACL design.
The ingress rejection applies to new connections from peers, not replies to
outbound connections initiated here.

`100.64.0.0/10` is shared address space: ISPs, CGNAT, and other overlays can
overlap it. All submitted addresses in that range go to Tailscale here.
If needed, replace broad prefixes with actual peer `/32` and `/128` routes or
carefully ordered exceptions before the broad-prefix rule.

CN lists are **heuristics, not precise physical geography, censorship status,
or a firewall boundary**. After the private/tailnet protections, CN domains
override IP geography: a CN-listed domain hosted overseas still goes direct.
An unlisted domain resolving to a CN IP also goes direct. HK/MO/TW are not
automatically mainland China; this policy does not merge their country lists.
Individual domains can still match the CN domain list.

IP rules use **ANY matching resolved address**, not an all-addresses test or
per-address routing. If an answer contains both CN and overseas IPs, a CN match
routes the whole connection direct. Likewise mixed private/public or tailnet/
public answers can select the earlier private/tailnet route for the whole
connection. `prefer_ipv4` prefers IPv4; it does not disable IPv6 or remove it
from matching.

Final Shadowsocks is a default route, **not failover**. Failure of a selected
proxy/tailnet route does not retry through direct. DNS resolution failure also
fails the connection rather than skipping resolution to try a different path.

For explicit Internet exceptions, insert domain routing overrides **after
the tailnet/private protections and before both CN rules**. For example,
`{"domain":["service.example"],"action":"route","outbound":"shadowsocks"}`
forces that replaced hostname to the proxy even if CN-listed. Add the matching
DNS override to `external-dns` before the `geosite-cn` DNS rule, but after the
private-name protections. A deliberate direct exception should similarly use
an appropriate direct resolver. These overrides cannot undo earlier private/
tailnet matches; assess mixed DNS answers rather than treating domain overrides
as security isolation.

## DNS priority and private-name guards

DNS providers are **illustrative choices, not known user preferences**:
`cn-dns` is UDP `223.5.5.5:53`; `external-dns` is DoH to `1.1.1.1:443/dns-query`
with TLS name `cloudflare-dns.com`, through Shadowsocks. Domestic UDP is not
poisoning-resistant or confidential. DoH uses an IP transport address to avoid
another public hostname bootstrap. Neither provider's live availability was
tested.

DNS rules run in this order:

1. Dynamic `preferred_by: tailnet-dns` sends names preferred by the embedded
   endpoint's MagicDNS/split-DNS configuration to `tailnet-dns`.
2. All `ts.net` suffix names and single-label names (optionally ending in a dot)
   go only to `tailnet-dns`. These broad fail-closed guards prevent public retry
   before a netmap is available; they do not assert that every such name is a
   real tailnet name.
3. Remaining `local`, `lan`, `home.arpa`, `internal`, `in-addr.arpa`, and
   `ip6.arpa` suffix queries are rejected.
4. `geosite-cn` queries use `cn-dns`; all other queries use `external-dns`.

`accept_search_domain: true` permits short MagicDNS names to expand against
actual Tailscale search domains. `accept_default_resolvers: false` prevents
fallback to tailnet-wide default resolvers for unrelated names. No invented
tailnet suffix is required. Unknown short names remain tailnet-only and fail
without public retry. Unknown LAN names and PTR lookups are deliberately blocked
unless the earlier dynamic tailnet rule handles them.

Your real LAN zones/resolver and custom corporate suffixes are unknown.
To enable a known LAN zone, add your actual reachable LAN DNS server and a
matching DNS rule **after dynamic tailnet preference but before the guards**.
For example, replace both placeholders in
`{"type":"udp","tag":"lan-dns","server":"192.168.1.1","server_port":53}`
and `{"domain_suffix":["home.arpa"],"action":"route","server":"lan-dns"}` with
your real resolver and zone. This enables only that zone, not universal LAN
discovery. If needed, add exact known LAN short names (`domain`) ahead of the
short-name guard and only your actual reverse zones ahead of the PTR guard.
Configure other corporate/private suffixes explicitly. This finite guard list
cannot promise universal private-name leak prevention.

## Maintained rule sets, bootstrap, and cache

The exact binary SRS URLs are:

- <https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs>
- <https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs>

[sing-geosite's generator](https://github.com/SagerNet/sing-geosite/blob/main/main.go)
derives its CN domain list from v2fly domain-list-community data, merging CN
categories and the `cn` suffix. Its
[release schedule](https://github.com/SagerNet/sing-geosite/blob/main/.github/workflows/release.yaml)
is daily.
[sing-geoip's generator](https://github.com/SagerNet/sing-geoip/blob/main/main.go)
uses `RegisteredCountry.IsoCode` from Dreamacro/maxmind-geoip's `Country.mmdb`,
not a real-time location test. Its
[release schedule](https://github.com/SagerNet/sing-geoip/blob/main/.github/workflows/release.yaml)
is monthly. The CN IP set includes IPv4 and IPv6.

Both URLs returned HTTP 200 with SRS version 1 during verification. They are
maintained moving branches, not pinned snapshots or freshness guarantees.
This configuration checks both every `1d`, irrespective of upstream cadence.
Trust in the publishers and HTTPS distribution remains necessary.

Both remote entries explicitly select the shared `rule-download` HTTP client,
which detours through Shadowsocks. **The first download needs a working proxy**.
There is no direct-download or empty-rule fallback: without usable cached rules
or an offline seed, initial download failure aborts startup. Keep
`experimental.cache_file.enabled: true` and the private writable cache path.
Valid cached rules are reused across restarts; background update failures are
logged and leave loaded rules in use, potentially stale. A cache from a changed
URL is not silently trusted.

For an offline first start, obtain and vet both SRS files separately, store them
outside the checkout, and add `initial_path` to each remote entry, pointing to
its corresponding private local file. A valid seed is read only when no usable
cache exists; updates still run through the same proxy immediately after start.
Missing/invalid seeds warn and fall back to the initial **proxy** download, not
direct or empty rules. See [rule-set fields](../../configuration/rule-set/index.md).
Decode a downloaded file without starting services using:

```sh
/path/to/sing-box rule-set decompile /private/path/geosite-cn.srs -o /private/path/geosite-cn.json
/path/to/sing-box rule-set decompile /private/path/geoip-cn.srs -o /private/path/geoip-cn.json
```

## Application opt-in and limits

Configure only intended applications to use HTTP or SOCKS at `127.0.0.1:2080`.
After deliberate setup/start, these are opt-in examples, not validation commands:

```sh
curl --proxy http://127.0.0.1:2080 https://www.example.com/
curl --proxy socks5h://127.0.0.1:2080 https://www.example.com/
```

HTTP CONNECT and `socks5h` preserve the destination hostname for domain policy.
Locally resolved names submitted as IPs bypass domain rules (IP policy still
applies); browser DoH or application DNS outside the proxy bypasses this DNS
policy. Port-53 hijacking covers only DNS traffic submitted through
`local-proxy`, not system DNS or all encrypted DNS. Applications not opting in
remain unaffected. HTTP proxying does not carry arbitrary UDP/ICMP; SOCKS UDP
and QUIC depend on client/protocol support and are not guaranteed here.

Non-starting checks do not establish login, ACLs, reachability, DNS answers,
UDP forwarding, cross-platform runtime behavior, or production readiness.
