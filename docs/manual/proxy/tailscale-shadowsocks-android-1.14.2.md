# Android SFA 1.14.2: TUN, Shadowsocks and independent Tailscale

Use the separate [Android JSON](../../examples/tailscale-shadowsocks-android-1.14.2.json)
with **sing-box for Android (SFA) 1.14.2** in VPN mode. This is not the
[CLI opt-in mixed-listener example](tailscale-shadowsocks.md): it captures
traffic from apps included in the Android VPN. Embedded Tailscale handles
tailnet destinations, LAN/private and mainland-China matches go direct, and
overseas/unmatched traffic uses an IPv6 Shadowsocks server without direct
fallback. No new protocol implementation or app/core source patch is needed
for this configuration.

## Version pins and compatibility boundary

| Component | Pinned provenance |
| --- | --- |
| Core | [v1.14.2](https://github.com/SagerNet/sing-box/releases/tag/v1.14.2), commit [`af6e64c3b69e6132ebaee0e1a3d24e93903f6709`](https://github.com/SagerNet/sing-box/tree/af6e64c3b69e6132ebaee0e1a3d24e93903f6709) |
| Android app | Core's [`clients/android` submodule](https://github.com/SagerNet/sing-box/tree/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/clients/android), SagerNet/sing-box-for-android commit [`fc21909df7a3f0fc9435f3866fb6a4960711aa5f`](https://github.com/SagerNet/sing-box-for-android/tree/fc21909df7a3f0fc9435f3866fb6a4960711aa5f) |
| Official normal arm64 APK | `SFA-1.14.2-arm64-v8a.apk`, SHA-256 `4f97d009048a714c14313d582e714b0cd94503333f85bb733aad9aa13b5023c5` |
| Official Linux amd64 schema-check archive | `sing-box-1.14.2-linux-amd64.tar.gz`, SHA-256 `a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6` |

The official normal arm64 APK was independently inspected with `with_tailscale`
and `with_gvisor`; release metadata corroborates its digest. The downloaded
Linux archive was checked against both GitHub's asset digest and the pin above.
It reports core `1.14.2`, revision `af6e64c3b69e6132ebaee0e1a3d24e93903f6709`,
`go1.26.8 linux/amd64`, CGO disabled, with both required tags. Linux
construction/schema checks are **not Android runtime tests**.

The shared `http_clients`, rule-set `http_client`, Tailscale DNS
`accept_search_domain` and DNS `preferred_by` fields are supported in core 1.14;
route `preferred_by` is supported since 1.13. They are **not fork-only or
1.15-only fields**. `stack: mixed` needs gVisor for its UDP side as well as
the system TCP stack.

The fork's current `build-2-1` release contains desktop CLI archives, **not
an APK**. A custom fork APK is being developed separately; this page does not
claim one has been built, signed, released or installed. Import into official
SFA 1.14.2, or a separately verified custom SFA build whose core version and
feature tags match this target. Do not assume a custom APK can update an
official installation: package identity and signing identity matter.

## Private setup and local import

1. Copy the JSON to a private local file. Replace bare `2001:db8::1` with your
   authorized server's reachable IPv6 literal (no brackets, scope or port
   suffix). It is an **RFC 3849 documentation-only address**, not a working
   server. Replace the separate port `8388`, cipher
   `chacha20-ietf-poly1305` and public test password
   `INSECURE-EXAMPLE-ONLY-REPLACE-ME` with the server's actual settings. These
   values are independent placeholders, not inferred user credentials; a
   2022 cipher needs a correctly sized base64 key. Never commit the private copy.
2. In SFA's profiles screen, add a **Local** profile using **Import** and choose
   that JSON with the Android file picker. Give it a distinct name such as
   `Tailscale + Shadowsocks (1.14.2)` and select it. Use VPN mode, not a
   proxy-only mode. Keep per-app exclusions empty initially: excluded apps
   bypass **all** this profile's routing and DNS policy.
3. Only when intentionally deploying, start the selected profile and approve
   Android's VPN consent prompt. Android has one active VPN slot per
   user/profile: the standalone Tailscale VPN cannot run simultaneously with
   SFA's VPN. Embedded Tailscale shares SFA's tunnel; it is not a second VPN.
4. On an intentional first runtime start, obtain the Tailscale enrollment URL
   from SFA's logs and complete login/device approval. No `auth_key` is supplied.
   Tailnet ACLs/grants must allow the intended peers and ports. Protect logs
   containing enrollment material; enrollment and phone operation were not
   performed as part of these non-starting checks.

`state_directory: tailscale-android` and `cache_file.path: cache-android.db`
are **app-working-directory-relative**, not relative to the imported JSON.
Pinned [libbox `config.go`](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/experimental/libbox/config.go)
passes `sWorkingPath` to the file manager; pinned
[`Application.kt`](https://github.com/SagerNet/sing-box-for-android/blob/fc21909df7a3f0fc9435f3866fb6a4960711aa5f/app/src/main/java/io/nekohasekai/sfa/Application.kt)
supplies `getExternalFilesDir(null)` as `workingPath` (distinct from `filesDir`
as `basePath`). Do not copy the CLI's `./private-state` parent or hardcode
`/data/user/0/...`. App-specific external storage is not a guarantee of
encrypted secret storage; protect node keys and backups. Uninstalling or clearing
app data removes state, requiring enrollment again. Each device/instance needs
separate state; never share node state. Multiple independent profiles in the
same app also need distinct state/cache names rather than assuming per-profile
path isolation.

## TUN policy and DNS limits

The only inbound is `tun-in`, with `auto_route: true`, `stack: mixed`, and
example addresses `172.19.0.1/30` and `fdfe:dcba:9876::1/126`. Check for
collisions with your LAN, overlays and other local routes before deployment;
choose non-overlapping tunnel addresses if needed. These are tunnel-local
addresses, not server or tailnet addresses. No mixed listener, fixed
`interface_name`, `strict_route`, Linux `auto_redirect`, OS route-table
settings or blanket app exclusion is added.

Do **not** blanket-exclude tailnet ranges from TUN: captured tailnet traffic
must reach the embedded endpoint. **Keep `route.auto_detect_interface: true`.**
In the pinned core, this boolean defaults to false; the
[`NetworkManager`](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/route/network.go)
passes it to the
[`default dialer`'s callback gate](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/common/dialer/default.go#L105-L130).
With SFA's platform interface, enabling it installs `ProtectFunc()` on both
the ordinary TCP dialer and UDP listener. The libbox platform callback reaches
SFA's pinned
[`VPNService.kt`](https://github.com/SagerNet/sing-box-for-android/blob/fc21909df7a3f0fc9435f3866fb6a4960711aa5f/app/src/main/java/io/nekohasekai/sfa/bg/VPNService.kt)
`protect(fd)` for outbound socket loop avoidance. Without this flag, ordinary
Shadowsocks, direct and DNS sockets can be captured back into the VPN;
Tailscale's separate netns protection does not protect those sockets.
This is Android's socket-protection callback, **not a fixed desktop interface
binding**: do not add `default_interface` or `bind_interface`, or bypass routes
for all tailnet destinations. The core's
[`C.IsLinux` constant includes Android](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/constant/os.go#L23),
so the route option's Linux platform gate does not exclude SFA.

| Order | Match/action |
| --- | --- |
| 1 | Reject new connections arriving from `tailnet` (not replies to locally initiated connections) |
| 2 | `tun-in`, port 53: `hijack-dns` |
| 3 | `resolve` with no server override, preserving DNS policy |
| 4 | `preferred_by: tailnet`: route to `tailnet` |
| 5 | `100.64.0.0/10` and `fd7a:115c:a1e0::/48`: route to `tailnet` |
| 6 | `ip_is_private`: direct |
| 7 | `geosite-cn`: direct |
| 8 | `geoip-cn`: direct |
| Final | `shadowsocks`, with no direct fallback |

Tailnet IPv6 is inside ULA and must precede private-direct. The shared
`100.64.0.0/10` range can collide with ISP/CGNAT/overlay addresses. No accepted
or advertised subnet routes, exit node, or system Tailscale interface is
enabled. `system_interface: false` and `accept_routes: false` stay explicit.
Neither Tailscale nor Shadowsocks detours through the other.

`dns.reverse_mapping: true` associates observed DNS replies with names to help
TUN domain rules. No sniff action is included, keeping the patch small.
Neither reverse mapping nor optional sniffing can guarantee domain recovery.
DNS interception covers only port-53 traffic from VPN-included apps; app
DoH/DoT, cached names and IP-only connections can defeat domain rules. IP
classification still applies. This is not a universal DNS leak guard or a
device-wide kill switch.

DNS policy is unchanged from the CLI example: dynamic tailnet preference first;
then `ts.net` and single-label names (including a trailing dot) to tailnet-only
DNS; then fail-closed `local`, `lan`, `home.arpa`, `internal`, `in-addr.arpa`,
`ip6.arpa` guards; CN domains to `223.5.5.5`; final DoH to `1.1.1.1` through
Shadowsocks. Short MagicDNS expansion is enabled, tailnet default resolvers
are not accepted, and missing private/tailnet names never retry publicly.
Unknown LAN names and PTR queries fail unless the earlier dynamic tailnet
rule handles them. Known LAN/corporate zones require explicit exceptions
before the guards; see the shared
[DNS policy and LAN setup](tailscale-shadowsocks.md#dns-priority-and-private-name-guards).

`prefer_ipv4` remains **dual-stack target DNS**, not IPv6-only destinations.
The literal Shadowsocks server needs no `domain_resolver`. Its transport
requires working underlying network IPv6; there is no automatic IPv4 backup.
IPv4 targets and the `1.1.1.1` DoH server require IPv4 egress on the Shadowsocks
server. UDP/QUIC also need server and network support. Direct Tailscale
control/DERP uses the default `cn-dns` resolver; reachability from China is
unverified and is not supplied by a working Shadowsocks route.

Both CN SRS downloads use `http_clients.rule-download` via Shadowsocks with
daily checks and persistent cache. First start needs usable cached rules,
vetted offline seeds or a working proxy download; there is no direct or
empty-rule fallback. For seeds, use `initial_path` pointing to files accessible
to SFA in its working directory, not the import file's folder or a desktop path.
See [cache/bootstrap behavior](tailscale-shadowsocks.md#maintained-rule-sets-bootstrap-and-cache).
CN domain/IP lists remain heuristics: CN domains override IP geography,
and **any** matching resolved IP can select a route for the whole connection.
Neither geography nor mixed DNS answers form a security boundary.

## Non-starting checks and upgrade-friendly patch layer

From the repository root, using the digest-verified native **official 1.14.2**
binary (not an APK executable):

```sh
/path/to/sing-box-1.14.2 version
/path/to/sing-box-1.14.2 check -c docs/examples/tailscale-shadowsocks-android-1.14.2.json
python3 .github/check-tailscale-shadowsocks-android.py --binary /path/to/sing-box-1.14.2
python3 .github/check-tailscale-shadowsocks.py --binary /path/to/sing-box-1.14.2
```

Optionally add `--fork-binary /path/to/fork/sing-box` to the Android checker
and rerun the unchanged CLI checker against that binary. Without binary
arguments the corresponding binary tests are explicitly skipped.
For **pinned-source structural callback-path coverage**, use a Git repository
containing both pinned commits (no checkout, build, APK or device execution):

```sh
git -C /path/to/source-repository fetch --no-tags --recurse-submodules=no \
  https://github.com/SagerNet/sing-box.git af6e64c3b69e6132ebaee0e1a3d24e93903f6709
git -C /path/to/source-repository fetch --no-tags --recurse-submodules=no \
  https://github.com/SagerNet/sing-box-for-android.git fc21909df7a3f0fc9435f3866fb6a4960711aa5f
python3 .github/check-tailscale-shadowsocks-android.py \
  --binary /path/to/sing-box-1.14.2 --source-repository /path/to/source-repository
```

The source test reads the pinned Git objects, not working-tree files. It checks
the core/app submodule pin, boolean option and Android/Linux gate, the flag-gated
TCP/UDP control installation, `ProtectFunc`, libbox forwarding and SFA's
`protect(fd)` callback. It is skipped explicitly without `--source-repository`;
missing objects or mismatched source fail rather than silently skip.
This is structural evidence, not a compiled unit test or proof of protection
on a running phone. Native `sing-box check` alone cannot verify this callback.

The existing fork CLI `dev-4a39ff496a24` (revision
`4a39ff496a245e1864cdbe608cab09f5d17df9bc`, `go1.25.5 linux/amd64`, CGO disabled)
passes construction checks but **does not contain `with_gvisor`**; it is not
evidence of an Android mixed-stack-capable build. It also warns that `stack`
is deprecated in 1.15, reinforcing why this profile targets 1.14.2 rather than
an arbitrary newer core.

The independent Android tests pin the official core version/revision and require
`with_tailscale` and `with_gvisor`; the optional fork comparison only checks
`with_tailscale` and schema, reporting its gVisor availability. They enforce Android-specific fields before
reusing the unchanged CLI policy assertions for shared behavior. Static tag
checks cover endpoint, DNS, route, rule-set, HTTP-client and detour references
in both examples, including nested rules. **`sing-box check` accepts a dangling
rule-set HTTP-client tag** because transport lookup is deferred until startup;
the independent negative-reference tests reject it. Other regressions cover
missing/false/non-boolean `route.auto_detect_interface`, missing `auto_route`,
wrong DNS hijack inbound, tailnet IPv6 order, final direct,
IPv4 proxy transport, state/cache paths and private DNS guards. These are
documentation fixture tests: they deliberately require the restricted example
IPv6 address and public password, not users' substituted production values.
Only the verified `auto_detect_interface: true` route delta is removed before
the unchanged CLI oracle runs; arbitrary extra route keys and fixed desktop
interface binding remain rejected.

Keep this layer limited to the separate JSON, checker, guide and navigation;
the CLI JSON and its 22 tests remain unchanged. Core and Android source pins
are separate. On upgrades, review both pins and release digests, apply the
configuration/docs/tests patch after the existing CLI patch, rerun both
checkers, and report conflicts rather than silently dropping policy. Maintain
any custom APK branding/build changes as separately reviewable patches.
The separate APK build work must record its own toolchains, full feature tags,
patch order and reproducible commands; this configuration layer is not an
APK build recipe. Keep signing keys private and retain a stable custom signing
identity for future updates.

No workflow files are changed and these checks are not newly wired into
Actions. No APK build, installation, service/VPN start, login, live DNS,
TCP/UDP/QUIC, ACL, routing or connectivity validation is claimed here.
