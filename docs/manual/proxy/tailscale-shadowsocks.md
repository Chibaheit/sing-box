# Independent Tailscale and Shadowsocks routing

Use [this combined JSON example](../../examples/tailscale-shadowsocks.json) with
one sing-box CLI binary: tailnet IP destinations use the Tailscale endpoint,
one selected Internet domain uses Shadowsocks, and unmatched destinations use
the explicit `direct` outbound. Neither protocol is chained through the other;
there is no `detour`, exit node, advertised subnet, or system TUN.

This is an **application opt-in proxy**, not a system-wide VPN or a privacy
kill switch. The mixed HTTP/SOCKS listener is only `127.0.0.1:2080` and does not
change the system proxy, routes, firewall, or DNS settings. It has no proxy
authentication: other processes/users on the same machine can use it. Do not
expose it on a LAN or wildcard address.

## Binary and offline validation

Shadowsocks is registered unconditionally. Tailscale requires `with_tailscale`,
already included in `release/DEFAULT_BUILD_TAGS_OTHERS` and the fork's existing
[Build Release workflow](https://github.com/Chibaheit/sing-box/blob/testing/.github/workflows/release.yml).
No second client binary or new protocol implementation is needed.

The fork's `build-2-1` release provides CLI archives for Linux, macOS, and Windows,
each for amd64 and arm64. Choose the matching archive and verify it against
the release's `SHA256SUMS` before use. These are not mobile/GUI packages; use a
version with the endpoint schema documented in this checkout.

From the repository root, with a verified native binary:

```sh
/path/to/sing-box version
/path/to/sing-box check -c docs/examples/tailscale-shadowsocks.json
python3 .github/check-tailscale-shadowsocks.py --binary /path/to/sing-box
```

`version` must report `with_tailscale`. `check` constructs and closes the
configuration without starting the proxy or Tailscale, logging in, resolving the
placeholder hosts, or creating node state. The Python standard-library checks
assert the policy, reject regressions (including missing IPv6, wrong rule order,
and a proxy default), and run the actual binary's version/schema checks.
Omit `--binary` for policy-only checks; binary checks are then explicitly skipped.
Automated CI integration for this example is deferred to a separate patch;
the checks above are not wired into Actions in this change. The existing release
build uses Go from `go.mod`, the combined release tags and `release/LDFLAGS`.
Its six-platform matrix remains unchanged.

## Replace placeholders before runtime use

Copy the JSON outside the checkout into a private configuration directory.
Replace `proxy.example`, port `8388`, cipher, and password with your authorized
Shadowsocks server settings. The included
`INSECURE-EXAMPLE-ONLY-REPLACE-ME` is a format-valid, public, test-only password
for `chacha20-ietf-poly1305`, **not a credential to deploy**. If your server uses
a 2022 cipher, use its correctly sized base64 key instead. Replace
`selected.example` with the exact Internet hostname you intend to proxy.
Both `.example` names are reserved placeholders, not working services.

Set `state_directory` to a private, persistent, writable directory outside the
repository and choose an appropriate `hostname`. The example's relative
`./tailscale-state` is resolved against the process working directory (not the
JSON file's directory); use an absolute path to avoid accidental new nodes.
On Windows use a native path, escaping backslashes in JSON, and `sing-box.exe`.
The same explicit-proxy topology works on the six CLI targets without
platform-specific TUN privileges, but each device needs its own node state.

The single binary and JSON do **not** replace Tailscale enrollment or persistent
identity. No Tailscale `auth_key` is included. On an intentional first runtime
start, authenticate using the login URL logged by the endpoint, and complete
any tailnet device approval. Alternatively, provision an auth key privately
according to the [endpoint documentation](../../configuration/endpoint/tailscale.md);
never commit it. Protect the state directory as credentials, retain it across
restarts, and do not share/copy it between devices or simultaneous instances.
Existing state is reused; an auth key is not needed on every restart.
Tailnet ACLs/grants must permit this node to reach the chosen peers and ports.
This configuration does not bypass ACLs, accept subnet routes, advertise routes,
or select/advertise an exit node.

## Exact routing and DNS behavior

For connections submitted to this listener, the first matching route wins:

| Destination presented to sing-box | Route |
| --- | --- |
| IP in `100.64.0.0/10` or `fd7a:115c:a1e0::/48` | Tailscale endpoint, before the Internet rule |
| Exact domain `selected.example` (after replacement) | Shadowsocks server |
| Anything else | `direct`, using the host's normal network |

`direct` is the **unmatched-route fallback**, not failover. A selected Shadowsocks
connection or tailnet connection that fails is not retried through `direct`.
The domain rule is exact: subdomains and connections submitted only as public
IP addresses do not match it. No sniffing or pre-routing DNS resolution is
enabled. An application that resolves a hostname before proxying can therefore
bypass the selected-domain rule. Use HTTP CONNECT with the hostname or SOCKS5
remote-name resolution (for example, an application's `socks5h` setting) when
domain selection is required.

`100.64.0.0/10` is shared address space, not exclusively Tailscale: ISPs, CGNAT,
and other overlays can overlap it. In this example **all** submitted addresses
in that range go to Tailscale, so overlapping non-tailnet services may become
unreachable through this proxy. If needed, replace the broad prefixes with
your actual peer `/32` and `/128` routes or carefully ordered exceptions.
Do not treat all RFC1918 space (`10/8`, `172.16/12`, `192.168/16`) as tailnet
destinations. Those addresses go direct here; access through a Tailscale subnet
router requires a separate, deliberate route/ACL design.

This example intentionally supports **tailnet IPs, not MagicDNS names**.
Use a peer's actual Tailscale IPv4/IPv6 address in the application. The local
DNS server uses the machine's existing resolver for the Shadowsocks server,
Tailscale control connectivity, and direct domain requests. DNS is not forced
through Shadowsocks; selected domain requests are passed to the Shadowsocks
server for resolution. There is no DNS hijack or DNS-leak prevention guarantee.

Optional MagicDNS needs a separately validated
[Tailscale DNS server](../../configuration/dns/server/tailscale.md) and matching
DNS/routing policy. Obtain your **actual tailnet suffix** from Tailscale's
admin DNS settings; do not assume a sample suffix, every `*.ts.net` name, or a
short hostname belongs to your tailnet. Merely adding a DNS server does not make
this IP-only routing policy handle unresolved tailnet names.

Configure only the intended applications to use HTTP or SOCKS at
`127.0.0.1:2080`; applications that do not opt in remain unaffected. HTTP proxying
does not carry arbitrary UDP/ICMP, and SOCKS UDP depends on application support.
The offline checks do not test login, live reachability, ACLs, UDP forwarding,
DNS answers, or cross-platform runtime behavior.
