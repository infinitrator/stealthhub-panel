# Production runtime compatibility contract

Verified: **2026-08-29**. This document is the release contract for Infiproxy
`0.1.0-beta.1`, not a recommendation to follow upstream `latest` releases.

## Client baseline

Clash Mi with Mihomo is the primary client ecosystem. The contract is the
embedded Mihomo parser/runtime, not a particular Clash Mi application build.
Every generated client composition below was parsed by the official **Mihomo
v1.19.30** binary with `mihomo -t -f <config>`.

Advanced TLS wrapper fields require Mihomo `v1.19.20` or newer because current
TLS common-field validation also requires SNI/servername from that release.
Infiproxy validates the stricter `v1.19.30` baseline for every composition.

Official evidence:

- [Mihomo v1.19.30 release](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.30)
- [Mihomo VLESS client](https://wiki.metacubex.one/en/config/proxies/vless/)
- [Mihomo common TLS fields](https://wiki.metacubex.one/en/config/proxies/tls/)
- [Mihomo AnyTLS client and Reality exclusion](https://wiki.metacubex.one/en/config/proxies/anytls/)
- [Mihomo Trojan client](https://wiki.metacubex.one/en/config/proxies/trojan/)
- [Mihomo Snell client](https://wiki.metacubex.one/en/config/proxies/snell/)

## Exact server pins

| Runtime | Exact production pin | Release state | Validation | Pin reason |
|---|---|---|---|---|
| Mihomo | `v1.19.30` | stable, not prerelease | `mihomo -t -f` for every advertised listener | Matches the client baseline and provides native modern listeners. |
| Xray-core | `v26.3.27` | stable, not prerelease | `xray run -test -config` | Compatibility fallback for REALITY. Mihomo explicitly excludes Xray `v26.7.11+` compatibility. |
| sing-box | `v1.13.20` | stable, not prerelease | `sing-box check -c` for every advertised inbound | Validated fallback and Shadowsocks 2022 + ShadowTLS runtime; it does not advertise XHTTP. |
| Hysteria | `app/v2.12.2` | stable, not prerelease | isolated loopback startup | Official GitHub release and Hysteria stable update channel both resolved `v2.12.2`. |
| TUIC server | `tuic-server-1.0.0` | stable, not prerelease | isolated loopback startup | Exact official TUIC v5 server release. |

Release sources: [Xray](https://github.com/XTLS/Xray-core/releases/tag/v26.3.27),
[sing-box](https://github.com/SagerNet/sing-box/releases/tag/v1.13.20),
[Hysteria](https://github.com/apernet/hysteria/releases/tag/app/v2.12.2), and
[TUIC](https://github.com/tuic-protocol/tuic/releases/tag/tuic-server-1.0.0).

The module updater resolves the exact tag, rejects draft/prerelease metadata,
verifies the release digest, and never crosses the pin automatically. A newer
installed version is reported as outside the validated contract and is not
automatically downgraded. Runtime automatic updates are **off unless an
operator explicitly enables them**.

## Supported compositions

All new profiles are inserted disabled. `Experimental` means the exact parser
and server config checks pass, but the camouflage mechanism should receive
additional field interoperability testing before broad production rollout.

| Capability | Mihomo client | Preferred server | Fallback | Stability |
|---|---|---|---|---|
| `vless-reality-tcp` | `v1.19.30`; TCP, Vision, XUDP | Mihomo `v1.19.30` | Xray `v26.3.27`; sing-box `v1.13.20` secondary | Stable |
| `vless-reality-xhttp` | `v1.19.30`; XHTTP without Vision | Mihomo `v1.19.30` | Xray `v26.3.27` | Stable |
| `vless-shadowtls-v3` | `v1.19.30`; TCP, no Vision | Mihomo `v1.19.30` | none | Experimental |
| `vless-restls` | `v1.19.30`; TCP, no Vision | Mihomo `v1.19.30` | none | Experimental |
| `vless-jls` | `v1.19.30`; TCP, no Vision | Mihomo `v1.19.30` | none | Experimental |
| `anytls-tls` | `v1.19.30` | Mihomo `v1.19.30` | none | Stable |
| `anytls-shadowtls-v3` | `v1.19.30` | Mihomo `v1.19.30` | none | Stable |
| `anytls-restls` | `v1.19.30` | Mihomo `v1.19.30` | none | Experimental |
| `anytls-jls` | `v1.19.30` | Mihomo `v1.19.30` | none | Experimental |
| `trojan-tls` | `v1.19.30` | Mihomo `v1.19.30` | none | Stable |
| `trojan-shadowtls-v3` | `v1.19.30` | Mihomo `v1.19.30` | none | Stable |
| `trojan-restls` | `v1.19.30` | Mihomo `v1.19.30` | none | Experimental |
| `trojan-jls` | `v1.19.30` | Mihomo `v1.19.30` | none | Experimental |
| `trojan-reality` | `v1.19.30` | Mihomo `v1.19.30` | none | Stable |
| `snell-v5` | `v1.19.30`; UDP over TCP | Mihomo `v1.19.30` | none | Stable |
| `snell-v5-shadowtls-v3` | `v1.19.30` | Mihomo `v1.19.30` | none | Stable |
| `snell-v5-restls` | `v1.19.30` | Mihomo `v1.19.30` | none | Experimental |
| `snell-v5-jls` | `v1.19.30` | Mihomo `v1.19.30` | none | Experimental |
| `shadowsocks2022-shadow-tls` | `v1.19.30` | sing-box `v1.13.20` | none | Stable |
| `hysteria2` | `v1.19.30`; TLS, UDP, optional Salamander | Hysteria `app/v2.12.2` | sing-box `v1.13.20` | Stable |
| `tuic` | `v1.19.30`; TUIC v5 | TUIC server `1.0.0` | sing-box `v1.13.20` | Stable |
| `mieru` | `v1.19.30`; TCP, standard handshake, low multiplexing | Mihomo `v1.19.30` | none | Stable |
| `trusttunnel-h2` | `v1.19.30`; HTTP/2, TLS, per-user auth | Mihomo `v1.19.30` | none | Experimental |
| `shadowquic` | `v1.19.30`; QUIC, intrinsic JLS, 0-RTT off | Mihomo `v1.19.30` | none | Experimental |
| `sudoku-httpmask` | `v1.19.30`; legacy HTTPMask, ChaCha20-Poly1305 | Mihomo `v1.19.30` | none | Experimental |

`any-tls` remains as a disabled legacy compatibility ID backed by sing-box
`v1.13.20`. New profiles use the explicit `anytls-tls` capability.

Server syntax evidence: [VLESS listener](https://wiki.metacubex.one/en/config/inbound/listeners/vless/),
[AnyTLS listener](https://wiki.metacubex.one/en/config/inbound/listeners/anytls/),
[Trojan listener](https://wiki.metacubex.one/en/config/inbound/listeners/trojan/), and
[Snell listener](https://wiki.metacubex.one/en/config/inbound/listeners/snell/),
[TrustTunnel listener](https://wiki.metacubex.one/en/config/inbound/listeners/trusttunnel/),
[ShadowQUIC listener](https://wiki.metacubex.one/en/config/inbound/listeners/shadowquic/), and
[Sudoku listener](https://wiki.metacubex.one/en/config/inbound/listeners/sudoku/).

## Rejected combinations

- **AnyTLS + REALITY** is not exposed. Mihomo explicitly states that the
  combination is unsupported and will remain unsupported.
- **VLESS XHTTP + Vision** is rejected by construction. Vision is emitted only
  for `vless-reality-tcp`; XHTTP clients and server users have no `flow` field.
- **sing-box + XHTTP** is not advertised. The pinned sing-box V2Ray transport
  catalog does not contain XHTTP.
- **Xray REALITY `v26.7.11+`** is outside the contract. Core selection refuses a
  nonmatching version marker; operators must not update this pin blindly.
- **Multiple ShadowTLS/ResTLS/JLS/REALITY wrappers** cannot be represented by a
  protocol adapter. Structural tests require at most one wrapper.
- **TrustTunnel HTTP/3** is not exposed. The current listener-claim model cannot
  safely reserve both TCP and UDP for one profile without an architecture
  change; `trusttunnel-h2` therefore emits TCP/H2 only.
- **MASQUE** is not exposed because no matching verified Mihomo server inbound
  is part of this runtime contract.
- **Hysteria Gecko or server-only camouflage** is not exposed because the
  Mihomo client contract documents Salamander for this profile.

## Validation procedure

Run the networked exact-runtime suite after every deliberate pin or renderer
change:

```bash
bash deploy/tests/runtime-compatibility.sh
```

The harness downloads only exact assets from official GitHub releases, checks
stable release metadata and SHA-256, parses all generated Mihomo client/server
configs, validates Xray and sing-box candidates, and starts Hysteria/TUIC on
`127.0.0.1` with a bounded lifetime. Ordinary Rust tests remain offline and
skip exact-binary tests unless the harness supplies binary paths.

REALITY private keys and TLS private keys remain root/runtime-only. Test keys
and certificates are generated in a temporary directory and deleted; no
private-key content is persisted in SQLite, snapshots, logs, or this document.
