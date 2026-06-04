# itox

`github.com/opd-ai/itox` implements **I2P-over-Tox** transport sessions — a supplemental friend-to-friend transport for go-i2p routers.

## What This Is

- ✅ A valid `lib/transport.Transport` that passes `var _ transport.Transport = (*ToxTransport)(nil)`
- ✅ Registered in `TransportMuxer` via `transport.Mux(ntcp2, ssu2, itoxTransport)`
- ✅ `Compatible(ri)` returns `true` only for RouterInfos registered in `PeerRegistry` whose mapped Tox key is a current friend
- ✅ `Compatible(ri)` returns `false` for all standard I2P RouterInfos — the muxer falls through to NTCP2/SSU2 normally
- ✅ Sessions exist only between operators who are mutual Tox friends
- ✅ The Tox friend list is the sole ACL

## What This Is NOT

- ❌ Not a replacement for NTCP2 or SSU2 — supplemental only
- ❌ Not selected by the muxer for peers not registered as Tox friends
- ❌ Does not add, read, or require any fields in RouterInfo
- ❌ Not published to the netDB — no `StoreRouterInfo` calls, ever
- ❌ No peer discovery — if you haven't registered the peer, it doesn't exist to this transport

## Muxer Integration Example

```go
// Build itox transport
itoxCfg := itox.DefaultConfig(toxClient, secretKey, localRI)
itoxTransport, err := itox.NewToxTransport(itoxCfg, noiseTransport)

// Register a Tox friend's RouterInfo received out-of-band (e.g. via Tox chat)
err = itoxTransport.Registry().Register(friendRouterInfo, friendToxPubKey)

// Add to muxer alongside standard transports — order determines preference.
// Place itox last so NTCP2/SSU2 are preferred for peers reachable via both.
mux := transport.Mux(ntcp2Transport, ssu2Transport, itoxTransport)

// Everything else is unchanged. The muxer calls Compatible() on each transport
// for every GetSession attempt. For peers not in PeerRegistry, itox returns
// false and the muxer uses NTCP2 or SSU2 normally. For registered Tox friends,
// itox returns true and the muxer uses the Tox channel.
```

## Security Model

- Friend-list ACL gate on every inbound and outbound session path
- Messages carried through toxcore Noise-IK channels only
- Non-friends are silently rejected with debug-level logging only
- No RouterInfo netDB publication performed by this package
- RouterInfo shared out-of-band; PeerRegistry maps identity hash to Tox pubkey locally
