// Package itox implements I2P-over-Tox transport sessions.
//
// itox is registered as an additional transport inside the existing go-i2p TransportMuxer
// alongside NTCP2 and SSU2:
//
//	mux := transport.Mux(ntcp2Transport, ssu2Transport, itoxTransport)
//
// TransportMuxer.findCompatibleSession iterates all registered transports calling
// Compatible(ri) on each in order. ToxTransport.Compatible returns false for any
// RouterInfo not registered in the local PeerRegistry, so it is never selected for
// standard I2P routing. NTCP2 and SSU2 are completely unaffected. When a peer IS
// registered in the PeerRegistry as a Tox friend, Compatible returns true and the
// muxer uses the Tox channel instead of (or in addition to, depending on muxer order)
// the public transport. The default I2P transports continue to handle all public
// network traffic normally.
//
// itox has no opinion about RouterInfo address fields. It never writes to or reads
// transport address fields from RouterInfo. The RouterInfo identity hash is used only
// as a local lookup key in PeerRegistry. The RouterInfo itself is shared between Tox
// friends entirely out-of-band (e.g. pasted into a Tox chat message), and the
// application calls PeerRegistry.Register(ri, toxPubKey) to create the mapping locally.
//
// Security model:
//   - Friend-list ACL gate on every inbound and outbound session path.
//   - No RouterInfo netDB publication is performed by this package.
//   - Messages are carried through toxcore Noise-IK channels only.
//   - Non-friends are rejected silently with slog.LevelDebug logging only.
package itox
