package itox

import (
	"net"

	toxtransport "github.com/opd-ai/toxcore/transport"
)

// NegotiatingTransportAdapter wraps a NegotiatingTransport to provide compatibility
// with the transportNoise interface used by ToxTransport. It adapts the method
// signatures to match what itox expects.
type NegotiatingTransportAdapter struct {
	*toxtransport.NegotiatingTransport
}

// NewNegotiatingTransportAdapter creates a new adapter for a NegotiatingTransport.
func NewNegotiatingTransportAdapter(nt *toxtransport.NegotiatingTransport) *NegotiatingTransportAdapter {
	return &NegotiatingTransportAdapter{NegotiatingTransport: nt}
}

// AddPeer adapts AddNoiseKeyForPeer to match the AddPeer interface used by itox.
// This allows NegotiatingTransport to be used where transportNoise interface is expected.
func (nta *NegotiatingTransportAdapter) AddPeer(addr net.Addr, publicKey []byte) error {
	return nta.AddNoiseKeyForPeer(addr, publicKey)
}
