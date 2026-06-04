package itox

import "encoding/hex"

// ToxI2PAddr represents a Tox-based I2P address as a net.Addr implementation.
// It wraps a 32-byte Tox public key and is used to identify peers in the transport layer.
type ToxI2PAddr struct {
	PublicKey [32]byte
}

// Network returns the network name "tox" for this address type.
func (a ToxI2PAddr) Network() string { return "tox" }

// String returns the hex-encoded representation of the 32-byte Tox public key.
func (a ToxI2PAddr) String() string  { return hex.EncodeToString(a.PublicKey[:]) }
