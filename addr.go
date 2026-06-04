package itox

import "encoding/hex"

type ToxI2PAddr struct {
	PublicKey [32]byte
}

func (a ToxI2PAddr) Network() string { return "tox" }
func (a ToxI2PAddr) String() string  { return hex.EncodeToString(a.PublicKey[:]) }
