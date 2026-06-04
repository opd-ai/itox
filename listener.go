package itox

import "net"

// AcceptConn is an alias for Accept, provided for compatibility with the go-i2p transport interface.
// It blocks until the next inbound connection notification arrives.
func (t *ToxTransport) AcceptConn() (net.Conn, error) {
	return t.Accept()
}
