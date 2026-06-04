package itox

import "net"

func (t *ToxTransport) AcceptConn() (net.Conn, error) {
	return t.Accept()
}
