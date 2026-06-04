package itox

import (
	"fmt"
	"net"
	"time"
)

type toxConn struct {
	local  net.Addr
	remote net.Addr
}

func (c *toxConn) Read(_ []byte) (int, error)         { return 0, fmt.Errorf("itox: conn read unsupported") }
func (c *toxConn) Write(_ []byte) (int, error)        { return 0, fmt.Errorf("itox: conn write unsupported") }
func (c *toxConn) Close() error                       { return nil }
func (c *toxConn) LocalAddr() net.Addr                { return c.local }
func (c *toxConn) RemoteAddr() net.Addr               { return c.remote }
func (c *toxConn) SetDeadline(_ time.Time) error      { return nil }
func (c *toxConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *toxConn) SetWriteDeadline(_ time.Time) error { return nil }
