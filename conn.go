package itox

import (
	"fmt"
	"net"
	"time"
)

// toxConn is a notification-only net.Conn implementation returned by Accept().
// It does not support data transfer via Read/Write. Instead, callers must use
// the associated ToxSession's QueueSendI2NP() and ReadNextI2NP() methods to
// send and receive I2NP messages.
//
// toxConn serves only to notify the caller that an inbound connection has
// arrived from the given remote address. It allows the muxer pattern to work:
// Accept() unblocks to signal a new peer, but actual data transfer happens
// through the session obtained via GetSession(ri).
type toxConn struct {
	local  net.Addr
	remote net.Addr
}

// Read is not supported on toxConn connections. Return an error instead.
// Use ToxSession.ReadNextI2NP() to read I2NP messages.
func (c *toxConn) Read(_ []byte) (int, error)         { return 0, fmt.Errorf("itox: conn read unsupported") }

// Write is not supported on toxConn connections. Return an error instead.
// Use ToxSession.QueueSendI2NP() to send I2NP messages.
func (c *toxConn) Write(_ []byte) (int, error)        { return 0, fmt.Errorf("itox: conn write unsupported") }

// Close is a no-op for toxConn. Call ToxSession.Close() to close the underlying session.
func (c *toxConn) Close() error                       { return nil }

// LocalAddr returns the local ToxI2PAddr.
func (c *toxConn) LocalAddr() net.Addr                { return c.local }

// RemoteAddr returns the remote ToxI2PAddr.
func (c *toxConn) RemoteAddr() net.Addr               { return c.remote }

// SetDeadline is a no-op for toxConn.
func (c *toxConn) SetDeadline(_ time.Time) error      { return nil }

// SetReadDeadline is a no-op for toxConn.
func (c *toxConn) SetReadDeadline(_ time.Time) error  { return nil }

// SetWriteDeadline is a no-op for toxConn.
func (c *toxConn) SetWriteDeadline(_ time.Time) error { return nil }
