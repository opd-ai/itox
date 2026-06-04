package itox

import (
	"github.com/go-i2p/common/router_info"
	i2ptransport "github.com/go-i2p/go-i2p/lib/transport"
)

// DialRouter returns a ToxSession for the given RouterInfo.
// This is an alias for GetSession, provided for compatibility with the go-i2p transport interface.
func (t *ToxTransport) DialRouter(ri router_info.RouterInfo) (i2ptransport.TransportSession, error) {
	return t.GetSession(ri)
}
