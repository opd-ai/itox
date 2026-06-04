package itox

import "errors"

var (
	ErrInvalidConfig      = errors.New("itox: invalid config")
	ErrInvalidRouterInfo  = errors.New("itox: invalid router info")
	ErrUnauthorizedPeer   = errors.New("itox: unauthorized peer")
	ErrSessionClosed      = errors.New("itox: session closed")
	ErrSendQueueFull      = errors.New("itox: send queue full")
	ErrInvalidFrame       = errors.New("itox: invalid frame")
	ErrFragmentExpired    = errors.New("itox: fragment expired")
	ErrPeerOffline        = errors.New("itox: peer offline")
	ErrSessionRekeyNeeded = errors.New("itox: session rekey required")
	ErrNotFriend          = errors.New("itox: peer is not a Tox friend")
	ErrPeerNotRegistered  = errors.New("itox: peer has no PeerRegistry entry")
	ErrFriendRemoved      = errors.New("itox: friend removed from Tox client")
)
