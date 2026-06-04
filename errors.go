package itox

import "errors"

var (
	ErrInvalidConfig      = errors.New("itox: invalid config")
	ErrUnauthorizedPeer   = errors.New("itox: unauthorized peer")
	ErrSessionClosed      = errors.New("itox: session closed")
	ErrSendQueueFull      = errors.New("itox: send queue full")
	ErrInvalidFrame       = errors.New("itox: invalid frame")
	ErrFragmentExpired    = errors.New("itox: fragment expired")
	ErrPeerOffline        = errors.New("itox: peer offline")
	ErrSessionRekeyNeeded = errors.New("itox: session rekey required")
)
