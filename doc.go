// Package itox implements I2P-over-Tox transport sessions.
//
// Security model:
//   - Friend-list ACL gate on every inbound and outbound session path.
//   - In stealth mode, peers must advertise I2P availability via Tox status messages.
//   - No RouterInfo netDB publication is performed by this package.
//   - Messages are carried through toxcore Noise-IK channels only.
//
// Friend-to-friend stealth routing:
//   - When StealthMode is enabled, Tox public keys are not published in RouterInfo.
//   - Friends exchange I2P availability status over encrypted Tox channels.
//   - I2P connections are only established after mutual status confirmation.
//   - The alternate transport remains hidden from the I2P network database.
//   - This provides a form of friend-to-friend stealth routing.
package itox
