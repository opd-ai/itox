// Package itox implements I2P-over-Tox transport sessions.
//
// Security model:
//   - Friend-list ACL gate on every inbound and outbound session path.
//   - No RouterInfo netDB publication is performed by this package.
//   - Messages are carried through toxcore Noise-IK channels only.
package itox
