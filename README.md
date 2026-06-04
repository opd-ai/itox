# itox

`github.com/opd-ai/itox` implements **I2P-over-Tox** transport sessions.

- Transport name: `tox`
- Router address option: `tox-pubkey` (base64, 32-byte Tox public key)
- ACL source: local Tox friend list only
- netDB publication: not performed by this package

## Friend-to-Friend Stealth Routing

When `StealthMode` is enabled in the configuration, itox implements friend-to-friend stealth routing:

1. **No netDB exposure**: Tox public keys are not published in RouterInfo addresses
2. **Status exchange**: Friends exchange I2P availability announcements over encrypted Tox channels
3. **Mutual confirmation**: I2P sessions are only established after both peers confirm availability
4. **Hidden transport**: The alternate Tox transport remains invisible to the I2P network database

### Configuration

```go
cfg := itox.DefaultConfig(tox, secretKey)
cfg.StealthMode = true  // Enable friend-to-friend stealth routing

transport, err := itox.NewToxTransport(cfg, noiseTransport)
if err != nil {
    log.Fatal(err)
}

// Broadcast I2P availability to all Tox friends
if err := transport.BroadcastI2PStatus(true); err != nil {
    log.Printf("Failed to broadcast status: %v", err)
}
```

### Stealth Mode Behavior

- **Compatible()**: Returns true only if the peer has advertised I2P availability via status message
- **GetSession()**: Rejects peers who haven't advertised I2P availability
- **Status messages**: Automatically processed when received from Tox friends
- **Backward compatibility**: When StealthMode is false, operates in traditional mode with RouterInfo

### Security Model

- Friend-list ACL gate on every inbound and outbound session path
- In stealth mode, additional I2P availability check required
- Messages carried through toxcore Noise-IK channels only
- Status messages use encrypted Tox channels with magic prefix (0xFFFEFD)
- Status entries expire after 5 minutes without updates
