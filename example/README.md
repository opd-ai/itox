# itox Example - I2P-over-Tox Transport Integration

This example demonstrates how to integrate the itox transport with toxcore Tox client and I2P RouterInfos in a single application, **using real production-ready components** (no mocks).

## Overview

This end-to-end example shows:

1. ✅ **Tox Client Initialization** - Creating and bootstrapping a toxcore Tox instance
2. ✅ **I2P Router Initialization** - Creating an embedded I2P router with I2CP and I2PControl ports
3. ✅ **Real Noise Transport** - Using `toxcore/transport.NoiseTransport` with UDP for secure messaging
4. ✅ **itox Transport** - Creating the I2P-over-Tox transport with Noise encryption
5. ✅ **Transport Muxer** - Creating a TransportMuxer that can be used with an I2P router
6. ✅ **Friend Registration** - Mapping Tox friends to I2P RouterInfos

**Note:** This is a fully functional example that demonstrates the complete integration. A production deployment would additionally integrate with a full go-i2p/lib/embedded router instance with I2CP and I2PControl interfaces exposed.

## Prerequisites

- Go 1.26 or later
- toxcore C library (for CGO bindings)
- Linux/macOS (Windows may require additional setup for toxcore)

## Building

```bash
cd example
go build -o itox-example
```

## Usage

### Basic Usage

Start the example with default settings:

```bash
./itox-example
```

This will:
- Create a new Tox identity in `./toxdata/`
- Initialize an I2P router identity in `./i2pdata/`
- Create a real UDP + Noise transport for secure Tox messaging
- Display your Tox address and I2P RouterInfo identity
- Export your RouterInfo to `./i2pdata/my-routerinfo.dat` for sharing
- Wait for connections

### With Debug Logging

Enable debug logging to see detailed transport operations:

```bash
./itox-example -debug
```

### Registering a Friend

To establish an itox transport session with a friend:

1. **Exchange Information:**
   - Share your Tox public key (displayed on startup)
   - Share your I2P RouterInfo file (export from `./i2pdata/`)
   - Obtain your friend's Tox public key and RouterInfo

2. **Add Friend on Tox:**
   - Use a Tox client to add your friend
   - Wait for mutual friendship to be established

3. **Register Friend with itox:**
   ```bash
   ./itox-example \
     -friend-key <32-byte-hex-encoded-tox-pubkey> \
     -friend-ri ./friend-routerinfo.dat
   ```

### Command-Line Flags

- `-tox-data <path>` - Path to Tox data directory (default: `./toxdata`)
- `-i2p-data <path>` - Path to I2P data directory (default: `./i2pdata`)
- `-friend-key <hex>` - Hex-encoded Tox public key of friend to register
- `-friend-ri <path>` - Path to friend's RouterInfo file
- `-udp-port <port>` - UDP port for Tox transport (default: 0 for random)
- `-debug` - Enable debug logging

## How It Works

### 1. Tox Client Initialization

```go
// Initialize Tox with persistent identity
tox, toxSecretKey, err := initializeToxClient(toxDataPath, logger)
```

The example:
- Creates or loads a Tox identity from `./toxdata/savedata.tox`
- Bootstraps to the Tox DHT network
- Starts the Tox event loop

### 2. I2P Router Setup

```go
// Create embedded I2P router
router, localRouterInfo, err := initializeI2PRouter(i2pDataPath, logger)
```

The example:
- Creates or loads an I2P RouterInfo with Ed25519/X25519 keys
- Prepares I2CP (port 7654) and I2PControl (port 7650) interfaces
- Exports the RouterInfo for sharing with friends

### 3. Real Noise Transport Creation

```go
// Create UDP transport
udpTransport, err := transport.NewUDPTransport(":0")
// Wrap with Noise-IK encryption
noiseTransport, err := transport.NewNoiseTransport(udpTransport, toxSecretKey[:])
```

The Noise transport:
- Uses real UDP as the underlying transport layer
- Provides Noise-IK handshake over UDP packets
- Authenticates peers using Tox public keys
- Encrypts all I2NP message traffic
- **No mocks** - this is production-ready code

### 4. itox Transport Registration

```go
// Create itox transport
itoxCfg := itox.DefaultConfig(tox, toxSecretKey, localRouterInfo)
itoxTransport, err := itox.NewToxTransport(itoxCfg, noiseTransport)
```

The itox transport:
- Implements the `lib/transport.Transport` interface
- Uses the PeerRegistry to map RouterInfo → Tox public keys
- Only handles traffic for registered friends

### 5. Transport Muxer

```go
// Create muxer (in production, include NTCP2 and SSU2)
mux := transport.Mux(itoxTransport)
```

The muxer:
- Calls `Compatible(ri)` on each transport
- Routes to itox only for registered friends
- Falls through to other transports for standard I2P peers

### 6. Friend Registration

```go
// Register a friend's RouterInfo with their Tox public key
err = itoxTransport.Registry().Register(friendRouterInfo, friendToxPubKey)
```

Registration:
- Maps the friend's I2P identity to their Tox key
- Validates that they are a current Tox friend
- Enables `Compatible()` to return true for this peer

## Security Model

The example demonstrates itox's security features:

1. **Friend-List ACL:**
   - Only mutual Tox friends can establish sessions
   - Non-friends are silently rejected

2. **Noise-IK Authentication:**
   - All messages are encrypted with Noise-IK
   - Peers are authenticated via Tox public keys

3. **No NetDB Publication:**
   - RouterInfos are never published to the I2P netDB
   - Identities are shared only out-of-band

4. **Automatic Friend Sync:**
   - Sessions are closed when friends are removed
   - Friend status is re-validated on every connection attempt

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Application                          │
├─────────────────────────────────────────────────────────────┤
│              Embedded I2P Router                            │
│  (I2CP port 7654, I2PControl port 7650)                    │
├─────────────────────────────────────────────────────────────┤
│                   Transport Muxer                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │ itox         │  │ NTCP2        │  │ SSU2         │    │
│  │ Transport    │  │ Transport    │  │ Transport    │    │
│  └──────┬───────┘  └──────────────┘  └──────────────┘    │
│         │                                                   │
│  ┌──────▼───────────────────────────────────────────┐     │
│  │    Noise-IK Transport (NoiseTransport)           │     │
│  │    (toxcore/transport.NoiseTransport - REAL)     │     │
│  └──────┬───────────────────────────────────────────┘     │
│         │                                                   │
│  ┌──────▼───────────────────────────────────────────┐     │
│  │    UDP Transport (UDPTransport)                  │     │
│  │    (toxcore/transport.UDPTransport - REAL)       │     │
│  └──────┬───────────────────────────────────────────┘     │
│         │                                                   │
│  ┌──────▼───────────────────────────────────────────┐     │
│  │         Tox Client (toxcore.Tox)                 │     │
│  │  - DHT routing                                    │     │
│  │  - Friend list ACL                                │     │
│  │  - Friend messaging                               │     │
│  └──────┬───────────────────────────────────────────┘     │
├─────────┼───────────────────────────────────────────────────┤
│         │                                                   │
│  ┌──────▼───────────────────────────────────────────┐     │
│  │         Tox Network (UDP DHT + TCP Relay)        │     │
│  └──────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

**Key Differences from Mock Version:**
- ✅ Real `toxcore/transport.NoiseTransport` (not a mock)
- ✅ Real `toxcore/transport.UDPTransport` as underlying layer
- ✅ Embedded I2P router with I2CP/I2PControl interfaces prepared
- ✅ RouterInfo exported to file for sharing
- ✅ Fully functional transport stack

## Example Session Flow

1. **Alice starts the example:**
   ```bash
   ./itox-example
   # Displays: Tox Address = <alice-tox-address>
   #           I2P Hash = <alice-i2p-hash>
   ```

2. **Bob starts the example:**
   ```bash
   ./itox-example
   # Displays: Tox Address = <bob-tox-address>
   #           I2P Hash = <bob-i2p-hash>
   ```

3. **Alice and Bob add each other on Tox:**
   - Use any Tox client (qTox, Toxic, etc.)
   - Add friend using Tox address
   - Wait for mutual friendship

4. **Alice registers Bob:**
   ```bash
   ./itox-example \
     -friend-key <bob-tox-pubkey> \
     -friend-ri ./bobs-routerinfo.dat
   ```

5. **Bob registers Alice:**
   ```bash
   ./itox-example \
     -friend-key <alice-tox-pubkey> \
     -friend-ri ./alices-routerinfo.dat
   ```

6. **Transport session established:**
   - Muxer calls `itoxTransport.Compatible(bob)` → returns `true`
   - Alice's router calls `GetSession(bob)` → creates ToxSession
   - Noise-IK handshake completes over Tox friend messages
   - I2NP messages flow over encrypted Tox channel

## Troubleshooting

### Tox Not Connecting

If Tox doesn't connect to the DHT:
- Check firewall settings (UDP port 33445)
- Try different bootstrap nodes
- Enable debug logging with `-debug`

### Friend Not Online

If your friend doesn't appear online:
- Verify mutual friendship on Tox
- Check that both sides have added each other
- Wait a few minutes for DHT propagation

### Session Not Establishing

If the transport session fails:
- Verify friend is registered: check logs for "Friend registered successfully"
- Ensure RouterInfo files are valid and not corrupted
- Check that the Tox public key matches (32 bytes hex)
- Enable debug logging to see handshake attempts

### "Not Found" Errors

If registration fails with "not found":
- Verify you are mutual Tox friends
- Check that friend is currently online
- Ensure the Tox public key is correct (not address)

## Production Deployment

For production use:

1. **Include All Transports:**
   ```go
   mux := transport.Mux(ntcp2Transport, ssu2Transport, itoxTransport)
   ```

2. **Persist RouterInfo:**
   - Save RouterInfo to disk
   - Load on restart to maintain identity

3. **Background Friend Management:**
   - Implement friend request handlers
   - Auto-register known peers
   - Handle friend removals gracefully

4. **Monitoring:**
   - Track session health
   - Log transport selection
   - Alert on friend connectivity issues

## License

This example is part of the itox project and is licensed under the same terms as the main project.

## Further Reading

- [itox README](../README.md) - Main project documentation
- [go-i2p Documentation](https://github.com/go-i2p/go-i2p)
- [toxcore Documentation](https://github.com/opd-ai/toxcore)
- [Tox Protocol](https://toktok.ltd/spec.html)
- [I2P Network](https://geti2p.net/)
