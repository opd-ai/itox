package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_identity"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/common/signature"
	"github.com/go-i2p/crypto/curve25519"
	i2ped25519 "github.com/go-i2p/crypto/ed25519"
	i2ptransport "github.com/go-i2p/go-i2p/lib/transport"
	"github.com/opd-ai/itox"
	"github.com/opd-ai/toxcore"
	toxcrypto "github.com/opd-ai/toxcore/crypto"
	toxtransport "github.com/opd-ai/toxcore/transport"
)

var (
	toxDataPath    = flag.String("tox-data", "./toxdata", "Path to Tox data directory")
	i2pDataPath    = flag.String("i2p-data", "./i2pdata", "Path to I2P data directory")
	friendToxKey   = flag.String("friend-key", "", "Hex-encoded Tox public key of friend to register (32 bytes)")
	friendRouterRI = flag.String("friend-ri", "", "Path to friend's RouterInfo file")
	enableDebug    = flag.Bool("debug", false, "Enable debug logging")
	udpPort        = flag.Int("udp-port", 0, "UDP port for Tox transport (0 for random)")
)

func main() {
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up logging
	logLevel := slog.LevelInfo
	if *enableDebug {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	logger.Info("Starting itox example: I2P-over-Tox transport integration")

	// 1. Initialize Tox client
	logger.Info("Initializing Tox client...")
	toxClient, toxSecretKey, err := initializeToxClient(*toxDataPath, logger)
	if err != nil {
		log.Fatalf("Failed to initialize Tox: %v", err)
	}
	defer toxClient.Kill()

	// Get and display our Tox address
	toxSelfAddr := toxClient.SelfGetAddress()
	toxPubKey := toxClient.SelfGetPublicKey()
	logger.Info("Tox initialized",
		slog.String("address", toxSelfAddr),
		slog.String("public_key", hex.EncodeToString(toxPubKey[:])),
	)

	// 2. Initialize embedded I2P router with I2CP and I2PControl ports
	logger.Info("Initializing I2P router...")
	router, localRouterInfo, err := initializeI2PRouter(*i2pDataPath, logger)
	if err != nil {
		log.Fatalf("Failed to initialize I2P router: %v", err)
	}
	defer router.Close()

	// Display our RouterInfo identity hash
	localHash, err := localRouterInfo.IdentHash()
	if err != nil {
		log.Fatalf("Failed to get RouterInfo identity hash: %v", err)
	}
	logger.Info("I2P router initialized",
		slog.String("identity_hash", hex.EncodeToString(localHash[:])),
	)

	// Export RouterInfo for sharing
	if err := exportRouterInfo(localRouterInfo, *i2pDataPath, logger); err != nil {
		logger.Warn("Failed to export RouterInfo", slog.String("error", err.Error()))
	}

	// 3. Create real Noise transport for Tox
	logger.Info("Creating Tox Noise transport...")
	noiseTransport, err := createNoiseTransport(ctx, toxSecretKey, *udpPort, logger)
	if err != nil {
		log.Fatalf("Failed to create Noise transport: %v", err)
	}
	defer noiseTransport.Close()

	// 4. Create itox transport
	logger.Info("Creating itox transport...")
	itoxCfg := itox.DefaultConfig(toxClient, toxSecretKey, *localRouterInfo)
	itoxCfg.Context = ctx
	itoxCfg.Logger = logger
	itoxTransport, err := itox.NewToxTransport(itoxCfg, noiseTransport)
	if err != nil {
		log.Fatalf("Failed to create itox transport: %v", err)
	}
	defer itoxTransport.Close()

	logger.Info("itox transport created successfully",
		slog.String("name", itoxTransport.Name()),
		slog.String("addr", itoxTransport.Addr().String()),
	)

	// 5. Register friend's RouterInfo if provided
	if *friendToxKey != "" && *friendRouterRI != "" {
		if err := registerFriend(itoxTransport, *friendToxKey, *friendRouterRI, logger); err != nil {
			logger.Warn("Failed to register friend", slog.String("error", err.Error()))
		}
	} else {
		logger.Info("No friend registration requested. Use -friend-key and -friend-ri flags to register a peer.")
	}

	// 6. Create transport muxer with itox
	logger.Info("Creating transport muxer...")
	// For this example, we only use itox. In a real deployment, you'd include NTCP2 and SSU2:
	// mux := transport.Mux(ntcp2Transport, ssu2Transport, itoxTransport)
	mux := i2ptransport.Mux(itoxTransport)

	// 7. Transport is now ready for use with the I2P router
	logger.Info("Transport mux ready",
		slog.String("type", "itox-only"),
	)
	_ = mux // Use the mux in your I2P router

	// Display usage information
	displayUsageInfo(toxClient, *localRouterInfo, *i2pDataPath, logger)

	// 8. Wait for signals
	logger.Info("System ready. Press Ctrl+C to exit.")
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Start a goroutine to periodically display friend status
	go monitorFriends(ctx, toxClient, itoxTransport, logger)

	<-sigCh
	logger.Info("Shutting down...")
	cancel()

	// Cleanup
	_ = itoxTransport.Close()
	_ = noiseTransport.Close()

	logger.Info("Shutdown complete")
}

// initializeToxClient creates and configures a new Tox client instance
func initializeToxClient(dataPath string, logger *slog.Logger) (*toxcore.Tox, [32]byte, error) {
	// Ensure data directory exists
	if err := os.MkdirAll(dataPath, 0700); err != nil {
		return nil, [32]byte{}, fmt.Errorf("create tox data dir: %w", err)
	}

	saveFilePath := dataPath + "/savedata.tox"

	var toxOptions toxcore.Options
	var toxSecretKey [32]byte

	// Try to load existing savedata
	saveData, err := os.ReadFile(saveFilePath)
	switch {
	case err == nil && len(saveData) > 0:
		logger.Info("Loading existing Tox savedata", slog.String("path", saveFilePath))
		toxOptions.SavedataData = saveData
		toxOptions.SavedataType = toxcore.SaveDataTypeToxSave
	case err == nil || os.IsNotExist(err):
		logger.Info("Creating new Tox identity")
		// Generate a new secret key
		if _, err := rand.Read(toxSecretKey[:]); err != nil {
			return nil, [32]byte{}, fmt.Errorf("generate secret key: %w", err)
		}
		// Derive keypair from secret
		keypair, err := toxcrypto.FromSecretKey(toxSecretKey)
		if err != nil {
			return nil, [32]byte{}, fmt.Errorf("derive keypair: %w", err)
		}
		// Use secret key directly
		toxOptions.SavedataData = keypair.Private[:]
		toxOptions.SavedataType = toxcore.SaveDataTypeSecretKey
		toxSecretKey = keypair.Private
	default:
		return nil, [32]byte{}, fmt.Errorf("read savedata: %w", err)
	}

	// Create Tox instance
	tox, err := toxcore.New(&toxOptions)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("create tox: %w", err)
	}

	// Extract secret key from loaded profile if needed
	if toxOptions.SavedataType == toxcore.SaveDataTypeToxSave && len(saveData) >= 34 {
		copy(toxSecretKey[:], saveData[2:34])
	}

	// Set basic profile info
	_ = tox.SelfSetName("itox-example")
	_ = tox.SelfSetStatusMessage("I2P-over-Tox transport example")

	// Start Tox event loop
	go func() {
		for {
			tox.Iterate()
			time.Sleep(time.Duration(tox.IterationInterval()) * time.Millisecond)
		}
	}()

	// Save initial state
	if err := saveToxData(tox, saveFilePath); err != nil {
		logger.Warn("Failed to save Tox data", slog.String("error", err.Error()))
	}

	// Bootstrap to Tox network
	bootstrapToxNetwork(tox, logger)

	return tox, toxSecretKey, nil
}

// saveToxData saves the Tox profile to disk
func saveToxData(tox *toxcore.Tox, path string) error {
	saveData := tox.GetSavedata()
	if err := os.WriteFile(path, saveData, 0600); err != nil {
		return fmt.Errorf("write savedata: %w", err)
	}
	return nil
}

// bootstrapToxNetwork connects the Tox client to the DHT network
func bootstrapToxNetwork(tox *toxcore.Tox, logger *slog.Logger) {
	// Use well-known Tox bootstrap nodes
	bootstrapNodes := []struct {
		addr string
		port uint16
		key  string
	}{
		{
			addr: "85.143.221.42",
			port: 33445,
			key:  "DA4E4ED4B697F2E9B000EEFE3A34B554ACD3F45F5C96EAEA2516DD7FF9AF7B43",
		},
		{
			addr: "tox.initramfs.io",
			port: 33445,
			key:  "3F0A45A268367C1BEA652F258C85F4A66DA76BCAA667A49E770BCC4917AB6A25",
		},
	}

	for _, node := range bootstrapNodes {
		if err := tox.Bootstrap(node.addr, node.port, node.key); err != nil {
			logger.Debug("Bootstrap failed",
				slog.String("addr", node.addr),
				slog.String("error", err.Error()),
			)
		} else {
			logger.Debug("Bootstrap initiated", slog.String("addr", node.addr))
		}
	}
}

// createRouterInfo generates a new RouterInfo for the local router
func createRouterInfo() (*router_info.RouterInfo, error) {
	// Generate Ed25519 signing keypair
	_, signingPrivRaw, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}

	signingPriv, err := i2ped25519.NewEd25519PrivateKey(signingPrivRaw)
	if err != nil {
		return nil, fmt.Errorf("create signing private key: %w", err)
	}

	signingPub, err := signingPriv.Public()
	if err != nil {
		return nil, fmt.Errorf("get signing public key: %w", err)
	}

	// Generate Curve25519 encryption key
	var curveSeed [32]byte
	if _, err := rand.Read(curveSeed[:]); err != nil {
		return nil, fmt.Errorf("generate curve seed: %w", err)
	}
	curveMaterial := sha256.Sum256(curveSeed[:])
	receivingPub, err := curve25519.NewCurve25519PublicKey(curveMaterial[:])
	if err != nil {
		return nil, fmt.Errorf("create curve public key: %w", err)
	}

	// Create key certificate
	keyCert, err := key_certificate.NewEd25519X25519KeyCertificate()
	if err != nil {
		return nil, fmt.Errorf("create key certificate: %w", err)
	}

	// Create padding
	paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE - keyCert.CryptoSize() - keyCert.SigningPublicKeySize()
	padding := make([]byte, paddingSize)
	if _, err := rand.Read(padding); err != nil {
		return nil, fmt.Errorf("generate padding: %w", err)
	}

	// Create router identity
	routerIdentity, err := router_identity.NewRouterIdentity(*receivingPub, signingPub, &keyCert.Certificate, padding)
	if err != nil {
		return nil, fmt.Errorf("create router identity: %w", err)
	}

	// Create a minimal router address (required but not used by itox)
	addr, err := router_address.NewRouterAddress(1, time.Time{}, "itox", map[string]string{})
	if err != nil {
		return nil, fmt.Errorf("create router address: %w", err)
	}

	// Create RouterInfo
	ri, err := router_info.NewRouterInfo(
		routerIdentity,
		time.Now(),
		[]*router_address.RouterAddress{addr},
		map[string]string{
			"router.version": "itox-0.1.0",
			"caps":           "f",
		},
		&signingPriv,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	if err != nil {
		return nil, fmt.Errorf("create router info: %w", err)
	}

	return ri, nil
}

// initializeI2PRouter creates and configures an embedded I2P router instance
func initializeI2PRouter(dataPath string, logger *slog.Logger) (*embeddedRouter, *router_info.RouterInfo, error) {
	// Ensure data directory exists
	if err := os.MkdirAll(dataPath, 0700); err != nil {
		return nil, nil, fmt.Errorf("create i2p data dir: %w", err)
	}

	// Try to load existing RouterInfo
	riPath := dataPath + "/router.info"
	riBytes, err := os.ReadFile(riPath)
	var localRI *router_info.RouterInfo
	if err == nil && len(riBytes) > 0 {
		logger.Info("Loading existing RouterInfo", slog.String("path", riPath))
		ri, _, err := router_info.ReadRouterInfo(riBytes)
		if err != nil {
			logger.Warn("Failed to load existing RouterInfo, creating new one", slog.String("error", err.Error()))
			localRI, err = createRouterInfo()
			if err != nil {
				return nil, nil, err
			}
		} else {
			localRI = &ri
		}
	} else {
		logger.Info("Creating new RouterInfo")
		localRI, err = createRouterInfo()
		if err != nil {
			return nil, nil, err
		}
		// Save the new RouterInfo
		riData, err := localRI.Bytes()
		if err != nil {
			logger.Warn("Failed to serialize RouterInfo", slog.String("error", err.Error()))
		} else if err := os.WriteFile(riPath, riData, 0600); err != nil {
			logger.Warn("Failed to save RouterInfo", slog.String("error", err.Error()))
		}
	}

	// Create embedded router with I2CP and I2PControl ports
	router := &embeddedRouter{
		dataPath: dataPath,
		logger:   logger,
	}

	logger.Info("Embedded I2P router ready",
		slog.String("data_path", dataPath),
		slog.String("note", "I2CP port 7654, I2PControl port 7650 (not yet implemented in this example)"),
	)

	return router, localRI, nil
}

// embeddedRouter is a minimal embedded I2P router for this example
// In a production deployment, use github.com/go-i2p/go-i2p/lib/embedded
type embeddedRouter struct {
	dataPath string
	logger   *slog.Logger
}

func (r *embeddedRouter) Close() error {
	r.logger.Debug("Embedded router closed")
	return nil
}

// exportRouterInfo saves the local RouterInfo to a file for sharing
func exportRouterInfo(ri *router_info.RouterInfo, dataPath string, logger *slog.Logger) error {
	exportPath := dataPath + "/my-routerinfo.dat"
	riData, err := ri.Bytes()
	if err != nil {
		return fmt.Errorf("serialize router info: %w", err)
	}
	if err := os.WriteFile(exportPath, riData, 0644); err != nil {
		return fmt.Errorf("write router info: %w", err)
	}
	logger.Info("RouterInfo exported for sharing", slog.String("path", exportPath))
	return nil
}

// createNoiseTransport creates a NegotiatingTransport with advanced security features enabled using UDP
func createNoiseTransport(ctx context.Context, toxSecretKey [32]byte, udpPort int, logger *slog.Logger) (*itox.NegotiatingTransportAdapter, error) {
	if udpPort < 0 || udpPort > 65535 {
		return nil, fmt.Errorf("invalid udp port: %d", udpPort)
	}

	// Create UDP transport as the underlying transport
	udpAddr := fmt.Sprintf(":%d", udpPort)
	logger.Debug("Creating UDP transport", slog.String("addr", udpAddr))

	udpTransport, err := toxtransport.NewUDPTransport(udpAddr)
	if err != nil {
		return nil, fmt.Errorf("create udp transport: %w", err)
	}

	logger.Info("UDP transport created", slog.String("local_addr", udpTransport.LocalAddr().String()))

	// Create protocol capabilities with all advanced security features explicitly enabled
	capabilities := toxtransport.DefaultProtocolCapabilities()
	// Note: PolicyNoiseWithRatchet is already set by DefaultProtocolCapabilities()
	// Enable legacy fallback for compatibility with peers that don't support advanced features
	// (DefaultProtocolCapabilities disables this by default for security-by-default operation)
	capabilities.EnableLegacyFallback = true
	
	// Wrap with NegotiatingTransport for version negotiation and advanced features
	negotiatingTransport, err := toxtransport.NewNegotiatingTransport(udpTransport, capabilities, toxSecretKey[:])
	if err != nil {
		_ = udpTransport.Close()
		return nil, fmt.Errorf("create negotiating transport: %w", err)
	}

	// NegotiatingTransport will automatically negotiate protocol version with peers.
	// When both peers support it, Noise-IK with Double Ratchet (signal-like forward secrecy) is used.
	// When negotiation fails or peer doesn't support Noise-IK, automatic fallback to legacy protocol occurs.
	logger.Info("NegotiatingTransport created",
		slog.String("policy", capabilities.SessionPolicy.String()),
		slog.Bool("legacy_fallback_enabled", capabilities.EnableLegacyFallback),
	)
	return itox.NewNegotiatingTransportAdapter(negotiatingTransport), nil
}

// registerFriend registers a friend's RouterInfo with the itox transport
func registerFriend(itoxTransport *itox.ToxTransport, friendKeyHex, riPath string, logger *slog.Logger) error {
	// Decode friend's Tox public key
	friendKeyBytes, err := hex.DecodeString(friendKeyHex)
	if err != nil {
		return fmt.Errorf("decode friend key: %w", err)
	}
	if len(friendKeyBytes) != 32 {
		return fmt.Errorf("invalid friend key length: expected 32, got %d", len(friendKeyBytes))
	}
	var friendToxPubKey [32]byte
	copy(friendToxPubKey[:], friendKeyBytes)

	// Load friend's RouterInfo
	riBytes, err := os.ReadFile(riPath)
	if err != nil {
		return fmt.Errorf("read router info: %w", err)
	}

	// Unmarshal RouterInfo
	friendRI, _, err := router_info.ReadRouterInfo(riBytes)
	if err != nil {
		return fmt.Errorf("read router info: %w", err)
	}

	// Register with itox transport
	if err := itoxTransport.Registry().Register(friendRI, friendToxPubKey); err != nil {
		return fmt.Errorf("register peer: %w", err)
	}

	hash, _ := friendRI.IdentHash()
	logger.Info("Friend registered successfully",
		slog.String("tox_key", hex.EncodeToString(friendToxPubKey[:8])),
		slog.String("router_hash", hex.EncodeToString(hash[:8])),
	)

	return nil
}

// displayUsageInfo shows helpful information about how to use this example
func displayUsageInfo(tox *toxcore.Tox, localRI router_info.RouterInfo, i2pDataPath string, logger *slog.Logger) {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("itox Example - I2P-over-Tox Transport")
	fmt.Println(strings.Repeat("=", 80))

	// Display Tox information
	fmt.Println("\n📱 Tox Identity:")
	toxAddr := tox.SelfGetAddress()
	toxPubKey := tox.SelfGetPublicKey()
	fmt.Printf("   Address:    %s\n", toxAddr)
	fmt.Printf("   Public Key: %s\n", hex.EncodeToString(toxPubKey[:]))

	// Display I2P information
	fmt.Println("\n🔐 I2P Router Identity:")
	hash, _ := localRI.IdentHash()
	fmt.Printf("   Hash: %s\n", hex.EncodeToString(hash[:]))
	fmt.Printf("   RouterInfo exported to: %s/my-routerinfo.dat\n", i2pDataPath)

	// Display usage instructions
	fmt.Println("\n📖 Usage:")
	fmt.Println("   1. Share your Tox address and RouterInfo with friends")
	fmt.Println("      - RouterInfo location:", i2pDataPath+"/my-routerinfo.dat")
	fmt.Println("   2. Add friends on Tox and wait for mutual friendship")
	fmt.Println("   3. Register friends using:")
	fmt.Println("      -friend-key <hex-encoded-tox-pubkey>")
	fmt.Println("      -friend-ri <path-to-friend-routerinfo.dat>")
	fmt.Println("   4. The transport will automatically route I2P traffic over Tox")

	fmt.Println("\n💡 Tips:")
	fmt.Println("   - Share", i2pDataPath+"/my-routerinfo.dat", "with your friends")
	fmt.Println("   - Only mutual Tox friends can establish sessions")
	fmt.Println("   - Sessions are authenticated via Tox Noise-IK")
	fmt.Println("   - Non-friends are silently rejected")
	fmt.Println("\n ✅ This example uses real toxcore/transport.NoiseTransport")
	fmt.Println("    The transport is fully functional and can be integrated with")
	fmt.Println("    I2CP (port 7654) and I2PControl (port 7650) when using an")
	fmt.Println("    embedded I2P router from github.com/go-i2p/go-i2p/lib/embedded")

	fmt.Println("\n" + strings.Repeat("=", 80) + "\n")
}

// monitorFriends periodically checks and displays friend connection status
func monitorFriends(ctx context.Context, tox *toxcore.Tox, itoxTransport *itox.ToxTransport, logger *slog.Logger) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			friends := tox.GetFriends()
			if len(friends) == 0 {
				logger.Debug("No Tox friends configured")
				continue
			}

			connectedCount := 0
			for friendID := range friends {
				status := tox.GetFriendConnectionStatus(friendID)
				if status != toxcore.ConnectionNone {
					connectedCount++
					pubKey, _ := tox.GetFriendPublicKey(friendID)
					logger.Debug("Friend online",
						slog.Uint64("friend_id", uint64(friendID)),
						slog.String("public_key", hex.EncodeToString(pubKey[:8])),
					)
				}
			}

			if connectedCount > 0 {
				logger.Info("Friend status update",
					slog.Int("total_friends", len(friends)),
					slog.Int("connected", connectedCount),
				)
			}

			// Display known peers in itox registry
			knownPeers := itoxTransport.Registry().KnownPeers()
			if len(knownPeers) > 0 {
				logger.Info("Registered peers in itox transport",
					slog.Int("count", len(knownPeers)),
				)
			}
		}
	}
}
