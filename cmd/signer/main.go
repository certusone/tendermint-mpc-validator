package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"sync"
	"time"

	"tendermint-signer/internal/signer"

	cmn "github.com/tendermint/tendermint/libs/common"
	tmlog "github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/privval"
	"github.com/tendermint/tendermint/types"
)

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func main() {
	logger := tmlog.NewTMLogger(
		tmlog.NewSyncWriter(os.Stdout),
	).With("module", "validator")

	var configFile = flag.String("config", "", "path to configuration file")
	flag.Parse()

	if *configFile == "" {
		panic("--config flag is required")
	}

	config, err := signer.LoadConfigFromFile(*configFile)
	if err != nil {
		log.Fatal(err)
	}

	logger.Info(
		"Tendermint Validator",
		"mode", config.Mode,
		"priv-key", config.PrivValKeyFile,
		"priv-state-dir", config.PrivValStateDir,
	)

	signer.InitSerialization()

	// services to stop on shutdown
	var services []cmn.Service

	var pv types.PrivValidator

	chainID := config.ChainID
	if chainID == "" {
		log.Fatal("chain_id option is required")
	}

	if config.Mode == "single" {
		stateFile := path.Join(config.PrivValStateDir, fmt.Sprintf("%s_priv_validator_state.json", chainID))

		var val types.PrivValidator
		if fileExists(stateFile) {
			val = privval.LoadFilePV(config.PrivValKeyFile, stateFile)
		} else {
			logger.Info("Initializing empty state file")
			val = privval.LoadFilePVEmptyState(config.PrivValKeyFile, stateFile)
		}

		pv = &signer.PvGuard{PrivValidator: val}
	} else if config.Mode == "mpc" {
		if config.CosignerThreshold == 0 {
			log.Fatal("The `cosigner_threshold` option is required in `threshold` mode")
		}

		if config.ListenAddress == "" {
			log.Fatal("The cosigner_listen_address option is required in `threshold` mode")
		}

		key, err := signer.LoadCosignerKey(config.PrivValKeyFile)
		if err != nil {
			panic(err)
		}

		// ok to auto initialize on disk since the cosigner share is the one that actually
		// protects against double sign - this exists as a cache for the final signature
		stateFile := path.Join(config.PrivValStateDir, fmt.Sprintf("%s_priv_validator_state.json", chainID))
		signState, err := signer.LoadOrCreateSignState(stateFile)
		if err != nil {
			panic(err)
		}

		// state for our cosigner share
		// Not automatically initialized on disk to avoid double sign risk
		shareStateFile := path.Join(config.PrivValStateDir, fmt.Sprintf("%s_share_sign_state.json", chainID))
		shareSignState, err := signer.LoadSignState(shareStateFile)
		if err != nil {
			panic(err)
		}

		cosigners := []signer.Cosigner{}
		remoteCosigners := []signer.RemoteCosigner{}

		// add ourselves as a peer so localcosigner can handle GetEphSecPart requests
		peers := []signer.CosignerPeer{signer.CosignerPeer{
			ID:        key.ID,
			PublicKey: key.RSAKey.PublicKey,
		}}

		for _, cosignerConfig := range config.Cosigners {
			cosigner := signer.NewRemoteCosigner(cosignerConfig.ID, cosignerConfig.Address)
			cosigners = append(cosigners, cosigner)
			remoteCosigners = append(remoteCosigners, *cosigner)

			if cosignerConfig.ID < 1 || cosignerConfig.ID > len(key.CosignerKeys) {
				log.Fatalf("Unexpected cosigner ID %d", cosignerConfig.ID)
			}

			pubKey := key.CosignerKeys[cosignerConfig.ID-1]
			peers = append(peers, signer.CosignerPeer{
				ID:        cosigner.GetID(),
				PublicKey: *pubKey,
			})
		}

		total := len(config.Cosigners) + 1
		localCosignerConfig := signer.LocalCosignerConfig{
			CosignerKey: key,
			SignState:   &shareSignState,
			RsaKey:      key.RSAKey,
			Peers:       peers,
			Total:       uint8(total),
			Threshold:   uint8(config.CosignerThreshold),
		}

		localCosigner := signer.NewLocalCosigner(localCosignerConfig)

		val := signer.NewThresholdValidator(&signer.ThresholdValidatorOpt{
			Pubkey:    key.PubKey,
			Threshold: config.CosignerThreshold,
			SignState: signState,
			Cosigner:  localCosigner,
			Peers:     cosigners,
		})

		rpcServerConfig := signer.CosignerRpcServerConfig{
			Logger:        logger,
			ListenAddress: config.ListenAddress,
			Cosigner:      localCosigner,
			Peers:         remoteCosigners,
		}

		rpcServer := signer.NewCosignerRpcServer(&rpcServerConfig)
		rpcServer.Start()
		services = append(services, rpcServer)

		pv = &signer.PvGuard{PrivValidator: val}
	} else {
		log.Fatalf("Unsupported mode: %s", config.Mode)
	}

	for _, node := range config.Nodes {
		dialer := net.Dialer{Timeout: 30 * time.Second}
		signer := signer.NewReconnRemoteSigner(node.Address, logger, config.ChainID, pv, dialer)

		err := signer.Start()
		if err != nil {
			panic(err)
		}

		services = append(services, signer)
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	cmn.TrapSignal(logger, func() {
		for _, service := range services {
			err := service.Stop()
			if err != nil {
				panic(err)
			}
		}
		wg.Done()
	})
	wg.Wait()
}