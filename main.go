package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/fox-one/mixin-sdk-go"
)

var (
	configPath    = flag.String("config", "config.yaml", "4swap legacy config file path")
	sinceDuration = flag.Duration("since", time.Hour, "rollback duration")
)

func main() {
	flag.Parse()
	cfg, err := loadConfig(*configPath)
	if err != nil {
		slog.Error("load config failed", slog.Any("err", err))
		return
	}

	if cfg.Dapp.PrivateKeySeed != "" {
		key, err := KeyFromSeed(cfg.Dapp.PrivateKeySeed)
		if err != nil {
			panic(fmt.Errorf("parse pin seed failed: %w", err))
		}

		privateKey := cfg.Dapp.PrivateKeySeed + key.Public().String()
		bts, _ := hex.DecodeString(privateKey)
		cfg.Dapp.PrivateKey = base64.StdEncoding.EncodeToString(bts)
	}
	if cfg.Dapp.ServerPublicKey != "" {
		b, err := hex.DecodeString(cfg.Dapp.ServerPublicKey)
		if err != nil {
			panic(fmt.Errorf("decode server public key failed: %w", err))
		}

		if len(b) != ed25519.PublicKeySize {
			panic(fmt.Errorf("invalid server public key"))
		}

		pub, err := publicKeyToCurve25519(b)
		if err != nil {
			panic(fmt.Errorf("convert server public key to curve25519 failed: %w", err))
		}

		cfg.Dapp.PinToken = base64.StdEncoding.EncodeToString(pub)
	}
	if cfg.Dapp.PinSeed != "" {
		pin, err := KeyFromSeed(cfg.Dapp.PinSeed)
		if err != nil {
			panic(fmt.Errorf("parse pin seed failed: %w", err))
		}
		cfg.Dapp.Pin = pin.String()
	}

	// init mixin client
	client, err := mixin.NewFromKeystore(&mixin.Keystore{
		ClientID:   cfg.Dapp.ClientID,
		SessionID:  cfg.Dapp.SessionID,
		PrivateKey: cfg.Dapp.PrivateKey,
		PinToken:   cfg.Dapp.PinToken,
	})
	if err != nil {
		slog.Error("init mixin client failed", slog.Any("err", err))
		return
	}

	// init list multisig outpus option
	opt := mixin.ListMultisigOutputsOption{
		Threshold: cfg.Group.Threshold,
		Offset:    time.Now().Add(-(*sinceDuration)).UTC(),
		Limit:     500,
	}

	for _, m := range cfg.Group.Members {
		opt.Members = append(opt.Members, m.ClientID)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Kill, os.Interrupt)
	defer stop()

	slog.Info("signer start", slog.Time("offset", opt.Offset))

	for {
		select {
		case <-ctx.Done():
			slog.Info("signer stop....")
			return
		case <-time.After(time.Second):
		}

		log := slog.With(slog.Time("offset", opt.Offset))

		outputs, err := client.ListMultisigOutputs(ctx, opt)
		if err != nil {
			log.Error("ListMultisigOutputs", slog.Any("err", err))
			continue
		}

		log.Info("ListMultisigOutputs", slog.Int("count", len(outputs)))

		for _, output := range outputs {
			opt.Offset = output.UpdatedAt
			if output.State != mixin.UTXOStateSigned {
				continue
			}

			if err := handleOutput(ctx, client, output, cfg); err != nil {
				break
			}
		}
	}
}

// output must be signed
func handleOutput(ctx context.Context, client *mixin.Client, output *mixin.MultisigUTXO, cfg *Config) error {
	log := slog.With(slog.String("utxo_id", output.UTXOID))

	log.Info("handle output", slog.String("state", output.State), slog.Int("signer_threshold", int(cfg.Group.SignThreshold)))

	sig, err := client.CreateMultisig(ctx, mixin.MultisigActionSign, output.SignedTx)
	if err != nil {
		log.Error("CreateMultisig", slog.Any("err", err))
		return err
	}

	signed := govalidator.IsIn(client.ClientID, sig.Signers...)
	log.Info("multisig created", slog.Int("signers", len(sig.Signers)), slog.Bool("signed", signed))

	if !signed && len(sig.Signers) >= int(cfg.Group.SignThreshold) {
		sig, err = client.SignMultisig(ctx, sig.RequestID, cfg.Dapp.Pin)
		if err != nil {
			log.Error("SignMultisig", slog.Any("err", err))
			return err
		}

		log.Info("multisig signed", slog.Int("signers", len(sig.Signers)), slog.Int("threshold", int(sig.Threshold)))
	}

	if len(sig.Signers) < int(sig.Threshold) {
		return nil
	}

	hash, err := client.SendRawTransaction(ctx, sig.RawTransaction)
	if err != nil {
		log.Error("SendRawTransaction", slog.Any("err", err))
		return err
	}

	log.Info("SendRawTransaction", slog.String("hash", hash.String()))
	return nil
}
