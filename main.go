package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/fox-one/mixin-sdk-go/v2"
	"github.com/fox-one/mixin-sdk-go/v2/mixinnet"
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

	if cfg.Dapp.PinSeed != "" {
		key, err := mixinnet.KeyFromSeed(cfg.Dapp.PinSeed)
		if err != nil {
			panic(err)
		}
		cfg.Dapp.Pin = key.String()
	}

	// init mixin client
	client, err := mixin.NewFromKeystore(&mixin.Keystore{
		ClientID:          cfg.Dapp.ClientID,
		SessionID:         cfg.Dapp.SessionID,
		PrivateKey:        cfg.Dapp.PrivateKey,
		PinToken:          cfg.Dapp.PinToken,
		ServerPublicKey:   cfg.Dapp.ServerPublicKey,
		SessionPrivateKey: cfg.Dapp.PrivateKeySeed,
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

	tx, err := mixinnet.NewClient(mixinnet.DefaultLegacyConfig).SendRawTransaction(ctx, sig.RawTransaction)
	if err != nil {
		log.Error("SendRawTransaction", slog.Any("err", err))
		return err
	}

	log.Info("SendRawTransaction", slog.String("hash", tx.Hash.String()))
	return nil
}
