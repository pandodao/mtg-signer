package main

import (
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

type (
	Config struct {
		Dapp  Dapp  `json:"dapp" yaml:"dapp"`
		Group Group `json:"group,omitempty" yaml:"group"`
	}

	Dapp struct {
		ClientID        string `json:"client_id" yaml:"client_id"`
		SessionID       string `json:"session_id" yaml:"session_id"`
		PrivateKey      string `json:"private_key" yaml:"private_key"`
		PinToken        string `json:"pin_token" yaml:"pin_token"`
		Pin             string `json:"pin" yaml:"pin"`
		PinSeed         string `json:"pin_seed" yaml:"pin_seed"`
		PrivateKeySeed  string `json:"private_key_seed" yaml:"private_key_seed"`
		ServerPublicKey string `json:"server_public_key" yaml:"server_public_key"`
	}

	Member struct {
		ClientID string `json:"client_id,omitempty" yaml:"client_id"`
	}

	Group struct {
		Members       []Member `json:"members,omitempty" yaml:"members"`
		Threshold     uint8    `json:"threshold,omitempty" yaml:"threshold"`
		SignThreshold uint8    `json:"sign_threshold,omitempty" yaml:"sign_threshold"`
	}
)

func loadConfig(filename string) (*Config, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	defer func() {
		_ = f.Close()
	}()

	return decodeConfig(f)
}

func decodeConfig(r io.Reader) (*Config, error) {
	var cfg Config
	if err := yaml.NewDecoder(r).Decode(&cfg); err != nil {
		return nil, err
	}

	if cfg.Group.SignThreshold == 0 && cfg.Group.Threshold > 0 {
		cfg.Group.SignThreshold = cfg.Group.Threshold - 1
	}

	return &cfg, nil
}
