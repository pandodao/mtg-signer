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
		ClientID   string `json:"client_id" yaml:"client_id"`
		SessionID  string `json:"session_id" yaml:"session_id"`
		PrivateKey string `json:"private_key" yaml:"private_key"`
		PinToken   string `json:"pin_token" yaml:"pin_token"`
		Pin        string `json:"pin" yaml:"pin"`
	}

	Member struct {
		ClientID string `json:"client_id,omitempty" yaml:"client_id"`
		// 节点共享的用户验证签名的公钥
		VerifyKey string `json:"verify_key,omitempty" yaml:"verify_key"`
	}

	Group struct {
		// 节点管理员 mixin id
		Admins []string `json:"admins,omitempty" yaml:"admins"`
		// 节点用于签名的私钥
		SignKey string `json:"sign_key,omitempty" yaml:"sign_key"`
		// memo 加解密用的私钥
		PrivateKey    string   `json:"private_key,omitempty" yaml:"private_key"`
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
