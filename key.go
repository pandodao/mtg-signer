package main

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"

	"filippo.io/edwards25519"
	"github.com/fox-one/mixin-sdk-go"
)

func publicKeyToCurve25519(publicKey ed25519.PublicKey) ([]byte, error) {
	p, err := (&edwards25519.Point{}).SetBytes(publicKey[:])
	if err != nil {
		return nil, err
	}
	return p.BytesMontgomery(), nil
}

func keyFromSeed(seed []byte) (mixin.Key, error) {
	var key mixin.Key
	h := sha512.Sum512(seed[:32])
	x := h[:32]
	var wideBytes [64]byte
	copy(wideBytes[:], x[:])
	wideBytes[0] &= 248
	wideBytes[31] &= 63
	wideBytes[31] |= 64
	s, err := edwards25519.NewScalar().SetUniformBytes(wideBytes[:])
	if err != nil {
		return key, err
	}
	copy(key[:], s.Bytes())
	return key, nil
}

func KeyFromSeed(seed string) (mixin.Key, error) {
	var key mixin.Key

	b, err := hex.DecodeString(seed)
	if err != nil {
		return key, err
	}

	return keyFromSeed(b)
}
