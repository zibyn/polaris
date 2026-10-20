// Package crypt encrypts secrets at rest with the master key (AES-256-GCM).
//
// Ciphertext layout: version(1) || nonce(12) || sealed. The version byte names
// the master key that sealed it, so a rotation can re-encrypt row by row.
//
// aad binds a ciphertext to where it is stored (e.g. "totp:<user id>"), so a
// value copied into another row or column fails to open.
package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

type Keyring struct {
	current byte
	aeads   map[byte]cipher.AEAD
	macKeys map[byte][]byte
}

// NewKeyring seals with keys[current] and opens with any key in keys.
func NewKeyring(current byte, keys map[byte][]byte) (*Keyring, error) {
	k := &Keyring{current: current, aeads: map[byte]cipher.AEAD{}, macKeys: map[byte][]byte{}}
	for v, key := range keys {
		if len(key) != 32 {
			return nil, fmt.Errorf("master key v%d: want 32 bytes, got %d", v, len(key))
		}
		k.macKeys[v] = hmacSHA256(key, []byte("polaris mac"))
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		if k.aeads[v], err = cipher.NewGCM(block); err != nil {
			return nil, err
		}
	}
	if k.aeads[current] == nil {
		return nil, fmt.Errorf("master key v%d not provided", current)
	}
	return k, nil
}

func (k *Keyring) Seal(plaintext, aad []byte) ([]byte, error) {
	aead := k.aeads[k.current]
	out := make([]byte, 1+aead.NonceSize(), 1+aead.NonceSize()+len(plaintext)+aead.Overhead())
	out[0] = k.current
	if _, err := rand.Read(out[1:]); err != nil {
		return nil, err
	}
	return aead.Seal(out, out[1:], plaintext, aad), nil
}

func (k *Keyring) Open(ciphertext, aad []byte) ([]byte, error) {
	if len(ciphertext) < 1 {
		return nil, errors.New("crypt: empty ciphertext")
	}
	aead := k.aeads[ciphertext[0]]
	if aead == nil {
		return nil, fmt.Errorf("crypt: no master key v%d", ciphertext[0])
	}
	if len(ciphertext) < 1+aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("crypt: ciphertext too short")
	}
	nonce, sealed := ciphertext[1:1+aead.NonceSize()], ciphertext[1+aead.NonceSize():]
	return aead.Open(nil, nonce, sealed, aad)
}

// MAC is a keyed hash of data, for a secret kept only to be recognised
// (恢复码): version(1) || HMAC-SHA256 under a key derived from the current
// master key.
func (k *Keyring) MAC(data []byte) []byte {
	return append([]byte{k.current}, hmacSHA256(k.macKeys[k.current], data)...)
}

// MACEqual reports whether mac is the MAC of data under the master key it
// names.
func (k *Keyring) MACEqual(mac, data []byte) bool {
	if len(mac) < 1 || k.macKeys[mac[0]] == nil {
		return false
	}
	return hmac.Equal(mac[1:], hmacSHA256(k.macKeys[mac[0]], data))
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
