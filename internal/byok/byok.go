// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package byok implements the register's payload encryption and the
// customer-held key hierarchy above it.
//
// The confidential VM's encrypted volume already protects the register
// against the host. This layer protects it against the operator, and it
// is what makes lawful erasure provable: personal-data fields are
// encrypted under a per-scope data-encryption key, and destroying that
// key destroys the plaintext everywhere it has ever been written,
// including in backups, without touching the ledger. The record's
// commitment is to the payload hash and the ciphertext, so a record
// still verifies after its content has been erased. Absence of content
// is not absence of record.
//
// Two wraps are kept for every data-encryption key: the operational
// wrap, under a key derived from the register's sealed master secret,
// which is what the running service uses; and the recovery wrap, under
// a key-encryption key the customer enrolled and holds themselves. An
// erasure destroys both.
package byok

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
)

// KeySize is the size of every symmetric key here.
const KeySize = 32

// Wrap algorithms for a customer key-encryption key.
const (
	AlgoX25519  = "x25519"
	AlgoRSAOAEP = "rsa-oaep-sha256"
)

// Keyring derives the register's operational wrapping key from the
// sealed master secret and caches unwrapped data-encryption keys.
type Keyring struct {
	wrapKey [KeySize]byte

	mu    sync.Mutex
	cache map[string][KeySize]byte
}

// NewKeyring derives a keyring from the register's master secret.
func NewKeyring(master [KeySize]byte) (*Keyring, error) {
	k := &Keyring{cache: map[string][KeySize]byte{}}
	if err := derive(master[:], "register/dek-wrap/v1", k.wrapKey[:]); err != nil {
		return nil, err
	}
	return k, nil
}

func derive(secret []byte, info string, out []byte) error {
	key, err := hkdf.Key(sha256.New, secret, nil, info, len(out))
	if err != nil {
		return fmt.Errorf("byok: derive %s: %w", info, err)
	}
	copy(out, key)
	return nil
}

// NewDEK generates a fresh data-encryption key.
func NewDEK() ([KeySize]byte, error) {
	var dek [KeySize]byte
	if _, err := rand.Read(dek[:]); err != nil {
		return dek, fmt.Errorf("byok: generate key: %w", err)
	}
	return dek, nil
}

// WrapOperational wraps a data-encryption key for the register's own
// use. The scope is bound in as associated data, so a wrap cannot be
// moved from one scope to another.
func (k *Keyring) WrapOperational(scope string, dek [KeySize]byte) ([]byte, error) {
	return sealAEAD(k.wrapKey, dek[:], []byte("dek:"+scope))
}

// UnwrapOperational recovers a data-encryption key, caching the result.
func (k *Keyring) UnwrapOperational(scope string, wrapped []byte) ([KeySize]byte, error) {
	k.mu.Lock()
	if dek, ok := k.cache[scope]; ok {
		k.mu.Unlock()
		return dek, nil
	}
	k.mu.Unlock()

	var dek [KeySize]byte
	pt, err := openAEAD(k.wrapKey, wrapped, []byte("dek:"+scope))
	if err != nil {
		return dek, fmt.Errorf("byok: unwrap %s: %w", scope, err)
	}
	if len(pt) != KeySize {
		return dek, fmt.Errorf("byok: unwrap %s: key is %d bytes", scope, len(pt))
	}
	copy(dek[:], pt)
	k.mu.Lock()
	k.cache[scope] = dek
	k.mu.Unlock()
	return dek, nil
}

// Forget drops a scope's key from the cache. Called when the key is
// destroyed, so a live process stops being able to read what it has
// just erased.
func (k *Keyring) Forget(scope string) {
	k.mu.Lock()
	delete(k.cache, scope)
	k.mu.Unlock()
}

// KEK is an enrolled customer key-encryption key.
type KEK struct {
	ID        string `json:"id"`
	Algorithm string `json:"algo"`
	PublicKey []byte `json:"-"`
}

// ParseKEK validates an enrolled public key.
func ParseKEK(id, algo string, public []byte) (*KEK, error) {
	switch algo {
	case AlgoX25519:
		if _, err := ecdh.X25519().NewPublicKey(public); err != nil {
			return nil, fmt.Errorf("byok: x25519 public key: %w", err)
		}
	case AlgoRSAOAEP:
		pub, err := x509.ParsePKIXPublicKey(public)
		if err != nil {
			return nil, fmt.Errorf("byok: rsa public key: %w", err)
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("byok: enrolled key is not RSA")
		}
		if rsaPub.N.BitLen() < 2048 {
			return nil, fmt.Errorf("byok: RSA key is %d bits, the minimum is 2048", rsaPub.N.BitLen())
		}
	default:
		return nil, fmt.Errorf("byok: unsupported key algorithm %q", algo)
	}
	return &KEK{ID: id, Algorithm: algo, PublicKey: public}, nil
}

// WrapRecovery wraps a data-encryption key to the customer's enrolled
// key. Only the customer can undo it: the register can produce a
// recovery wrap and can destroy one, but cannot read one back.
func (kek *KEK) WrapRecovery(scope string, dek [KeySize]byte) ([]byte, error) {
	switch kek.Algorithm {
	case AlgoX25519:
		peer, err := ecdh.X25519().NewPublicKey(kek.PublicKey)
		if err != nil {
			return nil, err
		}
		eph, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		shared, err := eph.ECDH(peer)
		if err != nil {
			return nil, err
		}
		var wrapKey [KeySize]byte
		if err := derive(append(shared, eph.PublicKey().Bytes()...), "register/recovery-wrap/v1", wrapKey[:]); err != nil {
			return nil, err
		}
		sealed, err := sealAEAD(wrapKey, dek[:], []byte("dek:"+scope))
		if err != nil {
			return nil, err
		}
		return append(eph.PublicKey().Bytes(), sealed...), nil
	case AlgoRSAOAEP:
		pub, err := x509.ParsePKIXPublicKey(kek.PublicKey)
		if err != nil {
			return nil, err
		}
		return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub.(*rsa.PublicKey), dek[:], []byte("dek:"+scope))
	}
	return nil, fmt.Errorf("byok: unsupported key algorithm %q", kek.Algorithm)
}

// Ciphertext is the encrypted half of a record payload.
type Ciphertext struct {
	Algorithm string `json:"alg"`
	Scope     string `json:"scope"`
	Nonce     string `json:"nonce"`
	Data      string `json:"data"`
}

// Encrypt seals the personal-data fields of a record. The associated
// data binds the ciphertext to the exact record version it belongs to,
// so a payload cannot be lifted from one record and replayed into
// another.
func Encrypt(dek [KeySize]byte, scope, objectID string, version uint64, plaintext []byte) (*Ciphertext, error) {
	aad := fmt.Sprintf("%s|%s|%d", scope, objectID, version)
	sealed, err := sealAEAD(dek, plaintext, []byte(aad))
	if err != nil {
		return nil, err
	}
	return &Ciphertext{
		Algorithm: "AES-256-GCM",
		Scope:     scope,
		Nonce:     base64.StdEncoding.EncodeToString(sealed[:nonceSize]),
		Data:      base64.StdEncoding.EncodeToString(sealed[nonceSize:]),
	}, nil
}

// Decrypt opens a record's encrypted fields.
func Decrypt(dek [KeySize]byte, ct *Ciphertext, objectID string, version uint64) ([]byte, error) {
	if ct.Algorithm != "AES-256-GCM" {
		return nil, fmt.Errorf("byok: unsupported payload algorithm %q", ct.Algorithm)
	}
	nonce, err := base64.StdEncoding.DecodeString(ct.Nonce)
	if err != nil {
		return nil, fmt.Errorf("byok: nonce: %w", err)
	}
	data, err := base64.StdEncoding.DecodeString(ct.Data)
	if err != nil {
		return nil, fmt.Errorf("byok: ciphertext: %w", err)
	}
	aad := fmt.Sprintf("%s|%s|%d", ct.Scope, objectID, version)
	return openAEAD(dek, append(nonce, data...), []byte(aad))
}

const nonceSize = 12

func sealAEAD(key [KeySize]byte, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func openAEAD(key [KeySize]byte, sealed, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("byok: ciphertext is too short")
	}
	return gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], aad)
}
