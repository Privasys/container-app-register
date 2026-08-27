// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package byok

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"
)

func testKeyring(t *testing.T) *Keyring {
	t.Helper()
	var master [KeySize]byte
	if _, err := rand.Read(master[:]); err != nil {
		t.Fatal(err)
	}
	k, err := NewKeyring(master)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestOperationalWrapIsBoundToItsScope(t *testing.T) {
	ring := testKeyring(t)
	dek, err := NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := ring.WrapOperational("gov/subject/owner-1", dek)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ring.UnwrapOperational("gov/subject/owner-1", wrapped)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if got != dek {
		t.Fatal("the unwrapped key is not the key that was wrapped")
	}
	// A wrap must not be movable from one data subject to another.
	if _, err := ring.UnwrapOperational("gov/subject/owner-2", wrapped); err == nil {
		t.Fatal("a wrap opened under the wrong scope")
	}
}

func TestPayloadIsBoundToItsRecordVersion(t *testing.T) {
	dek, err := NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte(`{"name":"SPECIMEN, Alice"}`)
	ct, err := Encrypt(dek, "gov/subject/owner-1", "owner-1", 3, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(dek, ct, "owner-1", 3)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("round trip = %s", got)
	}
	if _, err := Decrypt(dek, ct, "owner-1", 4); err == nil {
		t.Error("a payload opened at the wrong version")
	}
	if _, err := Decrypt(dek, ct, "owner-2", 3); err == nil {
		t.Error("a payload opened under the wrong record")
	}
}

func TestForgettingAKeyStopsReads(t *testing.T) {
	ring := testKeyring(t)
	dek, _ := NewDEK()
	wrapped, err := ring.WrapOperational("gov/subject/owner-1", dek)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.UnwrapOperational("gov/subject/owner-1", wrapped); err != nil {
		t.Fatal(err)
	}
	ring.Forget("gov/subject/owner-1")
	// After an erasure the wrap is destroyed; the cache must not keep
	// serving what the register has just promised is gone.
	if _, err := ring.UnwrapOperational("gov/subject/owner-1", nil); err == nil {
		t.Fatal("the key survived being forgotten")
	}
}

func TestRecoveryWrapToAnX25519Key(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kek, err := ParseKEK("customer-1", AlgoX25519, priv.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	dek, _ := NewDEK()
	wrap, err := kek.WrapRecovery("gov/subject/owner-1", dek)
	if err != nil {
		t.Fatal(err)
	}

	// The customer, holding the private half, can recover the key. This
	// is the whole point of the recovery wrap: it is theirs to open, and
	// the register cannot do it for them.
	ephemeral, sealed := wrap[:32], wrap[32:]
	peer, err := ecdh.X25519().NewPublicKey(ephemeral)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := priv.ECDH(peer)
	if err != nil {
		t.Fatal(err)
	}
	derived, err := hkdf.Key(sha256.New, append(shared, ephemeral...), nil, "register/recovery-wrap/v1", KeySize)
	if err != nil {
		t.Fatal(err)
	}
	var unwrapKey [KeySize]byte
	copy(unwrapKey[:], derived)
	recovered, err := openAEAD(unwrapKey, sealed, []byte("dek:gov/subject/owner-1"))
	if err != nil {
		t.Fatalf("the customer could not open their own recovery wrap: %v", err)
	}
	if string(recovered) != string(dek[:]) {
		t.Fatal("the recovered key is not the data-encryption key")
	}
}

func TestRecoveryWrapToAnRSAKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	kek, err := ParseKEK("customer-1", AlgoRSAOAEP, spki)
	if err != nil {
		t.Fatal(err)
	}
	dek, _ := NewDEK()
	wrap, err := kek.WrapRecovery("gov/tenant", dek)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, wrap, []byte("dek:gov/tenant"))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(recovered) != string(dek[:]) {
		t.Fatal("the recovered key is not the data-encryption key")
	}
}

func TestWeakAndUnknownKeysAreRefused(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&small.PublicKey)
	if _, err := ParseKEK("weak", AlgoRSAOAEP, spki); err == nil {
		t.Error("a 1024-bit RSA key should be refused")
	}
	if _, err := ParseKEK("odd", "rot13", []byte("nope")); err == nil {
		t.Error("an unknown algorithm should be refused")
	}
	if _, err := ParseKEK("short", AlgoX25519, []byte{1, 2, 3}); err == nil {
		t.Error("a malformed X25519 key should be refused")
	}
}
