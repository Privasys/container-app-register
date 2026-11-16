// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// issuer is an identity provider in a test: its discovery document, its
// key set, and tokens signed with its ES256 key.
type issuer struct {
	*httptest.Server
	key *ecdsa.PrivateKey
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	is := &issuer{key: key}
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"jwks_uri": is.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "use": "sig",
			"x": b64(key.PublicKey.X.FillBytes(make([]byte, 32))), "y": b64(key.PublicKey.Y.FillBytes(make([]byte, 32))),
		}}})
	})
	is.Server = httptest.NewServer(mux)
	t.Cleanup(is.Close)
	return is
}

func (is *issuer) sign(t *testing.T, typ string, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		raw, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	head := enc(map[string]any{"alg": "ES256", "typ": typ, "kid": "k1"}) + "." + enc(claims)
	sum := sha256.Sum256([]byte(head))
	r, s, err := ecdsa.Sign(rand.Reader, is.key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return head + "." + base64.RawURLEncoding.EncodeToString(sig)
}

const testApp = "0b9f1c2e-4a5d-4e6f-8a7b-9c0d1e2f3a4b"

func answerClaims(is *issuer) map[string]any {
	now := time.Now().Unix()
	return map[string]any{
		"iss": is.URL, "sub": "person-1", "aud": "approval:" + testApp, "iat": now, "exp": now + 300,
		"jti": "j1", "approval_id": "ap1", "approval_digest": strings.Repeat("a", 64),
		"act_digest": strings.Repeat("b", 64), "decision": "approve", "acr": "device",
		"amr": []any{"webauthn"}, "v": 1,
	}
}

func TestAnAnswerIsCheckedAgainstTheIdentityProvider(t *testing.T) {
	is := newIssuer(t)
	a := NewWalletApprovals(is.URL, testApp, "register-client", nil)
	ctx := context.Background()

	got, err := a.VerifyAnswer(ctx, is.sign(t, "op-approval+jwt", answerClaims(is)))
	if err != nil {
		t.Fatalf("a good answer: %v", err)
	}
	if got.Wallet != "person-1" || got.Decision != "approve" || got.ApprovalID != "ap1" || got.Receipt == "" {
		t.Fatalf("answer %+v", got)
	}
	for name, edit := range map[string]func(map[string]any){
		"another audience": func(c map[string]any) { c["aud"] = "approval:another" },
		"another version":  func(c map[string]any) { c["v"] = 2 },
		"a long life":      func(c map[string]any) { c["exp"] = c["iat"].(int64) + 3600 },
		"expired":          func(c map[string]any) { c["iat"], c["exp"] = int64(1), int64(2) },
		"no act":           func(c map[string]any) { delete(c, "act_digest") },
		"no decision":      func(c map[string]any) { c["decision"] = "maybe" },
	} {
		c := answerClaims(is)
		edit(c)
		if _, err := a.VerifyAnswer(ctx, is.sign(t, "op-approval+jwt", c)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := a.VerifyAnswer(ctx, is.sign(t, "JWT", answerClaims(is))); err == nil {
		t.Error("a token of another type was accepted")
	}
	forged := newIssuer(t)
	if _, err := a.VerifyAnswer(ctx, forged.sign(t, "op-approval+jwt", answerClaims(is))); err == nil {
		t.Error("a token signed by another key was accepted")
	}
}

func TestALinkIsCheckedAgainstItsNonce(t *testing.T) {
	is := newIssuer(t)
	a := NewWalletApprovals(is.URL, testApp, "register-client", nil)
	ctx := context.Background()
	now := time.Now().Unix()
	claims := func() map[string]any {
		return map[string]any{"iss": is.URL, "sub": "person-1", "aud": "register-client", "iat": now, "exp": now + 300,
			"nonce": "n-123", "amr": []any{"webauthn"}}
	}
	if sub, err := a.VerifyLink(ctx, is.sign(t, "JWT", claims()), "n-123", ""); err != nil || sub != "person-1" {
		t.Fatalf("a good link: %q %v", sub, err)
	}
	if _, err := a.VerifyLink(ctx, is.sign(t, "JWT", claims()), "n-other", ""); err == nil {
		t.Error("a link made for another nonce was accepted")
	}
	c := claims()
	c["amr"] = []any{"pwd"}
	if _, err := a.VerifyLink(ctx, is.sign(t, "JWT", c), "n-123", ""); err == nil {
		t.Error("a link without the wallet was accepted")
	}
	c = claims()
	c["aud"] = "another-client"
	if _, err := a.VerifyLink(ctx, is.sign(t, "JWT", c), "n-123", ""); err == nil {
		t.Error("a link for another client was accepted")
	}
}

func TestWhatTheWalletShowsIsClean(t *testing.T) {
	doc, err := approvalDocument("ap1", ApprovalRequest{
		Title:     "Approve‮: a​ record\nwith a very long title " + strings.Repeat("x", 200),
		Lines:     []ApprovalLine{{Label: "Reason", Value: "ok\u0007"}, {Label: "", Value: "dropped"}},
		ActDigest: "d", Assurance: "device", Callback: "/cb", TTL: 300,
	})
	if err != nil {
		t.Fatal(err)
	}
	var back struct {
		Title string         `json:"title"`
		Lines []ApprovalLine `json:"lines"`
		V     int            `json:"v"`
	}
	if err := json.Unmarshal([]byte(doc), &back); err != nil {
		t.Fatal(err)
	}
	if len([]rune(back.Title)) > 120 || strings.ContainsAny(back.Title, "‮​\n") || back.V != 1 {
		t.Fatalf("title %q", back.Title)
	}
	if len(back.Lines) != 1 || back.Lines[0].Value != "ok" {
		t.Fatalf("lines %+v", back.Lines)
	}
}
