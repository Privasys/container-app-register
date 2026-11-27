// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package auth

import (
	"context"
	"testing"
	"time"
)

const thisApp = "app:0b9f1c2e4a5d4e6f8a7b9c0d1e2f3a4b"

func accessClaims(is *issuer, aud any) map[string]any {
	now := time.Now().Unix()
	c := map[string]any{"iss": is.URL, "sub": "person-1", "iat": now, "exp": now + 300, "typ": "at+jwt"}
	if aud != nil {
		c["aud"] = aud
	}
	return c
}

func TestABearerTokenIsForThisAppAndNoOther(t *testing.T) {
	is := newIssuer(t)
	v := NewJWKSVerifier(is.URL, thisApp)
	ctx := context.Background()

	if id, err := v.Verify(ctx, is.sign(t, "JWT", accessClaims(is, thisApp))); err != nil || id.Sub != "person-1" {
		t.Fatalf("a token for this app: %+v %v", id, err)
	}
	if _, err := v.Verify(ctx, is.sign(t, "JWT", accessClaims(is, []any{"other", thisApp}))); err != nil {
		t.Errorf("a token naming this app among others: %v", err)
	}
	if _, err := v.Verify(ctx, is.sign(t, "at+jwt", accessClaims(is, thisApp))); err != nil {
		t.Errorf("an at+jwt header: %v", err)
	}

	for what, aud := range map[string]any{
		"another app":           "app:ffffffffffffffffffffffffffffffff",
		"the platform audience": "privasys-platform",
		"no audience":           nil,
		"this app's approvals":  "approval:0b9f1c2e-4a5d-4e6f-8a7b-9c0d1e2f3a4b",
	} {
		if _, err := v.Verify(ctx, is.sign(t, "JWT", accessClaims(is, aud))); err == nil {
			t.Errorf("a token for %s was accepted", what)
		}
	}
}

func TestOnlyAnAccessTokenSignsIn(t *testing.T) {
	is := newIssuer(t)
	v := NewJWKSVerifier(is.URL, thisApp)
	ctx := context.Background()

	noTyp := accessClaims(is, thisApp)
	delete(noTyp, "typ")
	otherTyp := accessClaims(is, thisApp)
	otherTyp["typ"] = "op-approval+jwt"
	noExp := accessClaims(is, thisApp)
	delete(noExp, "exp")
	for what, token := range map[string]string{
		"no typ claim":         is.sign(t, "JWT", noTyp),
		"another typ claim":    is.sign(t, "JWT", otherTyp),
		"an approval's header": is.sign(t, "op-approval+jwt", accessClaims(is, thisApp)),
		"no expiry":            is.sign(t, "JWT", noExp),
	} {
		if _, err := v.Verify(ctx, token); err == nil {
			t.Errorf("a token with %s was accepted", what)
		}
	}
}

func TestAVerifierWithNoAudienceAcceptsNothing(t *testing.T) {
	is := newIssuer(t)
	if _, err := NewJWKSVerifier(is.URL, "").Verify(context.Background(), is.sign(t, "JWT", accessClaims(is, thisApp))); err == nil {
		t.Error("a verifier with no audience accepted a token")
	}
}
