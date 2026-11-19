// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"regexp"
	"strings"
	"testing"
)

// The browser client is a reviewed file carried in the image. What the
// console and an adopter's pages call on it must be there, and the file must
// be the one its README names: a development sign-in hides a missing method,
// because nothing calls the client there.
func TestTheVendoredClientCarriesWhatPagesCall(t *testing.T) {
	client, err := os.ReadFile("../../ui/vendor/privasys-auth-client.iife.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{
		"connect", "getSession", "getTokenForAudience", "clearSession", "cancel", "destroy",
		"linkIdentity", // binds a wallet: POST /api/v1/me/wallets needs its id_token
	} {
		if !regexp.MustCompile(`\b` + method + `\(`).Match(client) {
			t.Errorf("the vendored client has no %s()", method)
		}
	}

	readme, err := os.ReadFile("../../ui/vendor/README.md")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(client)
	if want := hex.EncodeToString(sum[:]); !strings.Contains(string(readme), want) {
		t.Errorf("ui/vendor/README.md does not name the vendored client's SHA-256 %s", want)
	}
}
