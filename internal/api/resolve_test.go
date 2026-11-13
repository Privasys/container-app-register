// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/register"
)

// An identifier resolves to its record's page; another case or missing
// hyphens go to its written form; wrong check digits are a 400.
func TestAnIdentifierResolves(t *testing.T) {
	ts, srv, reg := newTestServerWith(t, func(p map[string]any) {
		for _, c := range p["classes"].([]any) {
			if class := c.(map[string]any); class["name"] == "owner" {
				class["identifiers"] = []any{map[string]any{"property": "reference", "format": "OWN-{year}-{serial:6}-{check}"}}
			}
		}
	})
	srv.Ready(reg, auth.DevVerifier{})
	good := "OWN-2026-7K3QX9-" + register.Check97("OWN20267K3QX9")
	client := ts.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	get := func(path string) *http.Response {
		resp, err := client.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	if resp := get("/id/reference/" + good); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/public/v1/owner/"+good {
		t.Errorf("canonical: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp := get("/id/reference/" + strings.ToLower(strings.ReplaceAll(good, "-", ""))); resp.StatusCode != http.StatusPermanentRedirect || resp.Header.Get("Location") != "/id/reference/"+good {
		t.Errorf("as typed: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	bad := good[:len(good)-1] + string("0123456789"[(int(good[len(good)-1]-'0')+1)%10])
	if resp := get("/id/reference/" + bad); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("wrong check digits: %d", resp.StatusCode)
	}
	if resp := get("/id/nothing/" + good); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown identifier: %d", resp.StatusCode)
	}
}
