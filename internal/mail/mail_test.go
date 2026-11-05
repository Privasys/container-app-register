// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package mail

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testMailer(t *testing.T, graph http.HandlerFunc) *Mailer {
	t.Helper()
	dir := t.TempDir()
	tpl := `<html><head><title>{{if .Reminder}}Expires soon{{else}}Invited &amp; welcome{{end}}</title></head>` +
		`<body>{{.RecipientName}} {{.AcceptURL}} {{.ExpiresOn}}{{if .TestNotice}} TEST{{end}}</body></html>`
	if err := os.WriteFile(filepath.Join(dir, "invitation.html"), []byte(tpl), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := New(Settings{
		TenantID: "tenant", ClientID: "client", ClientSecret: "shh", Sender: "register@example.org",
		BaseURL: "https://register.example.org/",
	}, dir)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(graph)
	t.Cleanup(ts.Close)
	m.loginURL, m.graphURL = ts.URL, ts.URL
	return m
}

func TestSendInvitationThroughGraph(t *testing.T) {
	tokens := 0
	var sent map[string]any
	var auth, path string
	m := testMailer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
			tokens++
			raw, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(raw))
			if form.Get("scope") != "https://graph.microsoft.com/.default" || form.Get("grant_type") != "client_credentials" ||
				form.Get("client_secret") != "shh" || r.URL.Path != "/tenant/oauth2/v2.0/token" {
				t.Errorf("token request %s %v", r.URL.Path, form)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 3600})
			return
		}
		auth, path = r.Header.Get("Authorization"), r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&sent)
		w.WriteHeader(http.StatusAccepted)
	})
	inv := Invitation{To: "ana@example.org", Name: "Ana", Link: "/workspace/join/abc#s3cret", ExpiresAt: time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC).Unix()}
	for range 2 {
		if err := m.SendInvitation(context.Background(), inv); err != nil {
			t.Fatal(err)
		}
	}
	if tokens != 1 {
		t.Errorf("asked for %d tokens, want the one kept", tokens)
	}
	if auth != "Bearer tok" || path != "/v1.0/users/register@example.org/sendMail" {
		t.Errorf("sent with %q to %q", auth, path)
	}
	if sent["saveToSentItems"] != false {
		t.Errorf("a message with a live link would stay in Sent Items: %v", sent["saveToSentItems"])
	}
	msg := sent["message"].(map[string]any)
	if msg["subject"] != "Invited & welcome" {
		t.Errorf("subject %q", msg["subject"])
	}
	body := msg["body"].(map[string]any)["content"].(string)
	for _, want := range []string{"Ana", "https://register.example.org/workspace/join/abc#s3cret", "19 November 2026", "TEST"} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q: %s", want, body)
		}
	}
}

// A refusal may quote the message, and the message holds a live link.
func TestARefusalNamesOnlyTheCode(t *testing.T) {
	m := testMailer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 3600})
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"ErrorAccessDenied","message":"ana@example.org s3cret"}}`))
	})
	err := m.SendInvitation(context.Background(), Invitation{To: "ana@example.org", Link: "/workspace/join/abc#s3cret"})
	if err == nil || !strings.Contains(err.Error(), "ErrorAccessDenied") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "s3cret") || strings.Contains(err.Error(), "ana@") {
		t.Errorf("the error carries the message: %v", err)
	}
}

func TestAddressesAreBare(t *testing.T) {
	for addr, want := range map[string]bool{
		"ana@example.org": true, "Ana <ana@example.org>": false, "a@b.org, c@d.org": false, "": false, "ana": false,
	} {
		if ValidAddress(addr) != want {
			t.Errorf("ValidAddress(%q) = %v", addr, !want)
		}
	}
}

func TestSettingsSurviveARestartAndKeepTheSecret(t *testing.T) {
	dir := t.TempDir()
	if held, err := LoadSettings(dir); err != nil || held != nil {
		t.Fatalf("empty volume: %v %v", held, err)
	}
	if err := SaveSettings(dir, Settings{ClientSecret: "shh", Sender: "a@b.org"}); err != nil {
		t.Fatal(err)
	}
	held, err := LoadSettings(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := (Settings{Sender: "new@b.org"}).Merge(*held); got.ClientSecret != "shh" || got.Sender != "new@b.org" {
		t.Errorf("merged %+v", got)
	}
}
