// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/mail"
)

// Without a sender an emailed invitation is refused before anything is
// written, so nobody is told a person was written to when they were not.
func TestAnEmailedInvitationNeedsASender(t *testing.T) {
	ts, srv, reg := newTestServer(t)
	srv.TrustSession = true
	if _, err := reg.BootstrapMember("sub-olga", "operator"); err != nil {
		t.Fatal(err)
	}
	srv.Ready(reg, auth.DevVerifier{})
	status, out := call(t, ts, http.MethodPost, "/api/v1/invites", "sub-olga",
		`{"role":"operator","email":"ana@example.org","name":"Ana Quayle"}`)
	if status != http.StatusBadRequest {
		t.Fatalf("no sender: %d %v", status, out)
	}
	_, list := call(t, ts, http.MethodGet, "/api/v1/invites", "sub-olga", "")
	if got := list["invites"].([]any); len(got) != 0 {
		t.Errorf("a refused invitation was written: %v", got)
	}
	if status, _ := call(t, ts, http.MethodPost, "/api/v1/invites", "sub-olga",
		`{"role":"operator","email":"Ana <ana@example.org>"}`); status != http.StatusBadRequest {
		t.Errorf("a decorated address was accepted: %d", status)
	}
}

// The configure answer reports the sender and never its secret.
func TestConfigureNeverEchoesTheSecret(t *testing.T) {
	_, srv, _ := newTestServer(t)
	srv.ConfigureMail = func([]byte) (string, error) { return "ready", nil }
	out := map[string]any{}
	if err := srv.configureMail([]byte(`{"mail_client_secret":"shh-do-not-echo"}`), out); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(out)
	if bytes.Contains(raw, []byte("shh-do-not-echo")) || out["mail"] != "ready" {
		t.Errorf("configure answered %s", raw)
	}
	if srv.Mailer.Load() != (*mail.Mailer)(nil) {
		t.Error("no sender was stored here")
	}
}
