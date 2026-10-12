// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/register"
)

// call makes a request as a person signed in over a sealed session: the
// runtime's header, and no token.
func call(t *testing.T, ts *httptest.Server, method, path, sub, payload string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+path, strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if payload != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if sub != "" {
		req.Header.Set("X-Privasys-Sub", sub)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var decoded map[string]any
	_ = json.Unmarshal(body, &decoded)
	return resp.StatusCode, decoded
}

// splitLink takes "/#/join/<id>/<secret>" apart.
func splitLink(t *testing.T, link any) (id, secret string) {
	t.Helper()
	parts := strings.Split(strings.TrimPrefix(link.(string), "/#/join/"), "/")
	if len(parts) != 2 {
		t.Fatalf("invitation link %q", link)
	}
	return parts[0], parts[1]
}

// The whole journey a deployment takes: the configure call names nobody
// it could know, hands back one invitation, and from there every role in
// the register is held because a named person granted it.
func TestMembershipFromTheFirstInvitation(t *testing.T) {
	ts, srv, reg := newTestServer(t)
	srv.TrustSession = true
	out := map[string]any{}
	if err := bootstrapMembers(reg, []byte(`{"admin_invite":true}`), out); err != nil {
		t.Fatal(err)
	}
	srv.Ready(reg, auth.DevVerifier{})
	if out["admin_role"] != "operator" {
		t.Fatalf("the first administrator would be %v, want the role that manages members", out["admin_role"])
	}
	id, secret := splitLink(t, out["admin_invite"])

	// Signed in, and holding nothing: known to the register, and told so.
	status, me := call(t, ts, http.MethodGet, "/api/v1/me", "sub-olga", "")
	if status != http.StatusOK || me["status"] != "no_role" {
		t.Fatalf("me before any grant = %d %v", status, me)
	}
	if status, _ := call(t, ts, http.MethodGet, "/api/v1/status", "sub-olga", ""); status != http.StatusForbidden {
		t.Errorf("a person with no role read the status: %d, want 403", status)
	}
	if status, _ := call(t, ts, http.MethodGet, "/api/v1/me", "", ""); status != http.StatusUnauthorized {
		t.Errorf("nobody at all = %d, want 401", status)
	}

	// A wrong secret and an unknown invitation get the same answer.
	wrong := `{"secret":"` + strings.Repeat("A", 43) + `"}`
	if status, _ := call(t, ts, http.MethodPost, "/api/v1/invites/"+id+"/redeem", "sub-olga", wrong); status != http.StatusGone {
		t.Errorf("wrong secret = %d, want 410", status)
	}
	if status, _ := call(t, ts, http.MethodPost, "/api/v1/invites/0000000000000000/redeem", "sub-olga", wrong); status != http.StatusGone {
		t.Errorf("unknown invitation = %d, want 410", status)
	}

	good := `{"secret":"` + secret + `"}`
	if status, body := call(t, ts, http.MethodPost, "/api/v1/invites/"+id+"/check", "sub-olga", good); status != http.StatusOK || body["role"] != "operator" {
		t.Fatalf("check = %d %v", status, body)
	}
	if status, body := call(t, ts, http.MethodPost, "/api/v1/invites/"+id+"/redeem", "sub-olga", good); status != http.StatusOK {
		t.Fatalf("redeem = %d %v", status, body)
	}
	// Single use.
	if status, _ := call(t, ts, http.MethodPost, "/api/v1/invites/"+id+"/redeem", "sub-mallory", good); status != http.StatusGone {
		t.Errorf("a spent invitation = %d, want 410", status)
	}

	status, me = call(t, ts, http.MethodGet, "/api/v1/me", "sub-olga", "")
	if status != http.StatusOK || me["status"] != "member" {
		t.Fatalf("me after redeeming = %d %v", status, me)
	}

	// The configure call runs on every restart. It must not mint a
	// second invitation once somebody administers the register.
	again := map[string]any{}
	if err := bootstrapMembers(reg, []byte(`{"admin_invite":true}`), again); err != nil {
		t.Fatal(err)
	}
	if _, minted := again["admin_invite"]; minted {
		t.Error("a second configure call minted another administrator invitation")
	}

	// Olga grants Rita the registrar role, by subject.
	grant := `{"sub":"sub-rita","role":"registrar","display":"Rita","reason":"Head of registrations."}`
	if status, body := call(t, ts, http.MethodPost, "/api/v1/members", "sub-olga", grant); status != http.StatusOK {
		t.Fatalf("grant = %d %v", status, body)
	}
	if status, _ := call(t, ts, http.MethodGet, "/api/v1/records?class=vehicle", "sub-rita", ""); status != http.StatusOK {
		t.Errorf("the new registrar could not read records: %d", status)
	}
	// Rita may not manage members: she holds no role that says so.
	if status, _ := call(t, ts, http.MethodGet, "/api/v1/members", "sub-rita", ""); status != http.StatusForbidden {
		t.Errorf("a registrar listed the members: %d, want 403", status)
	}

	// Separation of duties is refused at the grant, not discovered at
	// the next sign-in.
	clerk := `{"sub":"sub-rita","role":"clerk"}`
	if status, body := call(t, ts, http.MethodPost, "/api/v1/members", "sub-olga", clerk); status != http.StatusForbidden {
		t.Errorf("registrar and clerk together = %d %v, want 403", status, body)
	}

	// The last person who can manage membership cannot be removed.
	if status, _ := call(t, ts, http.MethodDelete, "/api/v1/members/sub-olga/operator", "sub-olga", ""); status != http.StatusConflict {
		t.Errorf("revoking the only administrator = %d, want 409", status)
	}

	// An invitation that was withdrawn is as dead as one that was used.
	status, body := call(t, ts, http.MethodPost, "/api/v1/invites", "sub-olga", `{"role":"auditor","label":"Court of auditors"}`)
	if status != http.StatusOK {
		t.Fatalf("invite = %d %v", status, body)
	}
	aid, asecret := splitLink(t, body["link"])
	if status, _ := call(t, ts, http.MethodDelete, "/api/v1/invites/"+aid, "sub-olga", ""); status != http.StatusOK {
		t.Fatalf("withdraw = %d", status)
	}
	if status, _ := call(t, ts, http.MethodPost, "/api/v1/invites/"+aid+"/redeem", "sub-anna", `{"secret":"`+asecret+`"}`); status != http.StatusGone {
		t.Errorf("a withdrawn invitation = %d, want 410", status)
	}

	// Every one of those was a transaction, with an author and a reason.
	status, log := call(t, ts, http.MethodGet, "/api/v1/log?kind=member.grant", "sub-olga", "")
	if status != http.StatusOK {
		t.Fatalf("log = %d %v", status, log)
	}
	entries, _ := log["transactions"].([]any)
	if len(entries) != 1 {
		t.Fatalf("member.grant transactions = %d, want 1", len(entries))
	}
	envelope := entries[0].(map[string]any)["envelope"].(map[string]any)
	if author := envelope["author"].(map[string]any); author["sub"] != "sub-olga" {
		t.Errorf("the grant is recorded as made by %v", author["sub"])
	}
	if !strings.Contains(envelope["message"].(string), "Head of registrations.") {
		t.Errorf("the grant's reason is not in its message: %q", envelope["message"])
	}

	// The invitation's secret is not in the log; only its hash went in.
	_, all := call(t, ts, http.MethodGet, "/api/v1/log?limit=200", "sub-olga", "")
	raw, _ := json.Marshal(all)
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), asecret) {
		t.Error("an invitation secret is readable in the transaction log")
	}
}

// Off the platform nothing strips the session header from an inbound
// request, so the register must not believe it.
func TestSessionHeaderIsNotBelievedOffThePlatform(t *testing.T) {
	ts, srv, reg := newTestServer(t)
	srv.Ready(reg, auth.DevVerifier{})
	if _, err := reg.BootstrapMember("sub-olga", "operator"); err != nil {
		t.Fatal(err)
	}
	if status, _ := call(t, ts, http.MethodGet, "/api/v1/me", "sub-olga", ""); status != http.StatusUnauthorized {
		t.Errorf("a forged session header was accepted: %d, want 401", status)
	}
}

// The configure call, as the platform makes it: once to bring the
// register up, and again whenever the deployer wants to name somebody.
// The second call must leave a running register running.
func TestConfigureNamesAdministratorsAndCanBeRepeated(t *testing.T) {
	ts, srv, reg := newTestServer(t)
	opened := 0
	srv.Configure = func([]byte) (*register.Register, auth.Verifier, error) {
		opened++
		return reg, auth.DevVerifier{}, nil
	}

	if status, _ := get(t, ts, "/readiness", ""); status != http.StatusServiceUnavailable {
		t.Errorf("readiness before configuration = %d, want 503", status)
	}
	status, body := post(t, ts, "/configure", "", `{"tenant":"gov","admin_invite":true}`)
	if status != http.StatusOK || body["status"] != "configured" {
		t.Fatalf("configure = %d %v", status, body)
	}
	if _, ok := body["admin_invite"].(string); !ok {
		t.Fatalf("a new register handed back no administrator invitation: %v", body)
	}
	if status, _ := get(t, ts, "/readiness", ""); status != http.StatusOK {
		t.Errorf("readiness after configuration = %d, want 200", status)
	}

	status, body = post(t, ts, "/configure", "", `{"tenant":"gov","admins":"sub-olga, sub-omar"}`)
	if status != http.StatusOK || body["status"] != "already_configured" {
		t.Fatalf("second configure = %d %v", status, body)
	}
	if body["admins_added"] != float64(2) {
		t.Errorf("admins_added = %v, want 2", body["admins_added"])
	}
	if opened != 1 {
		t.Errorf("the register was opened %d times, want once", opened)
	}
	// Naming the same people again changes nothing and fails nothing.
	if _, body = post(t, ts, "/configure", "", `{"admins":"sub-olga"}`); body["admins_added"] != float64(0) {
		t.Errorf("a repeated grant was counted: %v", body)
	}
	if status, _ := get(t, ts, "/api/v1/status", registrarToken); status != http.StatusOK {
		t.Errorf("the register stopped serving after a second configure call: %d", status)
	}
}
