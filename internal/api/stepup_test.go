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
)

func stepCall(t *testing.T, ts *httptest.Server, method, path, token, payload, approval string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+path, strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if payload != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if approval != "" {
		req.Header.Set(StepUpHeader, approval)
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

// approve follows an act refused for want of an approval: the page polls
// until the person has approved, then sends the act again.
func approve(t *testing.T, ts *httptest.Server, method, path, token, payload string) (int, map[string]any) {
	t.Helper()
	status, body := stepCall(t, ts, method, path, token, payload, "")
	if status != http.StatusPreconditionRequired || body["error"] != "step_up_required" {
		t.Fatalf("%s %s: expected 428, got %d %v", method, path, status, body)
	}
	id, _ := body["approval_id"].(string)
	if id == "" || body["push_sent"] != true || body["summary"] == "" {
		t.Fatalf("approval asked %v", body)
	}
	if status, state := stepCall(t, ts, http.MethodGet, "/api/v1/step-up/"+id, token, "", ""); status != http.StatusOK || state["state"] != "approved" {
		t.Fatalf("poll: %d %v", status, state)
	}
	status, body = stepCall(t, ts, method, path, token, payload, id)
	// The approval is spent: sent once more, it is refused.
	if again, _ := stepCall(t, ts, method, path, token, payload, id); again != http.StatusConflict {
		t.Fatalf("an approval was used twice: %d", again)
	}
	return status, body
}

func TestAnActWaitsForTheWalletOverHTTP(t *testing.T) {
	ts, srv, reg := newTestServerWith(t, func(doc map[string]any) {
		doc["step_up"] = map[string]any{"workflows": []any{"first_registration"}}
	})
	srv.Ready(reg, auth.DevVerifier{})
	srv.Approvals.Store(&ApprovalService{Approvals: auth.DevApprovals{}})
	clerk := "dev:clerk-1:Clerk:register:clerk"
	registrar := "dev:registrar-1:Registrar:register:registrar"

	status, out := stepCall(t, ts, http.MethodPost, "/api/v1/workflows/first_registration/propose", clerk, `{
		"payload": {"vin": "VF3CCHMZ3PT000010", "make": "Peugeot", "model": "208", "year": 2024, "colour": "red",
			"fuel": "petrol", "engine_cc": 1199, "first_registration": "2024-06-01", "plate": "CC-789-CC"},
		"evidence": {"proof_of_conformity": "`+strings.Repeat("a", 64)+`"}}`, "")
	if status != http.StatusOK {
		t.Fatalf("propose: %d %v", status, out)
	}
	task := out["task"].(map[string]any)["id"].(string)
	decide := "/api/v1/tasks/" + task + "/decide"

	if status, body := stepCall(t, ts, http.MethodPost, decide, registrar, `{"approve": true}`, ""); status != http.StatusPreconditionFailed || body["detail"] != "wallet_not_bound" {
		t.Fatalf("no wallet: %d %v", status, body)
	}
	if _, me := stepCall(t, ts, http.MethodGet, "/api/v1/me", registrar, "", ""); me["step_up"] != true ||
		me["wallet"].(map[string]any)["state"] != "none" {
		t.Fatalf("me before binding: %v", me)
	}
	if status, body := approve(t, ts, http.MethodPost, "/api/v1/me/wallets", registrar, `{"label": "Phone"}`); status != http.StatusOK ||
		body["wallet"].(map[string]any)["wallet"] != "dev-wallet:registrar-1:Phone" {
		t.Fatalf("bind: %d %v", status, body)
	}
	if _, me := stepCall(t, ts, http.MethodGet, "/api/v1/me", registrar, "", ""); me["wallet"].(map[string]any)["state"] != "bound" {
		t.Fatalf("me after binding: %v", me)
	}

	// Someone else cannot carry the registrar's approval.
	status, body := stepCall(t, ts, http.MethodPost, decide, registrar, `{"approve": true}`, "")
	if status != http.StatusPreconditionRequired {
		t.Fatalf("decide: %d %v", status, body)
	}
	if status, _ := stepCall(t, ts, http.MethodGet, "/api/v1/step-up/"+body["approval_id"].(string), clerk, "", ""); status == http.StatusOK {
		t.Fatal("another person polled the registrar's approval")
	}

	status, body = approve(t, ts, http.MethodPost, decide, registrar, `{"approve": true}`)
	if status != http.StatusOK {
		t.Fatalf("approved decision: %d %v", status, body)
	}
	approval := body["applied"].(map[string]any)["envelope"].(map[string]any)["approval"].(map[string]any)
	if approval["wallet"] != "dev-wallet:registrar-1:Phone" || approval["op_hash"] == "" {
		t.Fatalf("approval recorded %v", approval)
	}
}

func TestMembersSeeAndRemoveTheirWalletsOverHTTP(t *testing.T) {
	ts, srv, reg := newTestServerWith(t, func(doc map[string]any) {
		doc["step_up"] = map[string]any{"grant_roles": []any{"registrar"}}
	})
	srv.Ready(reg, auth.DevVerifier{})
	srv.Approvals.Store(&ApprovalService{Approvals: auth.DevApprovals{}})
	registrar := "dev:registrar-1:Registrar:register:registrar"
	operator := "dev:operator-1:Operator:register:operator"
	approve(t, ts, http.MethodPost, "/api/v1/me/wallets", registrar, "")
	// The stand-in binds a wallet of its own for each label, so a member
	// can hold several.
	approve(t, ts, http.MethodPost, "/api/v1/me/wallets", registrar, `{"label": "Work phone"}`)
	// A transport that sets no headers names the approval in the query.
	_, asked := stepCall(t, ts, http.MethodPost, "/api/v1/me/wallets", operator, "", "")
	id, _ := asked["approval_id"].(string)
	stepCall(t, ts, http.MethodGet, "/api/v1/step-up/"+id, operator, "", "")
	if status, body := stepCall(t, ts, http.MethodPost, "/api/v1/me/wallets?step_up_approval="+id, operator, "", ""); status != http.StatusOK {
		t.Fatalf("bind with the approval in the query: %d %v", status, body)
	}

	status, mine := stepCall(t, ts, http.MethodGet, "/api/v1/me/wallets", registrar, "", "")
	if status != http.StatusOK || len(mine["wallets"].([]any)) != 2 {
		t.Fatalf("my wallets: %d %v", status, mine)
	}
	if status, _ := stepCall(t, ts, http.MethodGet, "/api/v1/wallet-bindings?member=registrar-1", registrar, "", ""); status != http.StatusForbidden {
		t.Fatalf("a registrar listed bindings: %d", status)
	}
	status, list := stepCall(t, ts, http.MethodGet, "/api/v1/wallet-bindings?member=registrar-1", operator, "", "")
	if status != http.StatusOK || len(list["wallets"].([]any)) != 2 {
		t.Fatalf("bindings: %d %v", status, list)
	}
	if status, body := stepCall(t, ts, http.MethodDelete, "/api/v1/wallet-bindings/registrar-1/dev-wallet:registrar-1?reason=Phone+lost", operator, "", ""); status != http.StatusOK {
		t.Fatalf("remove: %d %v", status, body)
	}
	if status, body := stepCall(t, ts, http.MethodDelete, "/api/v1/me/wallets/dev-wallet:operator-1", operator, "", ""); status != http.StatusOK {
		t.Fatalf("remove my own: %d %v", status, body)
	}
	if _, me := stepCall(t, ts, http.MethodGet, "/api/v1/me", operator, "", ""); me["wallet"].(map[string]any)["state"] != "none" {
		t.Fatalf("me %v", me)
	}
}
