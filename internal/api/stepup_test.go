// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
	if status, body := link(t, ts, registrar, "Phone"); status != http.StatusOK ||
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
	link(t, ts, registrar, "")
	// The stand-in binds a wallet of its own for each label, so a member
	// can hold several.
	link(t, ts, registrar, "Work phone")
	link(t, ts, operator, "")
	// A grant needing approval, sent again with the approval in the query,
	// as a transport that sets no headers does.
	_, asked := stepCall(t, ts, http.MethodPost, "/api/v1/members", operator, `{"sub": "sub-ana", "role": "registrar"}`, "")
	id, _ := asked["approval_id"].(string)
	if status, body := stepCall(t, ts, http.MethodPost, "/api/v1/members?step_up_approval="+id, operator, `{"sub": "sub-ana", "role": "registrar"}`, ""); status != http.StatusOK {
		t.Fatalf("grant with the approval in the query: %d %v", status, body)
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

// link binds a wallet the way a page does: a nonce for the session, the
// wallet's link made with it, and the identity provider's token for it
// (which the development stand-in does without).
func link(t *testing.T, ts *httptest.Server, token, label string) (int, map[string]any) {
	t.Helper()
	status, n := stepCall(t, ts, http.MethodPost, "/api/v1/me/wallets/nonce", token, "", "")
	if status != http.StatusOK || n["nonce"] == "" {
		t.Fatalf("nonce: %d %v", status, n)
	}
	body, _ := json.Marshal(map[string]any{"nonce": n["nonce"], "label": label, "id_token": "from the wallet"})
	status, out := stepCall(t, ts, http.MethodPost, "/api/v1/me/wallets", token, string(body), "")
	if status != http.StatusOK {
		t.Fatalf("link: %d %v", status, out)
	}
	// A nonce is spent once.
	if again, _ := stepCall(t, ts, http.MethodPost, "/api/v1/me/wallets", token, string(body), ""); again == http.StatusOK {
		t.Fatal("a link nonce was used twice")
	}
	return status, out
}

// fakeWallet sends nothing and answers nothing on its own: the test
// delivers the answers, as the wallet would, to the callback. Its tokens
// are the answer's fields in JSON.
type fakeWallet struct{ asked []auth.ApprovalRequest }

func (f *fakeWallet) Ask(_ context.Context, req auth.ApprovalRequest) (*auth.PendingApproval, error) {
	f.asked = append(f.asked, req)
	n := len(f.asked)
	return &auth.PendingApproval{ID: fmt.Sprintf("ap-%d", n), Digest: fmt.Sprintf("digest-%d", n),
		ExpiresAt: time.Now().Unix() + 300, PushSent: true}, nil
}

func (f *fakeWallet) VerifyAnswer(_ context.Context, token string) (*auth.Approval, error) {
	var a auth.Approval
	if err := json.Unmarshal([]byte(token), &a); err != nil {
		return nil, err
	}
	return &a, nil
}

func (f *fakeWallet) VerifyLink(_ context.Context, _, _, name string) (string, error) {
	return "wallet-" + name, nil
}

func TestTheWalletDeliversItsAnswer(t *testing.T) {
	ts, srv, reg := newTestServerWith(t, func(doc map[string]any) {
		doc["step_up"] = map[string]any{"grant_roles": []any{"registrar"}}
	})
	srv.Ready(reg, auth.DevVerifier{})
	wallet := &fakeWallet{}
	srv.Approvals.Store(&ApprovalService{Approvals: wallet})
	operator := "dev:operator-1:Operator:register:operator"
	link(t, ts, operator, "")
	grant := `{"sub": "sub-ana", "role": "registrar", "reason": "Appointed."}`

	ask := func() (id, digest string, req auth.ApprovalRequest) {
		t.Helper()
		status, body := stepCall(t, ts, http.MethodPost, "/api/v1/members", operator, grant, "")
		if status != http.StatusPreconditionRequired {
			t.Fatalf("grant: %d %v", status, body)
		}
		req = wallet.asked[len(wallet.asked)-1]
		return body["approval_id"].(string), fmt.Sprintf("digest-%d", len(wallet.asked)), req
	}
	answer := func(id, digest, act, decision, jti string) (int, map[string]any) {
		token, _ := json.Marshal(auth.Approval{
			Wallet: "wallet-operator-1", OpHash: act, ApprovalID: id, ApprovalDigest: digest, Decision: decision,
			Acr: "device", Amr: []string{"webauthn"}, ID: jti, IssuedAt: time.Now().Unix(), Receipt: "signed",
		})
		body, _ := json.Marshal(map[string]any{"approval_id": id, "decision": decision, "token": string(token)})
		return stepCall(t, ts, http.MethodPost, "/api/v1/step-up/answer", "", string(body), "")
	}
	open := func(id, digest string) int {
		status, _ := stepCall(t, ts, http.MethodGet, "/.well-known/privasys/approval?id="+id+"&digest="+digest, "", "", "")
		return status
	}

	id, digest, req := ask()
	if req.Wallet != "wallet-operator-1" || req.Callback != "/api/v1/step-up/answer" || req.Assurance != "device" ||
		len(req.ActDigest) != 64 || !strings.HasPrefix(req.Title, "Grant ") {
		t.Fatalf("approval sent %+v", req)
	}
	if open(id, digest) != http.StatusOK || open(id, "another") != http.StatusNotFound {
		t.Fatal("the wallet was not told rightly whether the approval is open")
	}
	if status, _ := answer(id, digest, strings.Repeat("0", 64), "approve", "j1"); status != http.StatusConflict {
		t.Fatalf("an answer approving another act was taken: %d", status)
	}
	// The person says no.
	if status, body := answer(id, digest, req.ActDigest, "decline", "j2"); status != http.StatusOK || body["state"] != "declined" {
		t.Fatalf("decline: %d %v", status, body)
	}
	if _, state := stepCall(t, ts, http.MethodGet, "/api/v1/step-up/"+id, operator, "", ""); state["state"] != "declined" {
		t.Fatalf("poll after a decline %v", state)
	}
	if open(id, digest) != http.StatusNotFound {
		t.Fatal("an answered approval is still open")
	}
	if status, _ := stepCall(t, ts, http.MethodPost, "/api/v1/members", operator, grant, id); status != http.StatusConflict {
		t.Fatalf("a declined approval admitted the act: %d", status)
	}

	// Asked again, and approved.
	id, digest, req = ask()
	if status, body := answer(id, digest, req.ActDigest, "approve", "j3"); status != http.StatusOK || body["state"] != "approved" {
		t.Fatalf("approve: %d %v", status, body)
	}
	status, body := stepCall(t, ts, http.MethodPost, "/api/v1/members", operator, grant, id)
	if status != http.StatusOK {
		t.Fatalf("approved grant: %d %v", status, body)
	}
	receipt := body["transaction"].(map[string]any)["envelope"].(map[string]any)["approval"].(map[string]any)
	if receipt["receipt"] != "signed" || receipt["approval_id"] != id || receipt["act_digest"] != req.ActDigest {
		t.Fatalf("the act does not keep its receipt: %v", receipt)
	}
}
