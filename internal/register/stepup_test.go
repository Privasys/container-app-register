// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register_test

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/register"
)

// The car register where a registrar approves first registrations on
// their wallet, granting or removing a registrar is approved the same
// way, and so is an erasure.
func carPackWithStepUp(t *testing.T, confirm bool) []byte {
	t.Helper()
	raw, err := os.ReadFile(packPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["step_up"] = map[string]any{
		"workflows": []any{"first_registration"}, "decisions": []any{"approve", "reject"},
		"grant_roles": []any{"registrar"}, "revoke_roles": []any{"registrar"},
		"erasure": true, "bind_confirmation": confirm,
	}
	out, _ := json.Marshal(doc)
	return out
}

// needsApproval returns the approval an act was refused for want of.
func needsApproval(t *testing.T, err error) *register.StepUpRequired {
	t.Helper()
	var need *register.StepUpRequired
	if !errors.As(err, &need) {
		t.Fatalf("expected the act to wait for an approval, got %v", err)
	}
	return need
}

// approved is the principal again, carrying an approval of hash given
// on wallet.
func approved(t *testing.T, p *auth.Principal, wallet, hash string) *auth.Principal {
	t.Helper()
	a, err := auth.DevApproval(auth.DevApprovalToken(wallet, hash))
	if err != nil {
		t.Fatal(err)
	}
	c := *p
	c.Approval = a
	return &c
}

func bindWallet(t *testing.T, h *harness, p *auth.Principal) *register.WalletBinding {
	t.Helper()
	_, _, err := h.reg.BindWallet(p)
	need := needsApproval(t, err)
	if !need.Bind() || need.Wallet != "" {
		t.Fatalf("a binding is approved by whichever wallet scans it: %+v", need)
	}
	b, txn, err := h.reg.BindWallet(approved(t, p, "wallet-"+p.Sub, need.OpHash))
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	if txn.Envelope.Kind != model.KindWalletBind || txn.Envelope.Approval == nil {
		t.Fatalf("binding transaction %+v", txn.Envelope)
	}
	return b
}

func TestADecisionWaitsForTheApproversWallet(t *testing.T) {
	h := newHarnessWith(t, t.TempDir(), carPackWithStepUp(t, false))
	clerk := h.principal("clerk-1", "clerk")
	registrar := h.principal("registrar-1", "registrar")

	// Proposing is not named, so needs nothing.
	out, err := h.reg.Propose(clerk, "first_registration", register.ProposeRequest{
		Payload:  newVehicle("VF3CCHMZ3PT000010", "CC-789-CC"),
		Evidence: map[string]string{"proof_of_conformity": strings.Repeat("a", 64)},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.tick()
	if _, err := h.reg.Decide(registrar, out.Task.ID, register.Decision{Approve: true}); !errors.Is(err, register.ErrWalletNotBound) {
		t.Fatalf("a registrar with no wallet decided: %v", err)
	}
	if b := bindWallet(t, h, registrar); b.State != register.WalletBound || b.Wallet != "wallet-registrar-1" {
		t.Fatalf("binding %+v", b)
	}

	_, err = h.reg.Decide(registrar, out.Task.ID, register.Decision{Approve: true, Reason: "Conformity checked."})
	need := needsApproval(t, err)
	if need.Wallet != "wallet-registrar-1" || !strings.HasPrefix(need.Summary, "Approve: ") {
		t.Fatalf("approval asked %+v", need)
	}
	// An approval of another decision, or given on another wallet, is
	// not this one.
	_, err = h.reg.Decide(approved(t, registrar, "wallet-registrar-1", need.OpHash), out.Task.ID,
		register.Decision{Approve: false, Reason: "Conformity checked."})
	needsApproval(t, err)
	if _, err := h.reg.Decide(approved(t, registrar, "wallet-someone-else", need.OpHash), out.Task.ID,
		register.Decision{Approve: true, Reason: "Conformity checked."}); err == nil || !strings.Contains(err.Error(), "not bound to you") {
		t.Fatalf("an approval from another wallet was accepted: %v", err)
	}

	decided, err := h.reg.Decide(approved(t, registrar, "wallet-registrar-1", need.OpHash), out.Task.ID,
		register.Decision{Approve: true, Reason: "Conformity checked."})
	if err != nil {
		t.Fatalf("approved decision: %v", err)
	}
	a := decided.Applied.Envelope.Approval
	if a == nil || a.OpHash != need.OpHash || a.Wallet != "wallet-registrar-1" || a.ID == "" {
		t.Fatalf("the decision does not record its approval: %+v", a)
	}
	if decided.Task.State != model.TaskApproved {
		t.Fatalf("task %s", decided.Task.State)
	}
}

func TestAnApprovalIsSpentOnce(t *testing.T) {
	h := newHarnessWith(t, t.TempDir(), carPackWithStepUp(t, false))
	operator := h.principal("operator-1", "operator")
	bindWallet(t, h, operator)

	grant := func(p *auth.Principal) error {
		_, err := h.reg.GrantRole(p, "sub-ana", "registrar", "", "Appointed.")
		return err
	}
	need := needsApproval(t, grant(operator))
	approval := approved(t, operator, "wallet-operator-1", need.OpHash)
	if err := grant(approval); err != nil {
		t.Fatalf("grant: %v", err)
	}
	h.tick()
	_, err := h.reg.RevokeRole(operator, "sub-ana", "registrar", "Left.")
	revoke := needsApproval(t, err)
	if _, err := h.reg.RevokeRole(approved(t, operator, "wallet-operator-1", revoke.OpHash), "sub-ana", "registrar", "Left."); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	// The same grant again, with the approval already spent.
	h.tick()
	if err := grant(approval); err == nil || !strings.Contains(err.Error(), "used already") {
		t.Fatalf("an approval was spent twice: %v", err)
	}
	// A role the pack does not name is granted as before.
	if _, err := h.reg.GrantRole(operator, "sub-ana", "clerk", "", "Hired."); err != nil {
		t.Fatalf("grant clerk: %v", err)
	}
}

func TestAnErasureWaitsForAnApproval(t *testing.T) {
	h := newHarnessWith(t, t.TempDir(), carPackWithStepUp(t, false))
	clerk := h.principal("clerk-1", "clerk")
	out, err := h.reg.Propose(clerk, "register_owner", register.ProposeRequest{Payload: map[string]any{
		"reference": "PTY-7001", "kind": "person", "country": "FR", "name": "Ada Keeper",
	}})
	if err != nil {
		t.Fatal(err)
	}
	dpo := h.principal("dpo-1", "dpo")
	bindWallet(t, h, dpo)
	req := register.ErasureRequest{ObjectID: out.ObjectID, PolicyID: "P01", Reason: "Subject request."}
	h.tick()
	_, err = h.reg.Erase(dpo, req)
	need := needsApproval(t, err)
	res, err := h.reg.Erase(approved(t, dpo, "wallet-dpo-1", need.OpHash), req)
	if err != nil {
		t.Fatalf("erase: %v", err)
	}
	if res.Transaction.Envelope.Approval == nil {
		t.Fatal("the erasure does not record its approval")
	}
}

func TestABoundWalletWaitsForConfirmation(t *testing.T) {
	h := newHarnessWith(t, t.TempDir(), carPackWithStepUp(t, true))
	operator := h.principal("operator-1", "operator")
	registrar := h.principal("registrar-1", "registrar")

	// The first binding has nobody to confirm it.
	if b := bindWallet(t, h, operator); b.State != register.WalletBound {
		t.Fatalf("first binding %+v", b)
	}
	h.tick()
	if b := bindWallet(t, h, registrar); b.State != register.WalletPendingConfirmation {
		t.Fatalf("second binding %+v", b)
	}
	if state, _ := h.reg.WalletState("gov", "registrar-1"); state != register.WalletPendingConfirmation {
		t.Fatalf("state %s", state)
	}
	// A wallet serves one member.
	_, _, err := h.reg.BindWallet(h.principal("clerk-1", "clerk"))
	need := needsApproval(t, err)
	if _, _, err := h.reg.BindWallet(approved(t, h.principal("clerk-1", "clerk"), "wallet-operator-1", need.OpHash)); err == nil {
		t.Fatal("one wallet was bound to two members")
	}

	_, err = h.reg.GrantRole(registrar, "x", "registrar", "", "")
	if err == nil {
		t.Fatal("a registrar managed members")
	}
	if _, _, err := h.reg.ConfirmWallet(registrar, "registrar-1"); err == nil {
		t.Fatal("a member confirmed their own wallet")
	}
	h.tick()
	_, _, err = h.reg.ConfirmWallet(operator, "registrar-1")
	need = needsApproval(t, err)
	b, txn, err := h.reg.ConfirmWallet(approved(t, operator, "wallet-operator-1", need.OpHash), "registrar-1")
	if err != nil || b.State != register.WalletBound || b.ConfirmedBy != "operator-1" || txn.Envelope.Approval == nil {
		t.Fatalf("confirm %+v %v", b, err)
	}

	// A lost phone: unbound, with a reason, and bound again afresh.
	h.tick()
	if _, err := h.reg.UnbindWallet(operator, "registrar-1", ""); err == nil {
		t.Fatal("unbound without a reason")
	}
	if _, err := h.reg.UnbindWallet(operator, "registrar-1", "Phone lost."); err != nil {
		t.Fatal(err)
	}
	if state, _ := h.reg.WalletState("gov", "registrar-1"); state != register.WalletNone {
		t.Fatalf("state after unbinding %s", state)
	}
	list, err := h.reg.WalletBindings(operator)
	if err != nil || len(list) != 1 || list[0].Sub != "operator-1" {
		t.Fatalf("bindings %+v %v", list, err)
	}
}
