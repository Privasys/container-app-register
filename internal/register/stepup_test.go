// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register_test

import (
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/register"
)

// The car register where a registrar approves first registrations on
// their wallet, granting or removing a registrar is approved the same
// way, and so is an erasure.
func carPackWithStepUp(t *testing.T, _ bool) []byte {
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
		"erasure": true,
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

func bindWallet(t *testing.T, h *harness, p *auth.Principal) *register.MemberWallet {
	t.Helper()
	_, _, err := h.reg.BindWallet(p, "")
	need := needsApproval(t, err)
	if !need.Bind() || need.Wallet != "" {
		t.Fatalf("a binding is approved by whichever wallet scans it: %+v", need)
	}
	b, txn, err := h.reg.BindWallet(approved(t, p, "wallet-"+p.Sub, need.OpHash), "")
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
	if b := bindWallet(t, h, registrar); b.Wallet != "wallet-registrar-1" {
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

// A member binds wallets as they would register devices: several, any
// of which approves, each removable on its own, by the member or by an
// administrator; each binding and removal is written to the member and
// to the administrators.
func TestAMemberHoldsSeveralWallets(t *testing.T) {
	doc := map[string]any{}
	if err := json.Unmarshal(carPackWithStepUp(t, false), &doc); err != nil {
		t.Fatal(err)
	}
	doc["notifications"] = []any{
		map[string]any{"on": "wallet:bound", "to": []any{map[string]any{"member": true}, map[string]any{"role": "operator"}}, "template": "wallet-bound"},
		map[string]any{"on": "wallet:removed", "to": []any{map[string]any{"member": true}}, "template": "wallet-removed"},
	}
	raw, _ := json.Marshal(doc)
	h := newHarnessWith(t, t.TempDir(), raw)
	notices := &sink{}
	h.reg.SetNoticeSink(notices)
	if _, err := h.reg.BootstrapMember("operator-1", "operator"); err != nil {
		t.Fatal(err)
	}
	for sub, name := range map[string]string{"operator-1": "Olga Operator", "registrar-1": "Ada Registrar"} {
		if _, err := h.reg.SeeIdentity(sub, sub+"@example.org", name); err != nil {
			t.Fatal(err)
		}
	}
	operator := h.principal("operator-1", "operator")
	registrar := h.principal("registrar-1", "registrar")

	bindWallet(t, h, registrar)
	sent := notices.take()
	if len(sent) != 1 || sent[0].Template != "wallet-bound" || sent[0].Member != "Ada Registrar" ||
		!slices.Equal(emails(sent[0]), []string{"operator-1@example.org", "registrar-1@example.org"}) {
		t.Fatalf("binding notices %+v", sent)
	}
	h.tick()
	_, _, err := h.reg.BindWallet(registrar, "Work phone")
	need := needsApproval(t, err)
	second, _, err := h.reg.BindWallet(approved(t, registrar, "wallet-registrar-1-b", need.OpHash), "Work phone")
	if err != nil || second.Label != "Work phone" {
		t.Fatalf("second wallet %+v %v", second, err)
	}
	if state, n, _ := h.reg.WalletState("gov", "registrar-1"); state != register.WalletBound || n != 2 {
		t.Fatalf("state %s, %d wallets", state, n)
	}
	// A wallet serves one member.
	clerk := h.principal("clerk-1", "clerk")
	_, _, err = h.reg.BindWallet(clerk, "")
	need = needsApproval(t, err)
	if _, _, err := h.reg.BindWallet(approved(t, clerk, "wallet-registrar-1-b", need.OpHash), ""); err == nil {
		t.Fatal("one wallet was bound to two members")
	}

	// Either wallet approves; the one used last is asked first.
	h.tick()
	grant := func(p *auth.Principal) error {
		_, err := h.reg.GrantRole(p, "sub-ana", "registrar", "", "Appointed.")
		return err
	}
	bindWallet(t, h, operator)
	need = needsApproval(t, grant(operator))
	if err := grant(approved(t, operator, "wallet-operator-1", need.OpHash)); err != nil {
		t.Fatal(err)
	}
	mine, err := h.reg.MyWallets(operator)
	if err != nil || len(mine) != 1 || mine[0].LastUsedAt == 0 {
		t.Fatalf("the wallet's last use is not recorded: %+v %v", mine, err)
	}

	// The member removes one of their own; an administrator removes the
	// other, with a reason, and leaves the member as they were.
	notices.take()
	h.tick()
	if _, err := h.reg.RemoveMyWallet(registrar, "wallet-registrar-1-b", ""); err != nil {
		t.Fatal(err)
	}
	if sent := notices.take(); len(sent) != 1 || sent[0].WalletLabel != "Work phone" {
		t.Fatalf("removal notices %+v", sent)
	}
	if _, err := h.reg.RemoveWallet(registrar, "registrar-1", "wallet-registrar-1", "Phone lost."); err == nil {
		t.Fatal("a registrar managed members")
	}
	if _, err := h.reg.RemoveWallet(operator, "registrar-1", "wallet-registrar-1", ""); err == nil {
		t.Fatal("removed without a reason")
	}
	list, err := h.reg.WalletBindings(operator, "registrar-1")
	if err != nil || len(list) != 1 || list[0].Name != "Ada Registrar" {
		t.Fatalf("bindings %+v %v", list, err)
	}
	if _, err := h.reg.RemoveWallet(operator, "registrar-1", "wallet-registrar-1", "Phone lost."); err != nil {
		t.Fatal(err)
	}
	if state, _, _ := h.reg.WalletState("gov", "registrar-1"); state != register.WalletNone {
		t.Fatalf("state after removing both %s", state)
	}
	if all, _ := h.reg.WalletBindings(operator, ""); len(all) != 1 || all[0].Sub != "operator-1" {
		t.Fatalf("all bindings %+v", all)
	}
}
