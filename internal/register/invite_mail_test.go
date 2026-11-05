// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register_test

import (
	"testing"
	"time"

	"github.com/Privasys/container-app-register/internal/register"
)

func TestAnEmailedInvitationIsSealedAndRemindedOnce(t *testing.T) {
	h := newHarness(t)
	h.tick()
	operator := h.principal("operator-1", "operator")
	to := register.InviteRecipient{Email: "canary.invited@example.invalid", Name: "CANARY Invited", Organisation: "CANARY Firm"}
	inv, secret, err := h.reg.CreateEmailedInvite(operator, "registrar", 14*24*time.Hour, to)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{to.Email, to.Name, to.Organisation, secret} {
		if leaks := leaksIn(t, h, needle); len(leaks) != 0 {
			t.Errorf("%q is in the clear in %d ledger leaves: %v", needle, len(leaks), leaks)
		}
	}

	if due, err := h.reg.InviteReminders(); err != nil || len(due) != 0 {
		t.Fatalf("reminders before their time: %v %v", due, err)
	}

	h.now = h.now.Add(register.RemindAfter + time.Minute)
	due, err := h.reg.InviteReminders()
	if err != nil || len(due) != 1 {
		t.Fatalf("reminders = %v %v", due, err)
	}
	if got := due[0].To; got.Email != to.Email || got.Name != to.Name || got.Secret != secret {
		t.Errorf("the reminder opened as %+v", got)
	}
	if err := h.reg.MarkReminded(inv.ID); err != nil {
		t.Fatal(err)
	}
	if due, _ := h.reg.InviteReminders(); len(due) != 0 {
		t.Errorf("reminded twice: %v", due)
	}
}

// Whichever way an invitation finishes, its recipient goes with it.
func TestAFinishedInvitationForgetsItsRecipient(t *testing.T) {
	for name, finish := range map[string]func(*harness, *register.Invite, string) error{
		"accepted": func(h *harness, inv *register.Invite, secret string) error {
			_, _, err := h.reg.RedeemInvite(h.principal("operator-1", "operator").Tenant, "sub-new", inv.ID, secret)
			return err
		},
		"withdrawn": func(h *harness, inv *register.Invite, _ string) error {
			_, err := h.reg.RevokeInvite(h.principal("operator-1", "operator"), inv.ID)
			return err
		},
		"expired": func(h *harness, _ *register.Invite, _ string) error {
			h.now = h.now.Add(15 * 24 * time.Hour)
			n, err := h.reg.ForgetExpiredRecipients()
			if err == nil && n != 1 {
				t.Errorf("forgot %d recipients, want 1", n)
			}
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.tick()
			operator := h.principal("operator-1", "operator")
			inv, secret, err := h.reg.CreateEmailedInvite(operator, "registrar", 14*24*time.Hour,
				register.InviteRecipient{Email: "gone@example.invalid"})
			if err != nil {
				t.Fatal(err)
			}
			h.tick()
			if err := finish(h, inv, secret); err != nil {
				t.Fatal(err)
			}
			h.now = h.now.Add(register.RemindAfter)
			if due, err := h.reg.InviteReminders(); err != nil || len(due) != 0 {
				t.Errorf("still remindable: %v %v", due, err)
			}
			if n, err := h.reg.ForgetExpiredRecipients(); err != nil || n != 0 {
				t.Errorf("forgotten again: %d %v", n, err)
			}
		})
	}
}

func TestAnOpenInvitationIsNotForgotten(t *testing.T) {
	h := newHarness(t)
	h.tick()
	operator := h.principal("operator-1", "operator")
	if _, _, err := h.reg.CreateEmailedInvite(operator, "registrar", 14*24*time.Hour,
		register.InviteRecipient{Email: "open@example.invalid"}); err != nil {
		t.Fatal(err)
	}
	if n, err := h.reg.ForgetExpiredRecipients(); err != nil || n != 0 {
		t.Fatalf("forgot an open invitation: %d %v", n, err)
	}
}
