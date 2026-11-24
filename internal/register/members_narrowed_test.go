// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register_test

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/register"
)

// The organisations pack with a clerk who manages insurers only, and a
// senior clerk who manages insurers and the police.
func carPackWithClerks(t *testing.T) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(carPackWithOrganisations(t), &doc); err != nil {
		t.Fatal(err)
	}
	doc["roles"] = append(doc["roles"].([]any),
		map[string]any{"name": "desk_clerk", "oidc_roles": []any{"register:desk_clerk"}, "permissions": []any{"members:insurer"}},
		map[string]any{"name": "senior_clerk", "oidc_roles": []any{"register:senior_clerk"},
			"permissions": []any{"members:insurer", "members:police"}})
	out, _ := json.Marshal(doc)
	return out
}

func refused(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "may not") {
		t.Errorf("%s: want a refusal, got %v", what, err)
	}
}

func TestAClerkInvitesToTheRolesItManages(t *testing.T) {
	h := newHarnessWith(t, t.TempDir(), carPackWithClerks(t))
	recordOrganisations(t, h, "ORG-NEW", "ORG-POLICE", "ORG-EMPTY")
	join(t, h, "operator-1", "sub-police", register.InviteRequest{Role: "police", Organisation: "ORG-POLICE"})
	clerk := h.principal("clerk-1", "desk_clerk")

	// Into a new organisation: the first person administers it, and the
	// organisation holds the role.
	h.tick()
	inv, secret, err := h.reg.Invite(clerk, register.InviteRequest{Role: "insurer", Organisation: "ORG-NEW"})
	if err != nil {
		t.Fatalf("a clerk inviting an insurer: %v", err)
	}
	h.tick()
	if _, _, err := h.reg.RedeemInvite("gov", "sub-insurer", inv.ID, secret); err != nil {
		t.Fatal(err)
	}
	if held, _ := h.reg.OrganisationRoles("gov", "ORG-NEW"); !slices.Contains(held, "insurer") {
		t.Errorf("the organisation holds %v", held)
	}
	affs, err := h.reg.Affiliations("gov", "sub-insurer")
	if err != nil || len(affs) != 1 || !affs[0].Admin {
		t.Errorf("the first person: %+v %v", affs, err)
	}

	// Personally, with no organisation.
	h.tick()
	if _, _, err := h.reg.Invite(clerk, register.InviteRequest{Role: "insurer"}); err != nil {
		t.Errorf("a clerk inviting a person: %v", err)
	}

	// Another role, an organisation holding one it does not manage, and an
	// invitation that would share whatever the organisation holds.
	_, _, err = h.reg.Invite(clerk, register.InviteRequest{Role: "police", Organisation: "ORG-EMPTY"})
	refused(t, "a role it does not manage", err)
	_, _, err = h.reg.Invite(clerk, register.InviteRequest{Role: "operator"})
	refused(t, "the administrator's role", err)
	_, _, err = h.reg.Invite(clerk, register.InviteRequest{Role: "insurer", Organisation: "ORG-POLICE"})
	refused(t, "an organisation holding another role", err)
	_, _, err = h.reg.Invite(clerk, register.InviteRequest{Organisation: "ORG-NEW"})
	refused(t, "an invitation naming no role", err)

	// Managing every role an organisation holds is enough.
	h.tick()
	if _, _, err := h.reg.Invite(h.principal("clerk-2", "senior_clerk"),
		register.InviteRequest{Role: "insurer", Organisation: "ORG-POLICE"}); err != nil {
		t.Errorf("a clerk managing both roles: %v", err)
	}
}

// The narrowed permission counts under the role that carries it.
func TestANarrowedPermissionNeedsItsRole(t *testing.T) {
	h := newHarnessWith(t, t.TempDir(), carPackWithClerks(t))
	both := h.principal("clerk-1", "police", "desk_clerk")
	_, _, err := h.reg.Invite(both, register.InviteRequest{Role: "insurer"})
	refused(t, "acting under another role", err)
}

// An organisation that takes on another role after the invitation was issued
// is no longer the clerk's to bring anyone into.
func TestANarrowedInvitationLapsesWhenTheOrganisationChanges(t *testing.T) {
	h := newHarnessWith(t, t.TempDir(), carPackWithClerks(t))
	recordOrganisations(t, h, "ORG-LATER")
	h.tick()
	inv, secret, err := h.reg.Invite(h.principal("clerk-1", "desk_clerk"), register.InviteRequest{Role: "insurer", Organisation: "ORG-LATER"})
	if err != nil {
		t.Fatal(err)
	}
	join(t, h, "operator-1", "sub-police", register.InviteRequest{Role: "police", Organisation: "ORG-LATER"})
	h.tick()
	if _, err := h.reg.CheckInvite("gov", inv.ID, secret); !errors.Is(err, register.ErrInvite) {
		t.Errorf("checked: %v", err)
	}
	if _, _, err := h.reg.RedeemInvite("gov", "sub-late", inv.ID, secret); !errors.Is(err, register.ErrInvite) {
		t.Errorf("redeemed: %v", err)
	}
	if held, _, _ := h.reg.GrantedRoles("gov", "sub-late"); len(held) != 0 {
		t.Errorf("the person holds %v", held)
	}
}

func TestAClerkSeesAndWithdrawsOnlyItsOwnRoles(t *testing.T) {
	h := newHarnessWith(t, t.TempDir(), carPackWithClerks(t))
	recordOrganisations(t, h, "ORG-A")
	operator := h.principal("operator-1", "operator")
	clerk := h.principal("clerk-1", "desk_clerk")
	h.tick()
	mine, _, err := h.reg.Invite(clerk, register.InviteRequest{Role: "insurer",
		To: &register.InviteRecipient{Email: "mine@example.invalid"}})
	if err != nil {
		t.Fatal(err)
	}
	h.tick()
	other, _, err := h.reg.CreateInvite(operator, "insurer", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	// Each party sees and withdraws the invitations it issued, even to a
	// role both manage.
	listed, err := h.reg.Invites(clerk)
	if err != nil || len(listed) != 1 || listed[0].ID != mine.ID || listed[0].IssuedUnder != "desk_clerk" ||
		listed[0].To == nil || listed[0].To.Email != "mine@example.invalid" {
		t.Fatalf("the clerk lists %+v %v", listed, err)
	}
	h.tick()
	_, err = h.reg.RevokeInvite(clerk, other.ID)
	refused(t, "withdrawing another party's invitation", err)
	if _, err := h.reg.RevokeInvite(clerk, mine.ID); err != nil {
		t.Errorf("withdrawing its own: %v", err)
	}
	if all, _ := h.reg.Invites(operator); len(all) != 1 || all[0].ID != other.ID {
		t.Errorf("the administrator lists %+v", all)
	}

	// Who holds a role, and taking it away with a reason.
	h.tick()
	if _, err := h.reg.GrantRole(operator, "sub-i", "insurer", "", ""); err != nil {
		t.Fatal(err)
	}
	h.tick()
	if _, err := h.reg.GrantRole(operator, "sub-r", "registrar", "", ""); err != nil {
		t.Fatal(err)
	}
	members, err := h.reg.Members(clerk)
	if err != nil || len(members) != 1 || members[0].Sub != "sub-i" {
		t.Errorf("the clerk sees members %+v %v", members, err)
	}
	_, err = h.reg.GrantRole(clerk, "sub-x", "insurer", "", "")
	refused(t, "granting directly", err)
	_, err = h.reg.RevokeRole(clerk, "sub-r", "registrar", "because")
	refused(t, "revoking another role", err)
	if _, err := h.reg.RevokeRole(clerk, "sub-i", "insurer", ""); err == nil {
		t.Error("revoked without a reason")
	}
	h.tick()
	if _, err := h.reg.RevokeRole(clerk, "sub-i", "insurer", "the licence ended"); err != nil {
		t.Errorf("revoking its role: %v", err)
	}

	// An organisation, and a role it holds.
	h.tick()
	if _, _, err := h.reg.RecordOrganisation(clerk, map[string]any{
		"reference": "ORG-CLERK", "kind": "company", "country": "FR", "name": "Recorded by a clerk",
	}); err != nil {
		t.Errorf("recording an organisation: %v", err)
	}
	join(t, h, "operator-1", "sub-a", register.InviteRequest{Role: "police", Organisation: "ORG-A"})
	_, err = h.reg.WithdrawOrganisationRole(clerk, "ORG-A", "police", "because")
	refused(t, "withdrawing another role from an organisation", err)
	_, err = h.reg.SetOrganisationAdmin(clerk, "ORG-A", "sub-a", false)
	refused(t, "administering an organisation", err)
}

func TestAPackNamesTheRolesItNarrowsTo(t *testing.T) {
	if _, err := auth.NewModel([]auth.RoleSpec{{Name: "clerk", Permissions: []string{"members:nobody"}}}); err == nil {
		t.Error("a permission over an undeclared role loaded")
	}
	if _, err := auth.NewModel([]auth.RoleSpec{{Name: "clerk", Permissions: []string{"members:*", "members:clerk"}}}); err != nil {
		t.Errorf("declared roles refused: %v", err)
	}
}
