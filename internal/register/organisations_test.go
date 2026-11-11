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

	"github.com/Privasys/container-app-register/internal/register"
)

// The car register's pack with owners as the organisations people belong
// to: the police held by an organisation (a constabulary), the insurer by
// a firm or a person, the auditor given only by an appointment, and the
// police limited to the owners that are their own organisation. Odd for a
// car register, but the smallest pack that exercises every kind of role.
func carPackWithOrganisations(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(packPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, r := range doc["roles"].([]any) {
		role := r.(map[string]any)
		switch role["name"] {
		case "police":
			role["held"] = "organisation"
		case "insurer":
			role["held"] = "either"
		case "auditor":
			role["held"] = "appointment"
		}
	}
	doc["organisations"] = map[string]any{"class": "owner"}
	doc["scopes"] = []any{map[string]any{"class": "owner", "roles": []any{"police"}, "property": "reference"}}
	out, _ := json.Marshal(doc)
	return out
}

func recordOrganisations(t *testing.T, h *harness, refs ...string) {
	t.Helper()
	operator := h.principal("operator-1", "operator")
	for _, ref := range refs {
		h.tick()
		if _, _, err := h.reg.RecordOrganisation(operator, map[string]any{
			"reference": ref, "kind": "company", "country": "IM", "name": "Organisation " + ref,
		}); err != nil {
			t.Fatalf("record %s: %v", ref, err)
		}
	}
}

func join(t *testing.T, h *harness, inviter, sub string, req register.InviteRequest) {
	t.Helper()
	h.tick()
	as := rolesFor(inviter)
	if as == nil {
		as = roles(t, h, inviter)
	}
	inv, secret, err := h.reg.Invite(h.principal(inviter, as...), req)
	if err != nil {
		t.Fatalf("%s inviting %s: %v", inviter, sub, err)
	}
	h.tick()
	if _, _, err := h.reg.RedeemInvite("gov", sub, inv.ID, secret); err != nil {
		t.Fatalf("%s accepting: %v", sub, err)
	}
}

// rolesFor is the identity-provider role each test caller signs in with.
func rolesFor(sub string) []string {
	if strings.HasPrefix(sub, "operator") {
		return []string{"operator"}
	}
	return nil
}

func roles(t *testing.T, h *harness, sub string) []string {
	t.Helper()
	held, _, err := h.reg.GrantedRoles("gov", sub)
	if err != nil {
		t.Fatal(err)
	}
	return held
}

func TestAnOrganisationRoleIsInheritedByItsMembers(t *testing.T) {
	h := newHarnessWith(t, t.TempDir(), carPackWithOrganisations(t))
	recordOrganisations(t, h, "ORG-NORTH", "ORG-SOUTH")

	// The first person invited brings the organisation its role and
	// administers it.
	join(t, h, "operator-1", "sub-north-1", register.InviteRequest{Role: "police", Organisation: "ORG-NORTH"})
	if got := roles(t, h, "sub-north-1"); !slices.Contains(got, "police") {
		t.Fatalf("first person holds %v", got)
	}
	affs, _ := h.reg.Affiliations("gov", "sub-north-1")
	if len(affs) != 1 || !affs[0].Admin || !slices.Contains(affs[0].Roles, "police") {
		t.Fatalf("affiliation %+v", affs)
	}

	// A colleague invited by the administrator joins with no role named,
	// and inherits the organisation's.
	join(t, h, "sub-north-1", "sub-north-2", register.InviteRequest{Organisation: "ORG-NORTH"})
	if got := roles(t, h, "sub-north-2"); !slices.Contains(got, "police") {
		t.Fatalf("a colleague holds %v", got)
	}
	admin := h.principal("sub-north-1", "police")
	for name, req := range map[string]register.InviteRequest{
		"another organisation":    {Organisation: "ORG-SOUTH"},
		"a role it does not hold": {Role: "registrar", Organisation: "ORG-NORTH"},
		"no organisation":         {Role: "police"},
	} {
		if _, _, err := h.reg.Invite(admin, req); err == nil {
			t.Errorf("an administrator invited into %s", name)
		}
	}

	// The scope follows the organisation.
	listed, err := h.reg.ListObjects(h.principal("sub-north-2", "police"), register.ListFilter{Class: "owner"})
	if err != nil || len(listed) != 1 || listed[0].NaturalKey != "ORG-NORTH" {
		t.Fatalf("listed %+v %v", listed, err)
	}

	// Leaving the organisation ends the role, and withdrawing the role
	// ends it for every member.
	h.tick()
	if _, err := h.reg.RemoveFromOrganisation(admin, "ORG-NORTH", "sub-north-2", "Left the force."); err != nil {
		t.Fatal(err)
	}
	if got := roles(t, h, "sub-north-2"); slices.Contains(got, "police") {
		t.Errorf("a person who left still holds %v", got)
	}
	h.tick()
	if _, err := h.reg.WithdrawOrganisationRole(h.principal("operator-1", "operator"), "ORG-NORTH", "police", "Mandate ended."); err != nil {
		t.Fatal(err)
	}
	if got := roles(t, h, "sub-north-1"); slices.Contains(got, "police") {
		t.Errorf("after the withdrawal the administrator holds %v", got)
	}
}

func TestPersonalEitherAndAppointmentRoles(t *testing.T) {
	h := newHarnessWith(t, t.TempDir(), carPackWithOrganisations(t))
	recordOrganisations(t, h, "ORG-INSURE")
	operator := h.principal("operator-1", "operator")

	// A personal role belongs to the person, not to their organisation.
	join(t, h, "operator-1", "sub-clerk", register.InviteRequest{Role: "clerk", Organisation: "ORG-INSURE"})
	join(t, h, "operator-1", "sub-colleague", register.InviteRequest{Organisation: "ORG-INSURE"})
	if got := roles(t, h, "sub-colleague"); slices.Contains(got, "clerk") {
		t.Errorf("a colleague inherited a personal role: %v", got)
	}

	// "Either": with an organisation it is the organisation's, without one the person's.
	join(t, h, "operator-1", "sub-broker", register.InviteRequest{Role: "insurer"})
	if got, _ := h.reg.OrganisationRoles("gov", "ORG-INSURE"); slices.Contains(got, "insurer") {
		t.Errorf("an individual approval reached the organisation: %v", got)
	}
	if got := roles(t, h, "sub-broker"); !slices.Contains(got, "insurer") {
		t.Errorf("the individual holds %v", got)
	}

	// An appointment role is never given by an invitation.
	h.tick()
	if _, _, err := h.reg.Invite(operator, register.InviteRequest{Role: "auditor", Organisation: "ORG-INSURE"}); err == nil || !strings.Contains(err.Error(), "appointment") {
		t.Errorf("an appointment role was offered by invitation: %v", err)
	}
	// An organisation role needs an organisation.
	if _, _, err := h.reg.Invite(operator, register.InviteRequest{Role: "police"}); err == nil {
		t.Error("an organisation role was offered to a person alone")
	}
}

func TestJoiningMayNotBreakSeparationOfDuties(t *testing.T) {
	h := newHarnessWith(t, t.TempDir(), carPackWithOrganisations(t))
	recordOrganisations(t, h, "ORG-NORTH")
	join(t, h, "operator-1", "sub-north-1", register.InviteRequest{Role: "police", Organisation: "ORG-NORTH"})

	// Give police and clerk a conflict, then ask a clerk to join the force.
	var doc map[string]any
	_ = json.Unmarshal(carPackWithOrganisations(t), &doc)
	for _, r := range doc["roles"].([]any) {
		if role := r.(map[string]any); role["name"] == "clerk" {
			role["incompatible_with"] = []any{"police"}
		}
	}
	raw, _ := json.Marshal(doc)
	h2 := newHarnessWith(t, t.TempDir(), raw)
	recordOrganisations(t, h2, "ORG-NORTH")
	join(t, h2, "operator-1", "sub-north-1", register.InviteRequest{Role: "police", Organisation: "ORG-NORTH"})
	join(t, h2, "operator-1", "sub-clerk", register.InviteRequest{Role: "clerk"})
	h2.tick()
	inv, secret, err := h2.reg.Invite(h2.principal("sub-north-1", "police"), register.InviteRequest{Organisation: "ORG-NORTH"})
	if err != nil {
		t.Fatal(err)
	}
	h2.tick()
	if _, _, err := h2.reg.RedeemInvite("gov", "sub-clerk", inv.ID, secret); err == nil || !strings.Contains(err.Error(), "separation of duties") {
		t.Errorf("a clerk joined the force: %v", err)
	}
}

func TestOrganisationAdministrators(t *testing.T) {
	h := newHarnessWith(t, t.TempDir(), carPackWithOrganisations(t))
	recordOrganisations(t, h, "ORG-NORTH")
	join(t, h, "operator-1", "sub-north-1", register.InviteRequest{Role: "police", Organisation: "ORG-NORTH"})
	join(t, h, "sub-north-1", "sub-north-2", register.InviteRequest{Organisation: "ORG-NORTH"})
	admin := h.principal("sub-north-1", "police")

	h.tick()
	if _, err := h.reg.SetOrganisationAdmin(admin, "ORG-NORTH", "sub-north-1", false); err == nil {
		t.Error("the last administrator stepped down")
	}
	h.tick()
	if _, err := h.reg.SetOrganisationAdmin(admin, "ORG-NORTH", "sub-north-2", true); err != nil {
		t.Fatal(err)
	}
	h.tick()
	if _, err := h.reg.SetOrganisationAdmin(admin, "ORG-NORTH", "sub-north-1", false); err != nil {
		t.Errorf("with two administrators, one stepped down: %v", err)
	}
	if _, err := h.reg.OrganisationMembers(admin, "ORG-NORTH"); err == nil {
		t.Error("a former administrator listed the organisation's members")
	}
	members, err := h.reg.OrganisationMembers(h.principal("sub-north-2", "police"), "ORG-NORTH")
	if err != nil || len(members) != 2 || !slices.Contains(members[0].Roles, "police") {
		t.Fatalf("members %+v %v", members, err)
	}
}

func TestOneOrganisationOnlyWhenThePackSaysSo(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal(carPackWithOrganisations(t), &doc); err != nil {
		t.Fatal(err)
	}
	doc["organisations"] = map[string]any{"class": "owner", "single": true}
	single, _ := json.Marshal(doc)
	h := newHarnessWith(t, t.TempDir(), single)
	recordOrganisations(t, h, "ORG-NORTH", "ORG-SOUTH")
	operator := h.principal("operator-1", "operator")

	join(t, h, "operator-1", "sub-one", register.InviteRequest{Role: "police", Organisation: "ORG-NORTH"})

	// An invitation into a second organisation can be issued, since the
	// person it is for is not known until it is accepted, but not accepted.
	h.tick()
	inv, secret, err := h.reg.Invite(operator, register.InviteRequest{Role: "police", Organisation: "ORG-SOUTH"})
	if err != nil {
		t.Fatal(err)
	}
	h.tick()
	if _, _, err := h.reg.RedeemInvite("gov", "sub-one", inv.ID, secret); !errors.Is(err, register.ErrOneOrganisation) {
		t.Fatalf("joined a second organisation: %v", err)
	}
	if affs, _ := h.reg.Affiliations("gov", "sub-one"); len(affs) != 1 || affs[0].Organisation != "ORG-NORTH" {
		t.Fatalf("affiliations %+v", affs)
	}

	// The refused invitation is still open: someone else may accept it,
	// and so may the same person once they have left their organisation.
	h.tick()
	if _, err := h.reg.RemoveFromOrganisation(operator, "ORG-NORTH", "sub-one", "Moved to the south."); err != nil {
		t.Fatal(err)
	}
	h.tick()
	if _, _, err := h.reg.RedeemInvite("gov", "sub-one", inv.ID, secret); err != nil {
		t.Fatalf("after leaving: %v", err)
	}
	if affs, _ := h.reg.Affiliations("gov", "sub-one"); len(affs) != 1 || affs[0].Organisation != "ORG-SOUTH" {
		t.Fatalf("affiliations after moving %+v", affs)
	}
}

func TestSeveralOrganisationsByDefault(t *testing.T) {
	h := newHarnessWith(t, t.TempDir(), carPackWithOrganisations(t))
	recordOrganisations(t, h, "ORG-NORTH", "ORG-SOUTH")
	join(t, h, "operator-1", "sub-two", register.InviteRequest{Role: "police", Organisation: "ORG-NORTH"})
	join(t, h, "operator-1", "sub-two", register.InviteRequest{Organisation: "ORG-SOUTH"})
	if affs, _ := h.reg.Affiliations("gov", "sub-two"); len(affs) != 2 {
		t.Fatalf("affiliations %+v", affs)
	}
}
