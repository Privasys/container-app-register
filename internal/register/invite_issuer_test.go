// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register_test

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/Privasys/container-app-register/internal/register"
)

// The organisations pack with two overseers of invitations, one cleared for
// personal data.
func carPackWithOverseers(t *testing.T) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(carPackWithOrganisations(t), &doc); err != nil {
		t.Fatal(err)
	}
	doc["roles"] = append(doc["roles"].([]any),
		map[string]any{"name": "overseer", "oidc_roles": []any{"register:overseer"}, "permissions": []any{"invitations"}},
		map[string]any{"name": "overseer_pii", "oidc_roles": []any{"register:overseer_pii"}, "permissions": []any{"invitations"}, "pii": true})
	out, _ := json.Marshal(doc)
	return out
}

func ids(invites []*register.Invite) []string {
	out := make([]string, 0, len(invites))
	for _, inv := range invites {
		out = append(out, inv.ID)
	}
	slices.Sort(out)
	return out
}

func sorted(s ...string) []string { slices.Sort(s); return s }

func TestEachPartySeesTheInvitationsItIssued(t *testing.T) {
	h := newHarnessWith(t, t.TempDir(), carPackWithOverseers(t))
	recordOrganisations(t, h, "ORG-NORTH")
	operator := h.principal("operator-1", "operator")

	// The fleet's first person joins on the operator's invitation, and
	// administers it.
	h.tick()
	first, secret, err := h.reg.Invite(operator, register.InviteRequest{Role: "police", Organisation: "ORG-NORTH"})
	if err != nil {
		t.Fatal(err)
	}
	h.tick()
	if _, _, err := h.reg.RedeemInvite("gov", "sub-north-1", first.ID, secret); err != nil {
		t.Fatal(err)
	}
	if _, err := h.reg.SeeIdentity("sub-north-1", "", "North One"); err != nil {
		t.Fatal(err)
	}
	admin := h.principal("sub-north-1", "police")

	// The administrator invites a colleague; the operator invites an insurer
	// into the same organisation.
	h.tick()
	colleague, _, err := h.reg.Invite(admin, register.InviteRequest{Organisation: "ORG-NORTH",
		To: &register.InviteRecipient{Email: "colleague@example.invalid", Name: "A Colleague"}})
	if err != nil {
		t.Fatal(err)
	}
	h.tick()
	insurer, _, err := h.reg.Invite(operator, register.InviteRequest{Role: "insurer", Organisation: "ORG-NORTH"})
	if err != nil {
		t.Fatal(err)
	}

	// The operator's party: what operators issued, with who used it.
	got, err := h.reg.Invites(operator)
	if err != nil || !slices.Equal(ids(got), sorted(first.ID, insurer.ID)) {
		t.Fatalf("the operator lists %v %v", ids(got), err)
	}
	for _, inv := range got {
		if inv.ID == first.ID && (inv.UsedByDisplay != "North One" || inv.IssuedUnder != "operator") {
			t.Errorf("the used invitation lists as %+v", inv)
		}
		if inv.ID == insurer.ID && !slices.Equal(inv.OrganisationRoles, []string{"police"}) {
			t.Errorf("the open invitation into the organisation shows roles %v", inv.OrganisationRoles)
		}
	}
	_, err = h.reg.RevokeInvite(operator, colleague.ID)
	refused(t, "the operator withdrawing the organisation's invitation", err)

	// The organisation's party: what its own people issued into it.
	got, err = h.reg.Invites(admin)
	if err != nil || !slices.Equal(ids(got), []string{colleague.ID}) || got[0].To == nil || got[0].To.Name != "A Colleague" {
		t.Fatalf("the administrator lists %+v %v", got, err)
	}
	_, err = h.reg.RevokeInvite(admin, insurer.ID)
	refused(t, "the administrator withdrawing the operator's invitation", err)

	// Oversight reads everything and withdraws nothing; the names are for
	// a role cleared for personal data.
	all, err := h.reg.Invites(h.principal("overseer-1", "overseer"))
	if err != nil || !slices.Equal(ids(all), sorted(first.ID, colleague.ID, insurer.ID)) {
		t.Fatalf("the overseer lists %v %v", ids(all), err)
	}
	for _, inv := range all {
		if inv.To != nil || inv.UsedByDisplay != "" || !inv.Emailed && inv.ID == colleague.ID {
			t.Errorf("an overseer without clearance sees %+v", inv)
		}
	}
	all, _ = h.reg.Invites(h.principal("overseer-2", "overseer_pii"))
	for _, inv := range all {
		if inv.ID == colleague.ID && (inv.To == nil || inv.To.Email != "colleague@example.invalid") {
			t.Errorf("a cleared overseer sees %+v", inv)
		}
	}
	h.tick()
	_, err = h.reg.RevokeInvite(h.principal("overseer-2", "overseer_pii"), insurer.ID)
	refused(t, "an overseer withdrawing", err)

	// A fellow administrator sees and withdraws the organisation's own.
	join(t, h, "sub-north-1", "sub-north-2", register.InviteRequest{Organisation: "ORG-NORTH"})
	h.tick()
	if _, err := h.reg.SetOrganisationAdmin(admin, "ORG-NORTH", "sub-north-2", true); err != nil {
		t.Fatal(err)
	}
	fellow := h.principal("sub-north-2", "police")
	if got, _ := h.reg.Invites(fellow); !slices.Contains(ids(got), colleague.ID) || slices.Contains(ids(got), insurer.ID) {
		t.Errorf("the fellow administrator lists %v", ids(got))
	}
	h.tick()
	if _, err := h.reg.RevokeInvite(fellow, colleague.ID); err != nil {
		t.Errorf("the fellow administrator withdrawing: %v", err)
	}

	// The people of the organisation, by name.
	people, err := h.reg.OrganisationMembers(admin, "ORG-NORTH")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range people {
		if m.Sub == "sub-north-1" && m.Display != "North One" {
			t.Errorf("the administrator is listed as %+v", m)
		}
	}
}
