// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Privasys/container-app-register/internal/register"
)

// The car register's pack with owners as the organisations people belong
// to, and the police limited to the owners that are their own organisation:
// odd for a car register, but the smallest pack that exercises both.
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
	doc["organisations"] = map[string]any{"class": "owner"}
	doc["scopes"] = []any{map[string]any{"class": "owner", "roles": []any{"police"}, "property": "reference"}}
	out, _ := json.Marshal(doc)
	return out
}

func TestOrganisationsAndTheirScope(t *testing.T) {
	h := newHarnessWith(t, t.TempDir(), carPackWithOrganisations(t))
	operator := h.principal("operator-1", "operator")
	for _, ref := range []string{"ORG-NORTH", "ORG-SOUTH"} {
		h.tick()
		if _, _, err := h.reg.RecordOrganisation(operator, map[string]any{
			"reference": ref, "kind": "company", "country": "IM", "name": "Constabulary " + ref,
		}); err != nil {
			t.Fatalf("record %s: %v", ref, err)
		}
	}
	h.tick()
	if _, _, err := h.reg.Invite(operator, register.InviteRequest{Role: "police", Organisation: "ORG-NOWHERE"}); err == nil {
		t.Error("an invitation into an organisation that does not exist was issued")
	}

	// The first person invited into an organisation administers it.
	h.tick()
	first, secret, err := h.reg.Invite(operator, register.InviteRequest{Role: "police", Organisation: "ORG-NORTH"})
	if err != nil || !first.OrganisationAdmin {
		t.Fatalf("first invitation: %+v %v", first, err)
	}
	h.tick()
	if _, _, err := h.reg.RedeemInvite("gov", "sub-north-1", first.ID, secret); err != nil {
		t.Fatal(err)
	}
	affs, err := h.reg.Affiliations("gov", "sub-north-1")
	if err != nil || len(affs) != 1 || affs[0].Organisation != "ORG-NORTH" || !affs[0].Admin {
		t.Fatalf("affiliations %+v %v", affs, err)
	}

	// The administrator invites a colleague to their own role, in their own
	// organisation only.
	admin := h.principal("sub-north-1", "police")
	h.tick()
	colleague, secret2, err := h.reg.Invite(admin, register.InviteRequest{Role: "police", Organisation: "ORG-NORTH"})
	if err != nil || colleague.OrganisationAdmin {
		t.Fatalf("colleague invitation: %+v %v", colleague, err)
	}
	for name, req := range map[string]register.InviteRequest{
		"another organisation": {Role: "police", Organisation: "ORG-SOUTH"},
		"a role they lack":     {Role: "registrar", Organisation: "ORG-NORTH"},
		"no organisation":      {Role: "police"},
	} {
		if _, _, err := h.reg.Invite(admin, req); err == nil {
			t.Errorf("an organisation's administrator invited to %s", name)
		}
	}
	h.tick()
	if _, _, err := h.reg.RedeemInvite("gov", "sub-north-2", colleague.ID, secret2); err != nil {
		t.Fatal(err)
	}

	// The scope: a police officer sees only the owner that is their organisation.
	officer := h.principal("sub-north-2", "police")
	listed, err := h.reg.ListObjects(officer, register.ListFilter{Class: "owner"})
	if err != nil || len(listed) != 1 || listed[0].NaturalKey != "ORG-NORTH" {
		t.Fatalf("listed %+v %v", listed, err)
	}
	all, _ := h.reg.ListObjects(operator, register.ListFilter{Class: "owner", Limit: 100})
	var south string
	seen := 0
	for _, o := range all {
		if o.NaturalKey == "ORG-SOUTH" {
			south = o.ID
		}
		if strings.HasPrefix(o.NaturalKey, "ORG-") {
			seen++
		}
	}
	if seen != 2 {
		t.Errorf("the operator, who is not limited, sees %d of the two organisations", seen)
	}
	if _, err := h.reg.GetObject(officer, south); err == nil || !strings.Contains(err.Error(), "may not") {
		t.Errorf("an officer read another organisation: %v", err)
	}
	outsider := h.principal("sub-nobody", "police")
	if none, err := h.reg.ListObjects(outsider, register.ListFilter{Class: "owner"}); err != nil || len(none) != 0 {
		t.Errorf("an officer of no organisation sees %d owners (%v)", len(none), err)
	}

	// Administrators: there is always one.
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
	members, err := h.reg.OrganisationMembers(officer, "ORG-NORTH")
	if err != nil || len(members) != 2 {
		t.Fatalf("members %+v %v", members, err)
	}
}
