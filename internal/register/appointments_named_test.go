// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/Privasys/container-app-register/internal/pack"
	"github.com/Privasys/container-app-register/internal/register"
)

// The appointments pack, with driver appointments that name their holder.
func carPackWithNamedHolders(t *testing.T) []byte {
	return carPackWithAppointments(t, func(doc map[string]any) {
		for _, c := range doc["classes"].([]any) {
			class := c.(map[string]any)
			if class["name"] == "driver_appointment" {
				props := class["schema"].(map[string]any)["properties"].(map[string]any)
				props["holder"] = map[string]any{"type": "string"}
			}
		}
		for _, a := range doc["appointments"].([]any) {
			if a := a.(map[string]any); a["class"] == "driver_appointment" {
				a["holder_property"] = "holder"
			}
		}
	})
}

func TestARecordNamesItsHolder(t *testing.T) {
	h := newHarnessWith(t, t.TempDir(), carPackWithNamedHolders(t))
	manager, fleets := setUpFleets(t, h)
	for _, sub := range []string{"sub-driver", "sub-colleague"} {
		if _, err := h.reg.SeeIdentity(sub, "", ""); err != nil {
			t.Fatal(err)
		}
		if _, err := h.reg.SeeIdentity(sub, sub+"@example.invalid", ""); err != nil {
			t.Fatal(err)
		}
	}
	registrar := h.principal("registrar-1", "registrar")
	objectOf := func(ref string) string {
		listed, err := h.reg.ListObjects(registrar, register.ListFilter{Class: "driver_appointment", Search: ref})
		if err != nil || len(listed) != 1 {
			t.Fatalf("find %s: %+v %v", ref, listed, err)
		}
		return listed[0].ID
	}
	amend := func(ref string, payload map[string]any) error {
		h.tick()
		_, err := h.reg.Propose(registrar, "amend_driver_appointment", register.ProposeRequest{ObjectID: objectOf(ref), Payload: payload})
		return err
	}

	// Named on the record: held at once, scoped by the record's keys.
	record(t, h, "appoint_driver", map[string]any{"ref": "DA-9", "fleet_number": "F-1", "holder": "sub-driver"})
	if held := roles(t, h, "sub-driver"); !slices.Contains(held, "designated_driver") {
		t.Fatalf("the named driver holds %v", held)
	}
	driver, err := as(t, h, "sub-driver", "designated_driver")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.reg.GetObject(driver, fleets["F-1"]); err != nil {
		t.Errorf("reading the appointment's fleet: %v", err)
	}
	if _, err := h.reg.GetObject(driver, fleets["F-2"]); err == nil {
		t.Error("read another fleet")
	}
	mine, err := h.reg.Appointments("gov", "sub-driver")
	if err != nil || len(mine) != 1 || mine[0].Key != "DA-9" || mine[0].Keys["fleet_number"] != "F-1" || mine[0].GrantedBy != "registrar-1" || !mine[0].Named {
		t.Fatalf("appointments %+v %v", mine, err)
	}

	// Held: no invitation to it, and no unbinding but by the record.
	if err := accept(t, h, manager, "sub-colleague", register.InviteRequest{Role: "designated_driver", Appointment: "DA-9"}); err == nil ||
		!strings.Contains(err.Error(), "already held") {
		t.Errorf("invited to a named appointment: %v", err)
	}
	h.tick()
	if _, err := h.reg.EndAppointmentHolding(h.principal("operator-1", "operator"), "driver_appointment", "DA-9", "because"); err == nil ||
		!strings.Contains(err.Error(), "amend the record's holder") {
		t.Errorf("unbinding a named holder: %v", err)
	}

	// Naming someone else moves it; clearing it ends it.
	if err := amend("DA-9", map[string]any{"ref": "DA-9", "fleet_number": "F-1", "holder": "sub-colleague"}); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(roles(t, h, "sub-driver"), "designated_driver") || !slices.Contains(roles(t, h, "sub-colleague"), "designated_driver") {
		t.Errorf("after naming another: %v %v", roles(t, h, "sub-driver"), roles(t, h, "sub-colleague"))
	}
	if err := amend("DA-9", map[string]any{"ref": "DA-9", "fleet_number": "F-1"}); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(roles(t, h, "sub-colleague"), "designated_driver") {
		t.Error("the holding outlived its clearing")
	}

	// Cleared, the record takes an invitation again.
	if err := accept(t, h, manager, "sub-colleague", register.InviteRequest{Role: "designated_driver", Appointment: "DA-9"}); err != nil {
		t.Fatalf("inviting to a cleared record: %v", err)
	}
	// An invited holder is not displaced by naming another on the record.
	if err := amend("DA-9", map[string]any{"ref": "DA-9", "fleet_number": "F-1", "holder": "sub-driver"}); err == nil ||
		!strings.Contains(err.Error(), "accepted an invitation") {
		t.Errorf("displaced an invited holder: %v", err)
	}

	// Ending the record ends the holding.
	record(t, h, "appoint_driver", map[string]any{"ref": "DA-10", "fleet_number": "F-1", "holder": "sub-driver"})
	if err := amend("DA-10", map[string]any{"ref": "DA-10", "fleet_number": "F-1", "holder": "sub-driver", "ceased_on": "2026-11-26"}); err != nil {
		t.Fatal(err)
	}
	if mine, _ := h.reg.Appointments("gov", "sub-driver"); len(mine) != 0 {
		t.Errorf("an ended appointment is held: %+v", mine)
	}
}

func TestARecordNamesOnlyAKnownMember(t *testing.T) {
	h := newHarnessWith(t, t.TempDir(), carPackWithNamedHolders(t))
	setUpFleets(t, h)
	registrar := h.principal("registrar-1", "registrar")
	try := func(ref, holder string) error {
		h.tick()
		_, err := h.reg.Propose(registrar, "appoint_driver", register.ProposeRequest{Payload: map[string]any{
			"ref": ref, "fleet_number": "F-1", "holder": holder}})
		return err
	}
	// A member who has never signed in.
	if err := try("DA-20", "sub-driver"); err == nil || !strings.Contains(err.Error(), "never signed in") {
		t.Errorf("named someone never seen: %v", err)
	}
	// Someone who signed in but is no member.
	if _, err := h.reg.SeeIdentity("sub-stranger", "stranger@example.invalid", "A Stranger"); err != nil {
		t.Fatal(err)
	}
	if err := try("DA-21", "sub-stranger"); err == nil || !strings.Contains(err.Error(), "not a member") {
		t.Errorf("named a stranger: %v", err)
	}
	// A role the holder may not combine with the one given.
	if _, err := h.reg.SeeIdentity("sub-manager", "manager@example.invalid", ""); err != nil {
		t.Fatal(err)
	}
	if err := try("DA-22", "sub-manager"); err == nil {
		t.Error("named a holder into an incompatible role")
	}
	if held := roles(t, h, "sub-stranger"); len(held) != 0 {
		t.Errorf("the stranger holds %v", held)
	}
}

func TestAHolderPropertyIsAPropertyOfItsOwn(t *testing.T) {
	for what, prop := range map[string]string{"missing": "nobody", "the natural key": "ref", "a key": "fleet_number", "the end": "ceased_on"} {
		raw := carPackWithAppointments(t, func(doc map[string]any) {
			for _, a := range doc["appointments"].([]any) {
				if a := a.(map[string]any); a["class"] == "driver_appointment" {
					a["holder_property"] = prop
				}
			}
		})
		if _, err := pack.Load(raw); err == nil {
			t.Errorf("a holder property that is %s loaded", what)
		}
	}
}
