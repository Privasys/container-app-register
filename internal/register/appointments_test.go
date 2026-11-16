// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register_test

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/pack"
	"github.com/Privasys/container-app-register/internal/register"
)

// The car register with fleets, run by fleet operators (organisations),
// whose managers appoint designated drivers to one fleet each, and with
// inspectors appointed to one vehicle of a fleet for brakes or emissions.
func carPackWithAppointments(t *testing.T, edit func(doc map[string]any)) []byte {
	t.Helper()
	raw, err := os.ReadFile(packPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var more map[string]any
	if err := json.Unmarshal([]byte(appointmentsPackPart), &more); err != nil {
		t.Fatal(err)
	}
	for _, list := range []string{"roles", "classes", "workflows"} {
		doc[list] = append(doc[list].([]any), more[list].([]any)...)
	}
	for _, field := range []string{"organisations", "scopes", "invitations", "appointments"} {
		doc[field] = more[field]
	}
	if edit != nil {
		edit(doc)
	}
	out, _ := json.Marshal(doc)
	return out
}

const appointmentsPackPart = `{
  "roles": [
    {"name": "fleet_manager", "title": "Fleet manager", "held": "organisation", "oidc_roles": ["register:fleet_manager"],
     "permissions": ["read:fleet", "read:driver_appointment"], "incompatible_with": ["designated_driver"]},
    {"name": "designated_driver", "title": "Designated driver", "held": "appointment", "oidc_roles": [],
     "permissions": ["read:fleet", "read:driver_appointment"]},
    {"name": "brake_inspector", "title": "Brake inspector", "held": "appointment", "oidc_roles": [], "permissions": ["read:fleet"]},
    {"name": "emissions_inspector", "title": "Emissions inspector", "held": "appointment", "oidc_roles": [], "permissions": ["read:fleet"]}
  ],
  "classes": [
    {"name": "fleet", "title": "Fleet", "natural_key": "fleet_number", "statuses": ["active"], "initial_status": "active", "encryption": "none",
     "schema": {"type": "object", "additionalProperties": false, "required": ["fleet_number", "operator"], "properties": {
       "fleet_number": {"type": "string", "x-register": {"queryable": true, "unique": true}},
       "operator": {"type": "string", "x-register": {"queryable": true}}}}},
    {"name": "driver_appointment", "title": "Driver appointment", "natural_key": "ref", "statuses": ["current", "ceased"], "initial_status": "current", "encryption": "none",
     "schema": {"type": "object", "additionalProperties": false, "required": ["ref", "fleet_number"], "properties": {
       "ref": {"type": "string", "x-register": {"queryable": true, "unique": true}},
       "fleet_number": {"type": "string", "x-register": {"queryable": true}},
       "ceased_on": {"type": "string"}}}},
    {"name": "inspector_appointment", "title": "Inspector appointment", "natural_key": "ref", "statuses": ["current", "ended"], "initial_status": "current", "encryption": "none",
     "schema": {"type": "object", "additionalProperties": false, "required": ["ref", "kind", "fleet_number", "vin"], "properties": {
       "ref": {"type": "string", "x-register": {"queryable": true, "unique": true}},
       "kind": {"type": "string", "enum": ["BRAKES", "EMISSIONS"]},
       "fleet_number": {"type": "string"},
       "vin": {"type": "string"}}}}
  ],
  "workflows": [
    {"name": "record_fleet", "title": "Record a fleet", "class": "fleet", "action": "create",
     "propose_roles": ["registrar"], "approve_roles": ["registrar"], "auto_approve": true, "message": "Record fleet {{payload.fleet_number}}"},
    {"name": "appoint_driver", "title": "Appoint a driver", "class": "driver_appointment", "action": "create",
     "propose_roles": ["registrar"], "approve_roles": ["registrar"], "auto_approve": true, "message": "Appoint a driver to {{payload.fleet_number}}"},
    {"name": "amend_driver_appointment", "title": "Amend a driver appointment", "class": "driver_appointment", "action": "update",
     "propose_roles": ["registrar"], "approve_roles": ["registrar"], "auto_approve": true, "message": "Amend {{object.natural_key}}"},
    {"name": "cease_driver", "title": "Cease a driver appointment", "class": "driver_appointment", "action": "status", "status": "ceased",
     "propose_roles": ["registrar"], "approve_roles": ["registrar"], "auto_approve": true, "message": "Cease {{object.natural_key}}"},
    {"name": "appoint_inspector", "title": "Appoint an inspector", "class": "inspector_appointment", "action": "create",
     "propose_roles": ["registrar"], "approve_roles": ["registrar"], "auto_approve": true, "message": "Appoint an inspector to {{payload.vin}}"}
  ],
  "organisations": {"class": "owner"},
  "scopes": [
    {"class": "fleet", "roles": ["fleet_manager"], "property": "operator"},
    {"class": "driver_appointment", "roles": ["fleet_manager"], "property": "fleet_number", "via": "fleet"},
    {"class": "fleet", "roles": ["designated_driver", "brake_inspector"], "property": "fleet_number"}
  ],
  "invitations": [{"inviter": "fleet_manager", "role": "designated_driver", "class": "driver_appointment"}],
  "appointments": [
    {"class": "driver_appointment", "role": "designated_driver", "keys": ["fleet_number"], "ended_by": "ceased_on"},
    {"class": "inspector_appointment", "role_property": "kind",
     "roles": {"BRAKES": "brake_inspector", "EMISSIONS": "emissions_inspector"}, "keys": ["fleet_number", "vin"]}
  ]
}`

// record proposes a create through an auto-approved workflow and returns
// the new record's id.
func record(t *testing.T, h *harness, workflow string, payload map[string]any) string {
	t.Helper()
	h.tick()
	out, err := h.reg.Propose(h.principal("registrar-1", "registrar"), workflow, register.ProposeRequest{Payload: payload})
	if err != nil {
		t.Fatalf("%s: %v", workflow, err)
	}
	return out.ObjectID
}

// as is the principal a person resolves to from the roles the register
// itself gives them, as a sign-in would.
func as(t *testing.T, h *harness, sub, acting string) (*auth.Principal, error) {
	t.Helper()
	held, _, err := h.reg.GrantedRoles("gov", sub)
	if err != nil {
		t.Fatal(err)
	}
	return h.reg.Pack().Model().Resolve(&auth.Identity{Sub: sub, Display: sub, Granted: held}, "gov", acting)
}

func accept(t *testing.T, h *harness, inviter *auth.Principal, sub string, req register.InviteRequest) error {
	t.Helper()
	h.tick()
	inv, secret, err := h.reg.Invite(inviter, req)
	if err != nil {
		return err
	}
	h.tick()
	_, _, err = h.reg.RedeemInvite("gov", sub, inv.ID, secret)
	return err
}

func setUpFleets(t *testing.T, h *harness) (manager *auth.Principal, fleets map[string]string) {
	t.Helper()
	recordOrganisations(t, h, "ORG-NORTH", "ORG-SOUTH")
	join(t, h, "operator-1", "sub-manager", register.InviteRequest{Role: "fleet_manager", Organisation: "ORG-NORTH"})
	// Two drivers who work for an unrelated firm.
	join(t, h, "operator-1", "sub-driver", register.InviteRequest{Organisation: "ORG-SOUTH"})
	join(t, h, "operator-1", "sub-colleague", register.InviteRequest{Organisation: "ORG-SOUTH"})
	fleets = map[string]string{
		"F-1": record(t, h, "record_fleet", map[string]any{"fleet_number": "F-1", "operator": "ORG-NORTH"}),
		"F-2": record(t, h, "record_fleet", map[string]any{"fleet_number": "F-2", "operator": "ORG-SOUTH"}),
	}
	record(t, h, "appoint_driver", map[string]any{"ref": "DA-1", "fleet_number": "F-1"})
	record(t, h, "appoint_driver", map[string]any{"ref": "DA-2", "fleet_number": "F-2"})
	manager, err := as(t, h, "sub-manager", "fleet_manager")
	if err != nil {
		t.Fatal(err)
	}
	return manager, fleets
}

func TestAnAppointmentGivesItsRoleToThePersonBoundToIt(t *testing.T) {
	h := newHarnessWith(t, t.TempDir(), carPackWithAppointments(t, nil))
	manager, fleets := setUpFleets(t, h)

	// The manager invites to an appointment of a fleet it manages, and to
	// no other.
	if err := accept(t, h, manager, "sub-driver", register.InviteRequest{Role: "designated_driver", Appointment: "DA-2"}); err == nil ||
		!strings.Contains(err.Error(), "not within their scope") {
		t.Fatalf("invited outside its scope: %v", err)
	}
	if err := accept(t, h, manager, "sub-driver", register.InviteRequest{Role: "designated_driver", Appointment: "DA-1"}); err != nil {
		t.Fatal(err)
	}

	// The driver holds the role, personally: a colleague does not.
	if held := roles(t, h, "sub-driver"); !slices.Contains(held, "designated_driver") {
		t.Fatalf("driver holds %v", held)
	}
	if held := roles(t, h, "sub-colleague"); slices.Contains(held, "designated_driver") {
		t.Fatalf("a colleague inherited the appointment: %v", held)
	}

	// Acting as the driver, the scope is the appointment's fleet.
	driver, err := as(t, h, "sub-driver", "designated_driver")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.reg.GetObject(driver, fleets["F-1"]); err != nil {
		t.Fatalf("driver reading its fleet: %v", err)
	}
	if _, err := h.reg.GetObject(driver, fleets["F-2"]); err == nil {
		t.Fatal("driver read another fleet")
	}
	listed, err := h.reg.ListObjects(driver, register.ListFilter{Class: "fleet"})
	if err != nil || len(listed) != 1 || listed[0].NaturalKey != "F-1" {
		t.Fatalf("driver lists %+v, %v", listed, err)
	}

	// The person sees the appointment, with its keys; an administrator
	// sees it among the members.
	mine, err := h.reg.Appointments("gov", "sub-driver")
	if err != nil || len(mine) != 1 || mine[0].Key != "DA-1" || mine[0].Keys["fleet_number"] != "F-1" || mine[0].Role != "designated_driver" {
		t.Fatalf("appointments %+v, %v", mine, err)
	}
	members, err := h.reg.Members(h.principal("operator-1", "operator"))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range members {
		if m.Sub == "sub-driver" && m.Role == "designated_driver" && m.Appointment != nil && m.Appointment.Key == "DA-1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("members listing has no appointment: %+v", members)
	}

	// One person per appointment.
	if err := accept(t, h, manager, "sub-colleague", register.InviteRequest{Role: "designated_driver", Appointment: "DA-1"}); err == nil ||
		!strings.Contains(err.Error(), "already held") {
		t.Fatalf("a second holder: %v", err)
	}
}

func TestAnAppointmentLapsesWhenItsRecordEnds(t *testing.T) {
	h := newHarnessWith(t, t.TempDir(), carPackWithAppointments(t, nil))
	manager, _ := setUpFleets(t, h)
	record(t, h, "appoint_driver", map[string]any{"ref": "DA-3", "fleet_number": "F-1"})
	if err := accept(t, h, manager, "sub-driver", register.InviteRequest{Role: "designated_driver", Appointment: "DA-1"}); err != nil {
		t.Fatal(err)
	}
	if err := accept(t, h, manager, "sub-colleague", register.InviteRequest{Role: "designated_driver", Appointment: "DA-3"}); err != nil {
		t.Fatal(err)
	}
	registrar := h.principal("registrar-1", "registrar")
	objectOf := func(ref string) string {
		listed, err := h.reg.ListObjects(registrar, register.ListFilter{Class: "driver_appointment", Search: ref})
		if err != nil || len(listed) != 1 {
			t.Fatalf("find %s: %+v %v", ref, listed, err)
		}
		return listed[0].ID
	}

	// Leaving the initial status ends it.
	h.tick()
	if _, err := h.reg.Propose(registrar, "cease_driver", register.ProposeRequest{ObjectID: objectOf("DA-1")}); err != nil {
		t.Fatal(err)
	}
	if held := roles(t, h, "sub-driver"); slices.Contains(held, "designated_driver") {
		t.Fatalf("role kept after the appointment ceased: %v", held)
	}
	if _, err := as(t, h, "sub-driver", "designated_driver"); err == nil {
		t.Fatal("acted under a ceased appointment")
	}

	// So does setting the property that ends it.
	h.tick()
	if _, err := h.reg.Propose(registrar, "amend_driver_appointment", register.ProposeRequest{
		ObjectID: objectOf("DA-3"), Payload: map[string]any{"ref": "DA-3", "fleet_number": "F-1", "ceased_on": "2026-09-01"},
	}); err != nil {
		t.Fatal(err)
	}
	if held := roles(t, h, "sub-colleague"); slices.Contains(held, "designated_driver") {
		t.Fatalf("role kept after the end date was set: %v", held)
	}

	// An ended appointment cannot be offered again.
	if err := accept(t, h, manager, "sub-colleague", register.InviteRequest{Role: "designated_driver", Appointment: "DA-1"}); err == nil ||
		!strings.Contains(err.Error(), "not current") {
		t.Fatalf("invited to an ended appointment: %v", err)
	}
}

func TestAnAdministratorUnbindsAnAppointmentWithAReason(t *testing.T) {
	h := newHarnessWith(t, t.TempDir(), carPackWithAppointments(t, nil))
	manager, _ := setUpFleets(t, h)
	if err := accept(t, h, manager, "sub-driver", register.InviteRequest{Role: "designated_driver", Appointment: "DA-1"}); err != nil {
		t.Fatal(err)
	}
	operator := h.principal("operator-1", "operator")
	if _, err := h.reg.EndAppointmentHolding(operator, "driver_appointment", "DA-1", ""); err == nil {
		t.Fatal("unbound without a reason")
	}
	if _, err := h.reg.EndAppointmentHolding(manager, "driver_appointment", "DA-1", "left the firm"); err == nil {
		t.Fatal("a fleet manager unbound an appointment")
	}
	h.tick()
	txn, err := h.reg.EndAppointmentHolding(operator, "driver_appointment", "DA-1", "Left the firm.")
	if err != nil || !strings.Contains(txn.Envelope.Message, "Left the firm.") {
		t.Fatalf("unbind: %v", err)
	}
	if held := roles(t, h, "sub-driver"); slices.Contains(held, "designated_driver") {
		t.Fatalf("role kept after unbinding: %v", held)
	}
	// The appointment is open again.
	if err := accept(t, h, manager, "sub-colleague", register.InviteRequest{Role: "designated_driver", Appointment: "DA-1"}); err != nil {
		t.Fatal(err)
	}
}

func TestAnAppointmentKeepsSeparationOfDuties(t *testing.T) {
	h := newHarnessWith(t, t.TempDir(), carPackWithAppointments(t, nil))
	manager, _ := setUpFleets(t, h)
	// The manager may not appoint themself to drive.
	if err := accept(t, h, manager, "sub-manager", register.InviteRequest{Role: "designated_driver", Appointment: "DA-1"}); err == nil ||
		!strings.Contains(err.Error(), "separation of duties") {
		t.Fatalf("manager took a driver appointment: %v", err)
	}
}

func TestAnAppointmentClassMayGiveSeveralRoles(t *testing.T) {
	h := newHarnessWith(t, t.TempDir(), carPackWithAppointments(t, nil))
	_, fleets := setUpFleets(t, h)
	record(t, h, "appoint_inspector", map[string]any{"ref": "IA-1", "kind": "BRAKES", "fleet_number": "F-2", "vin": "VF1RFB00X66000002"})
	operator := h.principal("operator-1", "operator")

	// Whoever manages members may invite to any appointment, to the role
	// the record gives and no other.
	if err := accept(t, h, operator, "sub-colleague", register.InviteRequest{Role: "emissions_inspector", Appointment: "IA-1"}); err == nil ||
		!strings.Contains(err.Error(), "gives the role brake_inspector") {
		t.Fatalf("invited to the wrong role: %v", err)
	}
	if err := accept(t, h, operator, "sub-colleague", register.InviteRequest{Role: "brake_inspector", Appointment: "IA-1"}); err != nil {
		t.Fatal(err)
	}
	mine, err := h.reg.Appointments("gov", "sub-colleague")
	if err != nil || len(mine) != 1 || mine[0].Keys["vin"] != "VF1RFB00X66000002" || mine[0].Keys["fleet_number"] != "F-2" {
		t.Fatalf("appointments %+v, %v", mine, err)
	}
	inspector, err := as(t, h, "sub-colleague", "brake_inspector")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.reg.GetObject(inspector, fleets["F-2"]); err != nil {
		t.Fatalf("inspector reading its fleet: %v", err)
	}
	if _, err := h.reg.GetObject(inspector, fleets["F-1"]); err == nil {
		t.Fatal("inspector read another fleet")
	}
}

func TestAppointmentsAreValidatedAtLoad(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(doc map[string]any)
		want string
	}{
		{"role not held by appointment", func(doc map[string]any) {
			doc["appointments"].([]any)[0].(map[string]any)["role"] = "fleet_manager"
		}, "is not held by appointment"},
		{"role and role property", func(doc map[string]any) {
			doc["appointments"].([]any)[0].(map[string]any)["role_property"] = "fleet_number"
		}, "not both"},
		{"unknown key", func(doc map[string]any) {
			doc["appointments"].([]any)[0].(map[string]any)["keys"] = []any{"depot"}
		}, `has no property "depot"`},
		{"invitation to a role the class does not give", func(doc map[string]any) {
			doc["invitations"].([]any)[0].(map[string]any)["role"] = "brake_inspector"
		}, "does not give the role"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := pack.Load(carPackWithAppointments(t, tc.edit))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}
