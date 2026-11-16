// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/register"
)

// An appointment over HTTP: an administrator invites a driver to one
// appointment record, the driver accepts, sees it under /me, and loses the
// role when the administrator unbinds them.
func TestAnAppointmentOverTheAPI(t *testing.T) {
	ts, srv, reg := newTestServerWith(t, func(doc map[string]any) {
		var more map[string]any
		_ = json.Unmarshal([]byte(`{
		  "role": {"name": "designated_driver", "title": "Designated driver", "held": "appointment", "oidc_roles": [],
		           "permissions": ["read:driver_appointment"]},
		  "class": {"name": "driver_appointment", "title": "Driver appointment", "natural_key": "ref",
		            "statuses": ["current", "ceased"], "initial_status": "current", "encryption": "none",
		            "schema": {"type": "object", "additionalProperties": false, "required": ["ref", "fleet_number"], "properties": {
		              "ref": {"type": "string", "x-register": {"queryable": true, "unique": true}},
		              "fleet_number": {"type": "string"}}}},
		  "workflow": {"name": "appoint_driver", "title": "Appoint a driver", "class": "driver_appointment", "action": "create",
		               "propose_roles": ["registrar"], "approve_roles": ["registrar"], "auto_approve": true,
		               "message": "Appoint a driver to {{payload.fleet_number}}"}
		}`), &more)
		doc["roles"] = append(doc["roles"].([]any), more["role"])
		doc["classes"] = append(doc["classes"].([]any), more["class"])
		doc["workflows"] = append(doc["workflows"].([]any), more["workflow"])
		doc["appointments"] = []any{map[string]any{"class": "driver_appointment", "role": "designated_driver", "keys": []any{"fleet_number"}}}
	})
	srv.TrustSession = true
	out := map[string]any{}
	if err := srv.bootstrapMembers(reg, []byte(`{"admin_invite":true}`), out); err != nil {
		t.Fatal(err)
	}
	srv.Ready(reg, auth.DevVerifier{})
	id, secret := splitLink(t, out["admin_invite"])
	if status, _ := call(t, ts, http.MethodPost, "/api/v1/invites/"+id+"/redeem", "sub-olga", `{"secret":"`+secret+`"}`); status != http.StatusOK {
		t.Fatalf("administrator: %d", status)
	}
	registrar, err := reg.Pack().Model().Resolve(&auth.Identity{Sub: "registrar-1", Roles: []string{"register:registrar"}}, "gov", "registrar")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Propose(registrar, "appoint_driver", register.ProposeRequest{
		Payload: map[string]any{"ref": "DA-1", "fleet_number": "F-1"},
	}); err != nil {
		t.Fatal(err)
	}

	status, body := call(t, ts, http.MethodPost, "/api/v1/invites", "sub-olga",
		`{"role":"designated_driver","appointment_key":"DA-1"}`)
	if status != http.StatusOK {
		t.Fatalf("invite: %d %v", status, body)
	}
	id, secret = splitLink(t, body["link"])
	status, body = call(t, ts, http.MethodPost, "/api/v1/invites/"+id+"/redeem", "sub-dan", `{"secret":"`+secret+`"}`)
	if status != http.StatusOK || body["appointment"].(map[string]any)["key"] != "DA-1" {
		t.Fatalf("redeem: %d %v", status, body)
	}

	status, me := call(t, ts, http.MethodGet, "/api/v1/me", "sub-dan", "")
	apps, _ := me["appointments"].([]any)
	if status != http.StatusOK || me["status"] != "member" || len(apps) != 1 {
		t.Fatalf("me: %d %v", status, me)
	}
	a := apps[0].(map[string]any)
	if a["class"] != "driver_appointment" || a["key"] != "DA-1" || a["role"] != "designated_driver" ||
		a["keys"].(map[string]any)["fleet_number"] != "F-1" {
		t.Fatalf("appointment %v", a)
	}

	if status, _ := call(t, ts, http.MethodDelete, "/api/v1/appointments/driver_appointment/DA-1/holder?reason=Left", "sub-olga", ""); status != http.StatusOK {
		t.Fatalf("unbind: %d", status)
	}
	if _, me := call(t, ts, http.MethodGet, "/api/v1/me", "sub-dan", ""); me["status"] != "no_role" {
		t.Fatalf("after unbinding: %v", me)
	}
}
