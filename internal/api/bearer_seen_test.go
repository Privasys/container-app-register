// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/register"
)

func bearer(t *testing.T, ts *httptest.Server, method, path, token, payload string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+path, strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if payload != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var decoded map[string]any
	_ = json.Unmarshal(body, &decoded)
	return resp.StatusCode, decoded
}

// Someone who only ever signs in with a bearer token has signed in all the
// same: once a member, a record can name them as its holder.
func TestABearerSignInCountsAsSignedIn(t *testing.T) {
	ts, srv, reg := newTestServerWith(t, func(doc map[string]any) {
		var more map[string]any
		_ = json.Unmarshal([]byte(`{
		  "role": {"name": "designated_driver", "title": "Designated driver", "held": "appointment", "oidc_roles": [],
		           "permissions": ["read:driver_appointment"]},
		  "class": {"name": "driver_appointment", "title": "Driver appointment", "natural_key": "ref",
		            "statuses": ["current", "ceased"], "initial_status": "current", "encryption": "none",
		            "schema": {"type": "object", "additionalProperties": false, "required": ["ref", "fleet_number"], "properties": {
		              "ref": {"type": "string", "x-register": {"queryable": true, "unique": true}},
		              "fleet_number": {"type": "string"},
		              "holder": {"type": "string"}}}},
		  "workflow": {"name": "appoint_driver", "title": "Appoint a driver", "class": "driver_appointment", "action": "create",
		               "propose_roles": ["registrar"], "approve_roles": ["registrar"], "auto_approve": true,
		               "message": "Appoint a driver to {{payload.fleet_number}}"}
		}`), &more)
		doc["roles"] = append(doc["roles"].([]any), more["role"])
		doc["classes"] = append(doc["classes"].([]any), more["class"])
		doc["workflows"] = append(doc["workflows"].([]any), more["workflow"])
		doc["appointments"] = []any{map[string]any{"class": "driver_appointment", "role": "designated_driver",
			"keys": []any{"fleet_number"}, "holder_property": "holder"}}
	})
	out := map[string]any{}
	if err := srv.bootstrapMembers(reg, []byte(`{"admin_invite":true}`), out); err != nil {
		t.Fatal(err)
	}
	srv.Ready(reg, auth.DevVerifier{})
	const olga, dan = "dev:sub-olga:Olga:", "dev:sub-dan:Dan:"

	id, secret := splitLink(t, out["admin_invite"])
	if status, body := bearer(t, ts, http.MethodPost, "/api/v1/invites/"+id+"/redeem", olga, `{"secret":"`+secret+`"}`); status != http.StatusOK {
		t.Fatalf("administrator: %d %v", status, body)
	}
	status, body := bearer(t, ts, http.MethodPost, "/api/v1/invites", olga, `{"role":"insurer"}`)
	if status != http.StatusOK {
		t.Fatalf("invite: %d %v", status, body)
	}
	id, secret = splitLink(t, body["link"])
	if status, body := bearer(t, ts, http.MethodPost, "/api/v1/invites/"+id+"/redeem", dan, `{"secret":"`+secret+`"}`); status != http.StatusOK {
		t.Fatalf("member: %d %v", status, body)
	}

	registrar, err := reg.Pack().Model().Resolve(&auth.Identity{Sub: "registrar-1", Roles: []string{"register:registrar"}}, "gov", "registrar")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Propose(registrar, "appoint_driver", register.ProposeRequest{
		Payload: map[string]any{"ref": "DA-1", "fleet_number": "F-1", "holder": "sub-dan"},
	}); err != nil {
		t.Fatalf("naming a bearer-only member: %v", err)
	}
	status, me := bearer(t, ts, http.MethodGet, "/api/v1/me", dan, "")
	apps, _ := me["appointments"].([]any)
	if status != http.StatusOK || len(apps) != 1 || apps[0].(map[string]any)["named"] != true {
		t.Fatalf("me: %d %v", status, me)
	}
	if status, body := bearer(t, ts, http.MethodDelete, "/api/v1/appointments/driver_appointment/DA-1/holder?reason=Left", olga, ""); status != http.StatusBadRequest ||
		!strings.Contains(body["error"].(string), "amend the record") {
		t.Errorf("unbinding a named holder: %d %v", status, body)
	}
}
