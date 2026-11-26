// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register_test

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/Privasys/container-app-register/internal/pack"
	"github.com/Privasys/container-app-register/internal/register"
)

// Assets, and repair orders that name an asset and the repairer's firm: a
// repairer sees an asset while an open order of its firm names it.
const repairsPackPart = `{
  "roles": [
    {"name": "repairer", "title": "Repairer", "held": "organisation", "oidc_roles": [], "permissions": ["read:asset", "read:repair_order"]}
  ],
  "classes": [
    {"name": "asset", "title": "Asset", "natural_key": "asset_no", "statuses": ["active"], "initial_status": "active", "encryption": "none",
     "schema": {"type": "object", "additionalProperties": false, "required": ["asset_no"], "properties": {
       "asset_no": {"type": "string", "x-register": {"queryable": true, "unique": true}},
       "colour": {"type": "string"}}}},
    {"name": "repair_order", "title": "Repair order", "natural_key": "ref", "statuses": ["open", "closed"], "initial_status": "open", "encryption": "none",
     "schema": {"type": "object", "additionalProperties": false, "required": ["ref", "asset_no", "repairer"], "properties": {
       "ref": {"type": "string", "x-register": {"queryable": true, "unique": true}},
       "asset_no": {"type": "string", "x-register": {"queryable": true}},
       "repairer": {"type": "string", "x-register": {"queryable": true}},
       "notes": {"type": "string"}}}}
  ],
  "workflows": [
    {"name": "record_asset", "title": "Record an asset", "class": "asset", "action": "create",
     "propose_roles": ["registrar"], "approve_roles": ["registrar"], "auto_approve": true, "message": "Record {{payload.asset_no}}"},
    {"name": "open_order", "title": "Open a repair order", "class": "repair_order", "action": "create",
     "propose_roles": ["registrar"], "approve_roles": ["registrar"], "auto_approve": true, "message": "Open {{payload.ref}}"},
    {"name": "close_order", "title": "Close a repair order", "class": "repair_order", "action": "status", "status": "closed",
     "propose_roles": ["registrar"], "approve_roles": ["registrar"], "auto_approve": true, "message": "Close {{object.natural_key}}"}
  ],
  "scopes": [
    {"class": "repair_order", "roles": ["repairer"], "property": "repairer"},
    {"class": "asset", "roles": ["repairer"], "property": "asset_no", "via": "repair_order", "via_property": "asset_no", "via_current": true}
  ]
}`

func carPackWithRepairs(t *testing.T, edit func(doc map[string]any)) []byte {
	t.Helper()
	var more map[string]any
	if err := json.Unmarshal([]byte(repairsPackPart), &more); err != nil {
		t.Fatal(err)
	}
	return carPackWithAppointments(t, func(doc map[string]any) {
		for _, list := range []string{"roles", "classes", "workflows", "scopes"} {
			doc[list] = append(doc[list].([]any), more[list].([]any)...)
		}
		if edit != nil {
			edit(doc)
		}
	})
}

func TestAScopeFollowsALinkRecordWhileItIsCurrent(t *testing.T) {
	h := newHarnessWith(t, t.TempDir(), carPackWithRepairs(t, nil))
	recordOrganisations(t, h, "ORG-NORTH", "ORG-SOUTH")
	join(t, h, "operator-1", "sub-rep", register.InviteRequest{Role: "repairer", Organisation: "ORG-NORTH"})
	assets := map[string]string{}
	for _, no := range []string{"A-1", "A-2", "A-3"} {
		assets[no] = record(t, h, "record_asset", map[string]any{"asset_no": no})
	}
	order := record(t, h, "open_order", map[string]any{"ref": "RO-1", "asset_no": "A-1", "repairer": "ORG-NORTH"})
	record(t, h, "open_order", map[string]any{"ref": "RO-2", "asset_no": "A-2", "repairer": "ORG-SOUTH"})

	rep, err := as(t, h, "sub-rep", "repairer")
	if err != nil {
		t.Fatal(err)
	}
	sees := func(what string, want ...string) {
		t.Helper()
		for no, id := range assets {
			_, err := h.reg.GetObject(rep, id)
			if got := err == nil; got != slices.Contains(want, no) {
				t.Errorf("%s: reading %s: %v", what, no, err)
			}
		}
		listed, err := h.reg.ListObjects(rep, register.ListFilter{Class: "asset"})
		if err != nil {
			t.Fatal(err)
		}
		var keys []string
		for _, o := range listed {
			keys = append(keys, o.NaturalKey)
		}
		if !slices.Equal(keys, want) {
			t.Errorf("%s: lists %v, want %v", what, keys, want)
		}
		found, err := h.reg.ListObjects(rep, register.ListFilter{Class: "asset", Search: "A-"})
		if err != nil {
			t.Fatal(err)
		}
		keys = keys[:0]
		for _, o := range found {
			keys = append(keys, o.NaturalKey)
		}
		if !slices.Equal(keys, want) {
			t.Errorf("%s: a search finds %v, want %v", what, keys, want)
		}
	}

	// Named by an open order of the firm: in. Named by another firm's
	// order, or by none: out.
	sees("an open order", "A-1")

	// Closing the order ends the access at once.
	h.tick()
	if _, err := h.reg.Propose(h.principal("registrar-1", "registrar"), "close_order", register.ProposeRequest{ObjectID: order}); err != nil {
		t.Fatal(err)
	}
	sees("the order closed")

	// A new open order brings it back.
	record(t, h, "open_order", map[string]any{"ref": "RO-3", "asset_no": "A-1", "repairer": "ORG-NORTH"})
	sees("a new order", "A-1")
}

// Without via_current, an order counts whatever its status.
func TestALinkScopeCanCountEveryLinkRecord(t *testing.T) {
	h := newHarnessWith(t, t.TempDir(), carPackWithRepairs(t, func(doc map[string]any) {
		for _, s := range doc["scopes"].([]any) {
			if s := s.(map[string]any); s["via_property"] != nil {
				delete(s, "via_current")
			}
		}
	}))
	recordOrganisations(t, h, "ORG-NORTH")
	join(t, h, "operator-1", "sub-rep", register.InviteRequest{Role: "repairer", Organisation: "ORG-NORTH"})
	asset := record(t, h, "record_asset", map[string]any{"asset_no": "A-1"})
	order := record(t, h, "open_order", map[string]any{"ref": "RO-1", "asset_no": "A-1", "repairer": "ORG-NORTH"})
	h.tick()
	if _, err := h.reg.Propose(h.principal("registrar-1", "registrar"), "close_order", register.ProposeRequest{ObjectID: order}); err != nil {
		t.Fatal(err)
	}
	rep, err := as(t, h, "sub-rep", "repairer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.reg.GetObject(rep, asset); err != nil {
		t.Errorf("a closed order no longer counts: %v", err)
	}
}

func TestALinkScopeIsDeclaredWhole(t *testing.T) {
	for what, edit := range map[string]func(s map[string]any){
		"a missing property":       func(s map[string]any) { s["via_property"] = "nobody" },
		"a property not queryable": func(s map[string]any) { s["via_property"] = "notes" },
		"via_property without via": func(s map[string]any) { delete(s, "via") },
		"via_current without via":  func(s map[string]any) { delete(s, "via"); delete(s, "via_property") },
	} {
		raw := carPackWithRepairs(t, func(doc map[string]any) {
			for _, s := range doc["scopes"].([]any) {
				if s := s.(map[string]any); s["via_property"] != nil {
					edit(s)
				}
			}
		})
		if _, err := pack.Load(raw); err == nil {
			t.Errorf("a scope with %s loaded", what)
		}
	}
}
