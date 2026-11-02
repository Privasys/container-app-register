// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register_test

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/keys"
	"github.com/Privasys/container-app-register/internal/pack"
	"github.com/Privasys/container-app-register/internal/register"
	"github.com/Privasys/container-app-register/internal/store"
)

// A pack that keeps every value in an envelope {value, status} projects
// the member it names, typed, so filters and ordering see the value and
// not the envelope's text.
const envelopePack = `{
  "name": "envelopes", "title": "Envelope register", "version": "1.0.0", "tenant": "gov",
  "roles": [{"name": "registrar", "title": "Registrar", "oidc_roles": ["register:registrar"],
             "permissions": ["read:*", "propose:*", "approve:*"]}],
  "classes": [{
    "name": "asset", "title": "Asset", "natural_key": "ref",
    "statuses": ["registered"], "initial_status": "registered", "encryption": "none",
    "schema": {"type": "object", "additionalProperties": false, "required": ["ref", "asset_name"],
      "properties": {
        "ref": {"type": "string", "x-register": {"queryable": true, "unique": true}},
        "asset_name": {"type": "object", "required": ["value", "status"],
          "properties": {"value": {"type": "string", "maxLength": 120}, "status": {"type": "string"}},
          "x-register": {"queryable": true, "indexed": true, "member": "value"}},
        "size": {"type": "object",
          "properties": {"value": {"type": "integer"}, "status": {"type": "string"}},
          "x-register": {"queryable": true, "member": "value", "column": "size_bytes"}},
        "restricted": {"type": "object",
          "properties": {"value": {"type": "boolean"}, "status": {"type": "string"}},
          "x-register": {"queryable": true, "member": "value"}}
      }}
  }],
  "workflows": [{
    "name": "register_asset", "title": "Register an asset", "class": "asset", "action": "create",
    "propose_roles": ["registrar"], "approve_roles": ["registrar"], "auto_approve": true,
    "message": "Register asset {{payload.ref}}",
    "effects": [{"type": "record"}]
  }],
  "queries": [{
    "name": "assets_named", "title": "Assets by name", "roles": ["registrar"],
    "params": [{"name": "name", "title": "Name", "type": "string", "required": true}],
    "sql": "SELECT object_id, ref, asset_name, size_bytes, restricted FROM ` + "`q_asset`" + ` WHERE tenant = {{tenant}} AND asset_name = {{param.name}} ORDER BY size_bytes DESC"
  }, {
    "name": "large_assets", "title": "Assets over a size", "roles": ["registrar"],
    "params": [{"name": "min", "title": "Minimum size", "type": "integer", "required": true}],
    "sql": "SELECT ref, size_bytes FROM ` + "`q_asset`" + ` WHERE tenant = {{tenant}} AND size_bytes > {{param.min}} ORDER BY size_bytes ASC"
  }]
}`

func newEnvelopeRegister(t *testing.T) *register.Register {
	t.Helper()
	loaded, err := pack.Load([]byte(envelopePack))
	if err != nil {
		t.Fatalf("load pack: %v", err)
	}
	dir := t.TempDir()
	material, err := keys.Load(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	ck, source, err := material.CommitmentKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "register"), ck)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	reg, err := register.New(st, loaded, material, register.Options{
		Name: "envelopes", Tenant: "gov", ImageDigest: strings.Repeat("ab", 32),
		KeySource: source, Now: func() time.Time { now = now.Add(time.Second); return now },
	})
	if err != nil {
		st.Close()
		t.Fatalf("new register: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return reg
}

func TestEnvelopeMembersProjectTyped(t *testing.T) {
	reg := newEnvelopeRegister(t)
	p, err := reg.Pack().Model().Resolve(
		&auth.Identity{Sub: "registrar-1", Display: "registrar-1", Roles: []string{"register:registrar"}}, "gov", "registrar")
	if err != nil {
		t.Fatal(err)
	}
	env := func(v any) map[string]any { return map[string]any{"value": v, "status": "D"} }
	for _, a := range []struct {
		ref  string
		name string
		size any
		sens any
	}{
		{"A-1", "Harbour telemetry", float64(1500), true},
		{"A-2", "Harbour telemetry", float64(20), false},
		{"A-3", "Tide tables", float64(9), nil},
	} {
		payload := map[string]any{"ref": a.ref, "asset_name": env(a.name)}
		if a.size != nil {
			payload["size"] = env(a.size)
		}
		if a.sens != nil {
			payload["restricted"] = env(a.sens)
		}
		out, err := reg.Propose(p, "register_asset", register.ProposeRequest{Payload: payload})
		if err != nil {
			t.Fatalf("propose %s: %v", a.ref, err)
		}
		if out.Applied == nil {
			t.Fatalf("%s was not applied under policy", a.ref)
		}
	}

	// A saved query filters on the projected member and orders by the
	// integer member as a number, not as text.
	rows, err := reg.RunQuery(p, "assets_named", map[string]string{"name": "Harbour telemetry"})
	if err != nil {
		t.Fatalf("assets_named: %v", err)
	}
	if len(rows) != 2 || rows[0].Str("ref") != "A-1" || rows[1].Str("ref") != "A-2" {
		t.Fatalf("filter on an envelope member: %+v", rows)
	}
	if rows[0].Int("size_bytes") != 1500 || !rows[0].Bool("restricted") || rows[1].Bool("restricted") {
		t.Errorf("typed members: %+v", rows)
	}
	large, err := reg.RunQuery(p, "large_assets", map[string]string{"min": "10"})
	if err != nil {
		t.Fatalf("large_assets: %v", err)
	}
	if len(large) != 2 || large[0].Str("ref") != "A-2" || large[1].Str("ref") != "A-1" {
		t.Fatalf("numeric comparison on an integer member: %+v", large)
	}

	// Listing matches and sorts on the member columns too; an absent
	// envelope projects the zero value.
	list, err := reg.ListObjects(p, register.ListFilter{
		Class: "asset", Match: map[string]string{"asset_name": "Harbour telemetry"}, Order: "size_bytes", Desc: true,
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 || list[0].NaturalKey != "A-1" || list[1].NaturalKey != "A-2" {
		t.Fatalf("list by member: %+v", list)
	}
	all, err := reg.ListObjects(p, register.ListFilter{Class: "asset", Order: "size_bytes"})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 || all[0].NaturalKey != "A-3" {
		t.Fatalf("ascending by member with a zero-valued row: %+v", all)
	}
}
