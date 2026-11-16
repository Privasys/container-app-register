// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/Privasys/container-app-register/internal/register"
)

// The register at a size people will run it: a wide class of vehicles
// with a dozen projected value envelopes and an assigned identifier, and
// an event class of inspections whose proposal condition counts vehicles
// by VIN. REGISTER_PERF=<vehicles>[,<inspections>] runs it; it is slow by
// design and off otherwise. REGISTER_PERF_DIR keeps the data directory, so
// a second run can time the reads on a register already filled.
func TestRegisterAtScale(t *testing.T) {
	spec := os.Getenv("REGISTER_PERF")
	if spec == "" {
		t.Skip("REGISTER_PERF not set")
	}
	vehicles, inspections := 10000, 2000
	if _, err := fmt.Sscanf(spec, "%d,%d", &vehicles, &inspections); err != nil {
		vehicles, _ = strconv.Atoi(spec)
	}
	dir := os.Getenv("REGISTER_PERF_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	fresh := true
	if _, err := os.Stat(filepath.Join(dir, "register")); err == nil {
		fresh = false
	}
	h := newHarnessWith(t, dir, []byte(perfPack))
	clerk := h.principal("clerk-1", "clerk")

	envelope := func(v any) map[string]any { return map[string]any{"value": v, "status": "declared"} }
	vin := func(i int) string { return fmt.Sprintf("VF1PERF%010d", i) }
	if fresh {
		start := time.Now()
		for i := 0; i < vehicles; i++ {
			h.tick()
			payload := map[string]any{"vin": vin(i)}
			for c := 0; c < 12; c++ {
				payload[fmt.Sprintf("field_%02d", c)] = envelope(fmt.Sprintf("value %d of vehicle %d with words in it", c, i))
			}
			payload["model"] = envelope([]string{"Golf", "Clio", "Polo", "Megane"}[i%4])
			if _, err := h.reg.Propose(clerk, "register_vehicle", register.ProposeRequest{Payload: payload}); err != nil {
				t.Fatalf("vehicle %d: %v", i, err)
			}
			if (i+1)%1000 == 0 {
				t.Logf("vehicles %d: %.1f/s", i+1, float64(i+1)/time.Since(start).Seconds())
			}
		}
		start = time.Now()
		for i := 0; i < inspections; i++ {
			h.tick()
			if _, err := h.reg.Propose(clerk, "record_inspection", register.ProposeRequest{Payload: map[string]any{
				"ref": fmt.Sprintf("INS-%08d", i), "vin": vin(i % vehicles), "result": "pass", "inspector": "Ada",
			}}); err != nil {
				t.Fatalf("inspection %d: %v", i, err)
			}
			if (i+1)%500 == 0 {
				t.Logf("inspections %d: %.2f/s, last at %s", i+1, float64(i+1)/time.Since(start).Seconds(), time.Since(start)/time.Duration(i+1))
			}
		}
	}

	timed := func(name string, f func() (int, error)) {
		t.Helper()
		start := time.Now()
		n, err := f()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		t.Logf("%-40s %8.3f s  (%d)", name, time.Since(start).Seconds(), n)
	}
	reader := h.principal("registrar-1", "registrar")
	target := vin(vehicles / 2)
	timed("status (waits for the first count)", func() (int, error) {
		s, err := h.reg.Status()
		if err != nil {
			return 0, err
		}
		return int(s.Objects), nil
	})
	timed("list vehicles, first page (index cold)", func() (int, error) {
		rows, err := h.reg.ListObjects(reader, register.ListFilter{Class: "vehicle", Limit: 50})
		return len(rows), err
	})
	timed("list vehicles, page 20, newest first", func() (int, error) {
		rows, err := h.reg.ListObjects(reader, register.ListFilter{Class: "vehicle", Limit: 50, Offset: 950, Desc: true})
		return len(rows), err
	})
	timed("list vehicles, first page", func() (int, error) {
		rows, err := h.reg.ListObjects(reader, register.ListFilter{Class: "vehicle", Limit: 50})
		return len(rows), err
	})
	timed("vehicles where vin = X (natural key)", func() (int, error) {
		rows, err := h.reg.ListObjects(reader, register.ListFilter{Class: "vehicle", Match: map[string]string{"vin": target}})
		return len(rows), err
	})
	timed("vehicles where model = X (indexed)", func() (int, error) {
		rows, err := h.reg.ListObjects(reader, register.ListFilter{Class: "vehicle", Match: map[string]string{"model": "Clio"}, Limit: 50})
		return len(rows), err
	})
	timed("inspections where vin = X", func() (int, error) {
		rows, err := h.reg.ListObjects(reader, register.ListFilter{Class: "inspection", Match: map[string]string{"vin": target}})
		return len(rows), err
	})
	timed("public search vehicles, q=word", func() (int, error) {
		rows, err := h.reg.PublicList("vehicle", "words", nil, 50, 0)
		return len(rows), err
	})
	timed("public search, ~1/3 of records match", func() (int, error) {
		rows, err := h.reg.PublicList("vehicle", "of vehicle 1", nil, 50, 0)
		return len(rows), err
	})
	timed("public search vehicles, rare word", func() (int, error) {
		rows, err := h.reg.PublicList("vehicle", fmt.Sprintf("of vehicle %d with", vehicles/3), nil, 50, 0)
		return len(rows), err
	})
	timed("public search again (index warm)", func() (int, error) {
		rows, err := h.reg.PublicList("vehicle", fmt.Sprintf("of vehicle %d with", vehicles/4), nil, 50, 0)
		return len(rows), err
	})
	timed("public get vehicle", func() (int, error) {
		_, err := h.reg.PublicGet("vehicle", target)
		return 1, err
	})
	timed("status", func() (int, error) {
		s, err := h.reg.Status()
		if err != nil {
			return 0, err
		}
		return int(s.Objects), nil
	})
	timed("one inspection proposal (condition)", func() (int, error) {
		h.tick()
		_, err := h.reg.Propose(clerk, "record_inspection", register.ProposeRequest{Payload: map[string]any{
			"ref": fmt.Sprintf("INS-X-%d", time.Now().UnixNano()), "vin": target, "result": "pass", "inspector": "Ada",
		}})
		return 1, err
	})
}

var perfPack = func() string {
	fields := ""
	for c := 0; c < 12; c++ {
		fields += fmt.Sprintf(`"field_%02d": {"type": "object", "properties": {"value": {"type": "string"}, "status": {"type": "string"}},
		  "x-register": {"queryable": true, "member": "value", "public": true}},`, c)
	}
	return `{
  "name": "perf", "title": "Vehicle register at scale", "version": "1.0.0", "tenant": "gov",
  "roles": [
    {"name": "registrar", "title": "Registrar", "oidc_roles": ["register:registrar"], "permissions": ["read:*", "propose:*", "approve:*"]},
    {"name": "clerk", "title": "Clerk", "oidc_roles": ["register:clerk"], "permissions": ["read:*", "propose:*"]}
  ],
  "classes": [
    {"name": "vehicle", "title": "Vehicle", "natural_key": "vin", "statuses": ["registered"], "initial_status": "registered", "encryption": "none",
     "schema": {"type": "object", "additionalProperties": false, "required": ["vin"], "properties": {
       ` + fields + `
       "model": {"type": "object", "properties": {"value": {"type": "string"}, "status": {"type": "string"}},
         "x-register": {"queryable": true, "indexed": true, "member": "value", "public": true}},
       "vin": {"type": "string", "x-register": {"queryable": true, "unique": true, "public": true}}}}},
    {"name": "inspection", "title": "Inspection", "natural_key": "ref", "statuses": ["recorded"], "initial_status": "recorded", "encryption": "none",
     "schema": {"type": "object", "additionalProperties": false, "required": ["ref", "vin", "result"], "properties": {
       "ref": {"type": "string", "x-register": {"queryable": true, "unique": true}},
       "vin": {"type": "string", "x-register": {"queryable": true, "indexed": true}},
       "result": {"type": "string"}, "inspector": {"type": "string"}}}}
  ],
  "workflows": [
    {"name": "register_vehicle", "title": "Register a vehicle", "class": "vehicle", "action": "create",
     "propose_roles": ["clerk"], "approve_roles": ["registrar"], "auto_approve": true, "message": "Register {{payload.vin}}"},
    {"name": "amend_vehicle", "title": "Amend a vehicle", "class": "vehicle", "action": "update",
     "propose_roles": ["clerk"], "approve_roles": ["registrar"], "auto_approve": true, "message": "Amend {{object.natural_key}}"},
    {"name": "record_inspection", "title": "Record an inspection", "class": "inspection", "action": "create",
     "propose_roles": ["clerk"], "approve_roles": ["registrar"], "auto_approve": true, "message": "Inspect {{payload.vin}}",
     "conditions": [{"id": "vehicle_known", "description": "The vehicle is registered",
       "sql": "SELECT COUNT(*) FROM ` + "`q_vehicle`" + ` WHERE tenant = {{tenant}} AND vin = {{payload.vin}}",
       "expect": "nonzero", "on_fail": "reject", "message": "no such vehicle"}]}
  ]
}`
}()

// A search reads the text index, which sees records changed after it was
// built, applies the listing's other conditions, and pages in order.
func TestASearchSeesChangesAndPages(t *testing.T) {
	h := newHarnessWith(t, t.TempDir(), []byte(perfPack))
	clerk := h.principal("clerk-1", "clerk")
	reader := h.principal("registrar-1", "registrar")
	env := func(v string) map[string]any { return map[string]any{"value": v, "status": "declared"} }
	ids := map[string]string{}
	for i, model := range []string{"Golf Blue", "Golf Red", "Clio Blue"} {
		h.tick()
		vin := fmt.Sprintf("VF1TEXT%010d", i)
		out, err := h.reg.Propose(clerk, "register_vehicle", register.ProposeRequest{Payload: map[string]any{"vin": vin, "model": env(model)}})
		if err != nil {
			t.Fatal(err)
		}
		ids[vin] = out.ObjectID
	}
	search := func(text string, f register.ListFilter) []string {
		t.Helper()
		f.Class, f.Text, f.TextColumns = "vehicle", text, []string{"model"}
		rows, err := h.reg.ListObjects(reader, f)
		if err != nil {
			t.Fatal(err)
		}
		var keys []string
		for _, r := range rows {
			keys = append(keys, r.NaturalKey)
		}
		return keys
	}
	if got := search("blue", register.ListFilter{}); fmt.Sprint(got) != "[VF1TEXT0000000000 VF1TEXT0000000002]" {
		t.Fatalf("blue: %v", got)
	}
	if got := search("BLUE", register.ListFilter{Desc: true, Limit: 1, Offset: 1}); fmt.Sprint(got) != "[VF1TEXT0000000000]" {
		t.Fatalf("second blue, newest first: %v", got)
	}
	if got := search("blue", register.ListFilter{Match: map[string]string{"model": "Clio Blue"}}); fmt.Sprint(got) != "[VF1TEXT0000000002]" {
		t.Fatalf("blue and a match: %v", got)
	}
	if got := search("vf1text0000000001", register.ListFilter{}); fmt.Sprint(got) != "[VF1TEXT0000000001]" {
		t.Fatalf("by natural key: %v", got)
	}

	// A change after the index was built is seen by the next search.
	h.tick()
	if _, err := h.reg.Propose(clerk, "amend_vehicle", register.ProposeRequest{ObjectID: ids["VF1TEXT0000000001"],
		Payload: map[string]any{"vin": "VF1TEXT0000000001", "model": env("Golf Blue")}}); err != nil {
		t.Fatal(err)
	}
	if got := search("red", register.ListFilter{}); len(got) != 0 {
		t.Fatalf("red after the change: %v", got)
	}
	if got := search("blue", register.ListFilter{}); fmt.Sprint(got) != "[VF1TEXT0000000000 VF1TEXT0000000002 VF1TEXT0000000001]" {
		t.Fatalf("blue after the change: %v", got)
	}
}
