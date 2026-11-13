// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Privasys/container-app-register/internal/pack"
	"github.com/Privasys/container-app-register/internal/register"
)

// vehicleSource is a national vehicle registry the car register takes
// vehicles from.
var vehicleSource = map[string]any{
	"name": "vehicle_registry", "title": "National vehicle registry", "class": "vehicle",
	"path": "/vehicles/{key}", "import_roles": []any{"registrar"},
	"fields": map[string]any{
		"vin":                map[string]any{"from": "vin"},
		"make":               map[string]any{"from": "maker.name"},
		"model":              map[string]any{"from": "model"},
		"year":               map[string]any{"from": "year"},
		"colour":             map[string]any{"from": "colour"},
		"fuel":               map[string]any{"from": "fuel"},
		"first_registration": map[string]any{"from": "registered_at", "date": true},
		"plate":              map[string]any{"from": "plate"},
	},
	"status": map[string]any{"from": "state", "map": map[string]any{"STOLEN": "stolen"}, "default": "registered"},
}

func carPackWith(t *testing.T, sources ...any) []byte {
	t.Helper()
	raw, err := os.ReadFile(packPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["sources"] = sources
	out, _ := json.Marshal(doc)
	return out
}

func vehicleDoc() map[string]any {
	return map[string]any{
		"vin": "1HGCM82633A004352", "maker": map[string]any{"name": "Honda"}, "model": "Accord", "year": 2003.0,
		"colour": "silver", "fuel": "petrol", "registered_at": "2003-05-14T09:30:00Z", "plate": "MAN 42",
	}
}

func TestASourceMapsAndValidates(t *testing.T) {
	pk, err := pack.Load(carPackWith(t, vehicleSource))
	if err != nil {
		t.Fatalf("pack with a source: %v", err)
	}
	payload, status, err := register.MapSource(pk, pk.Source("vehicle_registry"), vehicleDoc())
	if err != nil {
		t.Fatal(err)
	}
	if payload["make"] != "Honda" || payload["first_registration"] != "2003-05-14" || status != "registered" {
		t.Errorf("mapped %v as %s", payload, status)
	}
	stolen := vehicleDoc()
	stolen["state"] = "STOLEN"
	if _, status, _ := register.MapSource(pk, pk.Source("vehicle_registry"), stolen); status != "stolen" {
		t.Errorf("a stolen vehicle maps to %s", status)
	}

	base := func(edit func(map[string]any)) map[string]any {
		raw, _ := json.Marshal(vehicleSource)
		var s map[string]any
		_ = json.Unmarshal(raw, &s)
		edit(s)
		return s
	}
	for name, bad := range map[string]map[string]any{
		"unknown class":    base(func(s map[string]any) { s["class"] = "nothing" }),
		"unmapped key":     base(func(s map[string]any) { delete(s["fields"].(map[string]any), "vin") }),
		"unknown property": base(func(s map[string]any) { s["fields"].(map[string]any)["wheels"] = map[string]any{"from": "w"} }),
		"unknown role":     base(func(s map[string]any) { s["import_roles"] = []any{"pilot"} }),
		"no key in path":   base(func(s map[string]any) { s["path"] = "/vehicles" }),
		"unknown status":   base(func(s map[string]any) { s["status"].(map[string]any)["default"] = "lost" }),
	} {
		if _, err := pack.Load(carPackWith(t, bad)); err == nil {
			t.Errorf("%s: the pack loaded", name)
		}
	}
}

func TestBringingInARecordFromASource(t *testing.T) {
	h := newHarnessWith(t, t.TempDir(), carPackWith(t, vehicleSource))
	h.tick()
	registrar := h.principal("registrar-1", "registrar")
	doc := vehicleDoc()

	seen, err := h.reg.DescribeSource(registrar, "vehicle_registry", "1HGCM82633A004352", doc)
	if err != nil || seen.Held {
		t.Fatalf("before: %+v %v", seen, err)
	}
	rec, txn, err := h.reg.ImportFromSource(registrar, "vehicle_registry", "1HGCM82633A004352", doc)
	if err != nil || txn == nil || !rec.Held || rec.ObjectID == "" {
		t.Fatalf("import: %+v %v %v", rec, txn, err)
	}
	if !strings.Contains(txn.Envelope.Message, "from National vehicle registry") || txn.Envelope.Author.Role != "system" {
		t.Errorf("transaction %q by %+v", txn.Envelope.Message, txn.Envelope.Author)
	}

	// The same again records nothing; a change at the source is a new version.
	h.tick()
	if _, again, err := h.reg.ImportFromSource(registrar, "vehicle_registry", "1HGCM82633A004352", doc); err != nil || again != nil {
		t.Errorf("an unchanged import recorded %v (%v)", again, err)
	}
	doc["state"] = "STOLEN"
	h.tick()
	rec2, refreshed, err := h.reg.ImportFromSource(registrar, "vehicle_registry", "1HGCM82633A004352", doc)
	if err != nil || refreshed == nil || rec2.ObjectID != rec.ObjectID || rec2.Status != "stolen" {
		t.Errorf("a changed import: %+v %v %v", rec2, refreshed, err)
	}

	// The source must answer for the key it was asked about, and only the
	// roles the pack names may import.
	if _, _, err := h.reg.ImportFromSource(registrar, "vehicle_registry", "JH4KA7650MC000000", doc); err == nil {
		t.Error("a document for another key was imported")
	}
	citizen := h.principal("citizen-1", "citizen")
	if _, _, err := h.reg.ImportFromSource(citizen, "vehicle_registry", "1HGCM82633A004352", doc); err == nil || !strings.Contains(err.Error(), "may not") {
		t.Errorf("a citizen imported: %v", err)
	}
}

// A source's show list hands members of the document to whoever may bring
// the record in, without recording them in the record.
func TestASourceShowsWhatItDoesNotRecord(t *testing.T) {
	src := map[string]any{}
	for k, v := range vehicleSource {
		src[k] = v
	}
	src["show"] = []any{"keepers"}
	h := newHarnessWith(t, t.TempDir(), carPackWith(t, src))
	h.tick()
	registrar := h.principal("registrar-1", "registrar")
	doc := vehicleDoc()
	doc["keepers"] = []any{map[string]any{"name": "A. Keeper"}}

	seen, err := h.reg.DescribeSource(registrar, "vehicle_registry", "1HGCM82633A004352", doc)
	if err != nil {
		t.Fatal(err)
	}
	if keepers, _ := seen.Shown["keepers"].([]any); len(keepers) != 1 {
		t.Fatalf("shown: %+v", seen.Shown)
	}
	if _, recorded := seen.Payload["keepers"]; recorded {
		t.Error("a shown member was mapped into the record")
	}
}
