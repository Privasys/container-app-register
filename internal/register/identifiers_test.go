// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register_test

import (
	"encoding/json"
	"os"
	"regexp"
	"testing"

	"github.com/Privasys/container-app-register/internal/register"
)

func TestCheckDigitsAreISO7064Mod9710(t *testing.T) {
	// A Legal Entity Identifier carries the same check digits.
	for _, lei := range []string{"5493001KJTIIGC8Y1R12", "7LTWFZYICNSX8D621K86"} {
		if !register.Valid97(lei) {
			t.Errorf("%s does not validate", lei)
		}
	}
	if got := register.Check97("IMDAR20277K3QX9"); !register.Valid97("IMDAR20277K3QX9" + got) {
		t.Errorf("check digits %s do not validate", got)
	}
	if register.Valid97("IM-DAR-2027-7K3QX9-00") && register.Valid97("IM-DAR-2027-7K3QX9-01") {
		t.Error("two different check digits both validate")
	}
}

// The car register's owners with a reference the register assigns.
func carPackWithOwnerIdentifier(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(packPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, c := range doc["classes"].([]any) {
		if class := c.(map[string]any); class["name"] == "owner" {
			class["identifiers"] = []any{map[string]any{
				"property": "reference", "format": "OWN-{year}-{serial:6}-{check}", "time_zone": "Europe/Isle_of_Man",
			}}
		}
	}
	out, _ := json.Marshal(doc)
	return out
}

func TestTheRegisterAssignsIdentifiers(t *testing.T) {
	h := newHarnessWith(t, t.TempDir(), carPackWithOwnerIdentifier(t))
	clerk := h.principal("clerk-1", "clerk")
	shape := regexp.MustCompile(`^OWN-2026-[0-9A-HJKMNP-TV-Z]{6}-[0-9]{2}$`)
	seen := map[string]bool{}
	previous := ""
	for i := 0; i < 25; i++ {
		h.tick()
		out, err := h.reg.Propose(clerk, "register_owner", register.ProposeRequest{Payload: map[string]any{
			"kind": "company", "country": "IM", "name": "Owner " + string(rune('A'+i)),
		}})
		if err != nil {
			t.Fatalf("owner %d: %v", i, err)
		}
		view, err := h.reg.GetObject(clerk, out.ObjectID)
		if err != nil {
			t.Fatal(err)
		}
		ref, _ := view.Version.Payload["reference"].(string)
		if !shape.MatchString(ref) || !register.Valid97(ref) {
			t.Fatalf("assigned %q", ref)
		}
		if seen[ref] {
			t.Fatalf("%s assigned twice", ref)
		}
		seen[ref] = true
		// Consecutive records must not get neighbouring serials.
		if previous != "" && ref[9:15] > previous[9:15] && ref[9:14] == previous[9:14] {
			t.Errorf("%s follows %s too closely", ref, previous)
		}
		previous = ref
	}

}

func TestTheSerialPermutationNeverRepeats(t *testing.T) {
	seen := map[uint64]bool{}
	for counter := uint64(0); counter < 1024; counter++ {
		v := register.Permute([]byte("key"), "2026", counter, 10)
		if v >= 1024 || seen[v] {
			t.Fatalf("counter %d gave %d, out of range or repeated", counter, v)
		}
		seen[v] = true
	}
}
