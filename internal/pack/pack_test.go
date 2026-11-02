// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package pack_test

import (
	"os"
	"strings"
	"testing"

	"github.com/Privasys/container-app-register/internal/pack"
)

// A projection may not shadow the columns every query table carries on
// its own; the loader says which property to rename.
func TestProjectedColumnsCannotShadowTheQueryTable(t *testing.T) {
	doc, err := os.ReadFile("../../packs/car-register/pack.json")
	if err != nil {
		t.Fatal(err)
	}
	const colour = `"colour": { "type": "string", "maxLength": 32, "x-register": { "queryable": true } }`
	if !strings.Contains(string(doc), colour) {
		t.Fatal("the fixture no longer declares colour as the test expects")
	}
	for _, reserved := range []string{"status", "tenant", "object_id", "updated_at"} {
		bad := strings.Replace(string(doc), colour,
			`"colour": { "type": "string", "maxLength": 32, "x-register": { "queryable": true, "column": "`+reserved+`" } }`, 1)
		_, err := pack.Load([]byte(bad))
		want := `class "vehicle" property "colour" projects to column "` + reserved + `", which the query table reserves`
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("column %s: err = %v, want %q", reserved, err, want)
		}
	}
	if _, err := pack.Load(doc); err != nil {
		t.Fatalf("the unmodified pack must load: %v", err)
	}
}
