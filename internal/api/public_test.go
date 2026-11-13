// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"net/http"
	"testing"

	"github.com/Privasys/container-app-register/internal/auth"
)

// markPublic marks some vehicle fields public in the starter pack.
func markPublic(fields ...string) func(map[string]any) {
	return func(p map[string]any) {
		for _, c := range p["classes"].([]any) {
			class := c.(map[string]any)
			if class["name"] != "vehicle" {
				continue
			}
			props := class["schema"].(map[string]any)["properties"].(map[string]any)
			for _, f := range fields {
				prop := props[f].(map[string]any)
				rules, _ := prop["x-register"].(map[string]any)
				if rules == nil {
					rules = map[string]any{}
				}
				rules["public"] = true
				prop["x-register"] = rules
			}
		}
	}
}

// Anyone reads the public fields of a public class without signing in,
// and nothing else: no other field, no class without public fields, no
// filter on a field that is not public.
func TestPublicReader(t *testing.T) {
	ts, srv, reg := newTestServerWith(t, markPublic("vin", "make", "model", "year"))
	srv.Ready(reg, auth.DevVerifier{})
	clerkToken := "dev:clerk-1:Clerk:register:clerk"
	status, body := post(t, ts, "/api/v1/workflows/first_registration/propose", clerkToken, `{"payload":{"vin":"VF3CCHMZ3PT000096","make":"Peugeot","model":"208",
	  "year":2024,"colour":"red","fuel":"petrol","engine_cc":1199,"first_registration":"2024-06-01","plate":"ZZ-996-ZZ"},
	  "evidence":{"proof_of_conformity":"`+"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"+`"}}`)
	if status != http.StatusOK {
		t.Fatalf("propose = %d (%v)", status, body)
	}
	id, _ := body["task"].(map[string]any)["id"].(string)
	if status, body = post(t, ts, "/api/v1/tasks/"+id+"/decide", registrarToken, `{"approve":true}`); status != http.StatusOK {
		t.Fatalf("decide = %d (%v)", status, body)
	}

	status, body = get(t, ts, "/public/v1/vehicle?q=VF3CCHMZ3PT000096", "")
	if status != http.StatusOK {
		t.Fatalf("public list = %d (%v)", status, body)
	}
	records, _ := body["records"].([]any)
	if len(records) != 1 {
		t.Fatalf("public list: %v", body)
	}
	fields := records[0].(map[string]any)["fields"].(map[string]any)
	if fields["make"] != "Peugeot" || fields["colour"] != nil || fields["plate"] != nil {
		t.Errorf("listed fields: %v", fields)
	}

	// Text search: a part of a public field, whatever its case of use.
	status, body = get(t, ts, "/public/v1/vehicle?q=eugeo", "")
	if records, _ := body["records"].([]any); status != http.StatusOK || len(records) != 1 {
		t.Fatalf("search by part of the make = %d (%v)", status, body)
	}
	if _, body = get(t, ts, "/public/v1/vehicle?q=red", ""); len(body["records"].([]any)) != 0 {
		t.Error("a search matched a field that is not public")
	}

	status, body = get(t, ts, "/public/v1/vehicle/VF3CCHMZ3PT000096", "")
	if status != http.StatusOK {
		t.Fatalf("public record = %d (%v)", status, body)
	}
	fields = body["fields"].(map[string]any)
	if fields["model"] != "208" || fields["engine_cc"] != nil || fields["first_registration"] != nil {
		t.Errorf("record fields: %v", fields)
	}
	if history, _ := body["history"].([]any); len(history) == 0 {
		t.Errorf("no history: %v", body)
	}

	if status, _ = get(t, ts, "/public/v1/owner", ""); status != http.StatusNotFound {
		t.Errorf("a class without public fields = %d, want 404", status)
	}
	if status, _ = get(t, ts, "/public/v1/vehicle?match.colour=red", ""); status == http.StatusOK {
		t.Error("a filter on a field that is not public was accepted")
	}
	if status, _ = get(t, ts, "/public/v1/vehicle/NOPE", ""); status != http.StatusNotFound {
		t.Errorf("an unknown record = %d, want 404", status)
	}
}
