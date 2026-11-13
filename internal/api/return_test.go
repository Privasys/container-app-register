// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Privasys/container-app-register/internal/auth"
)

// A reviewer may send a proposal back for more information: it closes
// without a decision on its merits, with the request recorded, and cannot
// be decided afterwards. The proposer may not send back their own.
func TestReturnForMoreInformation(t *testing.T) {
	ts, srv, reg := newTestServer(t)
	srv.Ready(reg, auth.DevVerifier{})
	clerkToken := "dev:clerk-1:Clerk:register:clerk"
	proposal := `{"payload":{"vin":"VF3CCHMZ3PT000097","make":"Peugeot","model":"208",
	  "year":2024,"colour":"red","fuel":"petrol","engine_cc":1199,
	  "first_registration":"2024-06-01","plate":"ZZ-997-ZZ"},
	  "evidence":{"proof_of_conformity":"` + strings.Repeat("c", 64) + `"}}`
	status, body := post(t, ts, "/api/v1/workflows/first_registration/propose", clerkToken, proposal)
	if status != http.StatusOK {
		t.Fatalf("propose = %d (%v)", status, body)
	}
	id, _ := body["task"].(map[string]any)["id"].(string)

	if status, _ := post(t, ts, "/api/v1/tasks/"+id+"/return", clerkToken, `{"reason":"more"}`); status == http.StatusOK {
		t.Fatal("the proposer sent back their own proposal")
	}
	if status, _ := post(t, ts, "/api/v1/tasks/"+id+"/return", registrarToken, `{"reason":"  "}`); status == http.StatusOK {
		t.Fatal("a return without saying what is needed was accepted")
	}
	status, body = post(t, ts, "/api/v1/tasks/"+id+"/return", registrarToken, `{"reason":"Attach the certificate of conformity"}`)
	if status != http.StatusOK {
		t.Fatalf("return = %d (%v)", status, body)
	}
	task, _ := body["task"].(map[string]any)
	if task["state"] != "returned" || task["decision_reason"] != "Attach the certificate of conformity" {
		t.Fatalf("returned task: %v", task)
	}
	if status, _ := post(t, ts, "/api/v1/tasks/"+id+"/decide", registrarToken, `{"approve":true}`); status == http.StatusOK {
		t.Fatal("a returned proposal was decided")
	}
}
