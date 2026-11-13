// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Privasys/container-app-register/internal/auth"
)

// A document comes back only through a proposal the caller may see that
// names it in its evidence: the Registrar reads the instrument of the
// application in front of them, and nothing else.
func TestDocumentReadThroughItsProposal(t *testing.T) {
	ts, srv, reg := newTestServer(t)
	srv.Ready(reg, auth.DevVerifier{})
	srv.Documents = t.TempDir()
	clerkToken := "dev:clerk-1:Clerk:register:clerk"

	content := "%PDF-1.4 a certificate of conformity\n"
	_, uploaded := post(t, ts, "/api/v1/documents", clerkToken, content)
	digest, _ := uploaded["digest"].(string)
	if len(digest) != 64 {
		t.Fatalf("upload: %v", uploaded)
	}
	proposal := `{"payload":{"vin":"VF3CCHMZ3PT000098","make":"Peugeot","model":"208",
	  "year":2024,"colour":"red","fuel":"petrol","engine_cc":1199,
	  "first_registration":"2024-06-01","plate":"ZZ-998-ZZ"},
	  "evidence":{"proof_of_conformity":"` + digest + `"}}`
	status, body := post(t, ts, "/api/v1/workflows/first_registration/propose", clerkToken, proposal)
	if status != http.StatusOK {
		t.Fatalf("propose = %d (%v)", status, body)
	}
	taskID, _ := body["task"].(map[string]any)["id"].(string)

	fetch := func(path string) (int, http.Header, string) {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+registrarToken)
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header, string(b)
	}

	status, h, got := fetch("/api/v1/documents/" + digest + "?task=" + taskID)
	if status != http.StatusOK || got != content {
		t.Fatalf("download = %d %q", status, got)
	}
	if !strings.Contains(h.Get("Content-Disposition"), `filename="proof_of_conformity.pdf"`) || h.Get("Content-Type") != "application/pdf" {
		t.Errorf("headers: %v", h)
	}
	if status, _, _ := fetch("/api/v1/documents/" + digest); status == http.StatusOK {
		t.Error("a document was served without its proposal")
	}
	if status, _, _ := fetch("/api/v1/documents/" + strings.Repeat("b", 64) + "?task=" + taskID); status == http.StatusOK {
		t.Error("a document the proposal does not name was served")
	}
	if status, _, _ := fetch("/api/v1/documents/" + digest + "?task=nope"); status == http.StatusOK {
		t.Error("a document was served through a proposal that does not exist")
	}
}
