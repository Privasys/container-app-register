// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/drafts"
)

func TestADraftIsWrittenOverTimeAndSubmittedOnce(t *testing.T) {
	ts, srv, reg := newTestServer(t)
	srv.TrustSession = true
	store, err := drafts.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv.Drafts = store
	if _, err := reg.BootstrapMember("sub-clerk", "clerk"); err != nil {
		t.Fatal(err)
	}
	srv.Ready(reg, auth.DevVerifier{})

	status, out := call(t, ts, http.MethodPost, "/api/v1/drafts", "sub-clerk",
		`{"workflow":"register_owner","title":"A new owner","payload":{"kind":"company"}}`)
	if status != http.StatusOK {
		t.Fatalf("create: %d %v", status, out)
	}
	id := out["draft"].(map[string]any)["id"].(string)

	status, out = call(t, ts, http.MethodPut, "/api/v1/drafts/"+id, "sub-clerk",
		`{"revision":1,"title":"A new owner","payload":{"kind":"company","country":"IM"}}`)
	if status != http.StatusOK || out["draft"].(map[string]any)["revision"].(float64) != 2 {
		t.Fatalf("save: %d %v", status, out)
	}
	if status, _ := call(t, ts, http.MethodPut, "/api/v1/drafts/"+id, "sub-clerk", `{"revision":1,"payload":{}}`); status != http.StatusConflict {
		t.Errorf("a stale save answered %d", status)
	}
	if status, _ := call(t, ts, http.MethodGet, "/api/v1/drafts/"+id, "sub-nobody", ""); status == http.StatusOK {
		t.Error("someone else read the draft")
	}

	// Incomplete, the proposal is refused and the draft stays.
	if status, _ := call(t, ts, http.MethodPost, "/api/v1/drafts/"+id+"/submit", "sub-clerk", `{"revision":2}`); status != http.StatusBadRequest {
		t.Errorf("an incomplete draft was submitted: %d", status)
	}
	call(t, ts, http.MethodPut, "/api/v1/drafts/"+id, "sub-clerk",
		`{"revision":2,"title":"A new owner","payload":{"kind":"company","country":"IM","name":"Quayle Holdings","reference":"QH-0001"}}`)
	status, out = call(t, ts, http.MethodPost, "/api/v1/drafts/"+id+"/submit", "sub-clerk", `{"revision":3}`)
	if status != http.StatusOK || out["object_id"] == nil {
		t.Fatalf("submit: %d %v", status, out)
	}
	if status, _ := call(t, ts, http.MethodGet, "/api/v1/drafts/"+id, "sub-clerk", ""); status != http.StatusNotFound {
		t.Errorf("a submitted draft is still there: %d", status)
	}
	if status, out := call(t, ts, http.MethodPost, "/api/v1/drafts", "sub-clerk", `{"workflow":"flag_stolen"}`); status != http.StatusForbidden {
		t.Errorf("a clerk drafted for a workflow they may not propose: %d %v", status, fmt.Sprint(out))
	}
}
