// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/checkpoint"
	"github.com/Privasys/container-app-register/internal/keys"
	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/pack"
	"github.com/Privasys/container-app-register/internal/register"
	"github.com/Privasys/container-app-register/internal/store"
)

const registrarToken = "dev:registrar-1:Registrar:register:registrar"

func newTestServer(t *testing.T) (*httptest.Server, *Server, *register.Register) {
	t.Helper()
	doc, err := os.ReadFile("../../packs/car-register/pack.json")
	if err != nil {
		t.Fatalf("read pack: %v", err)
	}
	loaded, err := pack.Load(doc)
	if err != nil {
		t.Fatalf("load pack: %v", err)
	}
	dir := t.TempDir()
	material, err := keys.Load(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	ck, source, err := material.CommitmentKey(nil)
	if err != nil {
		t.Fatalf("commitment key: %v", err)
	}
	st, err := store.Open(filepath.Join(dir, "register"), ck)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	reg, err := register.New(st, loaded, material, register.Options{
		Name: "test-register", Tenant: "gov", KeySource: source,
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	srv := NewServer(slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv.Version, srv.Name = "test", "test-register"
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, srv, reg
}

func get(t *testing.T, ts *httptest.Server, path, token string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, ts.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var decoded map[string]any
	_ = json.Unmarshal(body, &decoded)
	return resp.StatusCode, decoded
}

func post(t *testing.T, ts *httptest.Server, path, token, payload string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var decoded map[string]any
	_ = json.Unmarshal(body, &decoded)
	return resp.StatusCode, decoded
}

// An unconfigured register serves its health probe and nothing else.
// That is the platform contract: the enclave manager holds every other
// path at 503 until the deployer has configured the app, and the app
// says the same thing on its own account.
func TestUnconfiguredServesOnlyHealth(t *testing.T) {
	ts, _, _ := newTestServer(t)

	status, body := get(t, ts, "/health", "")
	if status != http.StatusOK {
		t.Fatalf("health = %d", status)
	}
	if body["state"] != StateAwaitingConfiguration {
		t.Errorf("state = %v", body["state"])
	}

	if status, _ := get(t, ts, "/api/v1/status", registrarToken); status != http.StatusServiceUnavailable {
		t.Errorf("status before configuration = %d, want 503", status)
	}
}

func TestAuthenticationAndRoles(t *testing.T) {
	ts, srv, reg := newTestServer(t)
	srv.Ready(reg, auth.DevVerifier{})

	if status, _ := get(t, ts, "/api/v1/status", ""); status != http.StatusUnauthorized {
		t.Errorf("no token = %d, want 401", status)
	}
	if status, _ := get(t, ts, "/api/v1/status", "dev:nobody:Nobody:some:other-role"); status != http.StatusUnauthorized {
		t.Errorf("a token with no register role = %d, want 401", status)
	}

	status, body := get(t, ts, "/api/v1/me", registrarToken)
	if status != http.StatusOK {
		t.Fatalf("me = %d (%v)", status, body)
	}
	principal, _ := body["principal"].(map[string]any)
	if principal["acting_role"] != "registrar" {
		t.Errorf("acting role = %v", principal["acting_role"])
	}
}

func TestReadPaths(t *testing.T) {
	ts, srv, reg := newTestServer(t)
	srv.Ready(reg, auth.DevVerifier{})

	status, body := get(t, ts, "/api/v1/pack", registrarToken)
	if status != http.StatusOK {
		t.Fatalf("pack = %d (%v)", status, body)
	}
	classes, _ := body["classes"].([]any)
	if len(classes) != 5 {
		t.Errorf("expected 5 classes, got %d", len(classes))
	}

	status, body = get(t, ts, "/api/v1/records?class=vehicle", registrarToken)
	if status != http.StatusOK {
		t.Fatalf("records = %d (%v)", status, body)
	}
	records, _ := body["records"].([]any)
	if len(records) != 2 {
		t.Fatalf("expected the two seeded vehicles, got %d", len(records))
	}
	first, _ := records[0].(map[string]any)
	id, _ := first["id"].(string)

	if status, body = get(t, ts, "/api/v1/records/"+id+"/history", registrarToken); status != http.StatusOK {
		t.Errorf("history = %d (%v)", status, body)
	}
	if status, body = get(t, ts, "/api/v1/log?limit=5", registrarToken); status != http.StatusOK {
		t.Errorf("log = %d (%v)", status, body)
	}
	if status, body = get(t, ts, "/api/v1/records/vehicle-nope", registrarToken); status != http.StatusNotFound {
		t.Errorf("an unregistered record = %d, want 404 (%v)", status, body)
	}
}

func TestProofEndpointAndVerificationKey(t *testing.T) {
	ts, srv, reg := newTestServer(t)
	srv.Ready(reg, auth.DevVerifier{})

	status, body := get(t, ts, "/api/v1/proofs/natural-keys/vehicle/WVWZZZ1JZXW000001", registrarToken)
	if status != http.StatusOK {
		t.Fatalf("proof = %d (%v)", status, body)
	}
	if body["present"] != true {
		t.Errorf("expected the VIN to be present: %v", body)
	}
	for _, field := range []string{"proof", "path", "root", "signature", "key_id"} {
		if body[field] == nil || body[field] == "" {
			t.Errorf("the bundle has no %s", field)
		}
	}

	status, body = get(t, ts, "/api/v1/checkpoints/key", registrarToken)
	if status != http.StatusOK || body["public_key"] == "" {
		t.Fatalf("verification key = %d (%v)", status, body)
	}
}

func TestToolEndpoints(t *testing.T) {
	ts, srv, reg := newTestServer(t)
	srv.Ready(reg, auth.DevVerifier{})

	status, body := post(t, ts, "/tools/lookup", registrarToken,
		`{"class":"vehicle","natural_key":"WVWZZZ1JZXW000001"}`)
	if status != http.StatusOK {
		t.Fatalf("lookup = %d (%v)", status, body)
	}
	if body["registered"] != true || body["record"] == nil {
		t.Errorf("lookup did not return the record: %v", body)
	}

	status, body = post(t, ts, "/tools/lookup", registrarToken,
		`{"class":"vehicle","natural_key":"WVWZZZ1JZXW999999"}`)
	if status != http.StatusOK || body["registered"] != false {
		t.Fatalf("an unregistered VIN should answer with an absence proof: %d %v", status, body)
	}

	status, body = post(t, ts, "/tools/query", registrarToken, `{"name":"vehicles_by_status"}`)
	if status != http.StatusOK {
		t.Fatalf("query = %d (%v)", status, body)
	}
	if rows, _ := body["rows"].([]any); len(rows) == 0 {
		t.Error("the query returned nothing")
	}
}

func TestWriteThroughTheAPI(t *testing.T) {
	ts, srv, reg := newTestServer(t)
	srv.Ready(reg, auth.DevVerifier{})

	clerkToken := "dev:clerk-1:Clerk:register:clerk"
	proposal := `{"payload":{"vin":"VF3CCHMZ3PT000099","make":"Peugeot","model":"208",
	  "year":2024,"colour":"red","fuel":"petrol","engine_cc":1199,
	  "first_registration":"2024-06-01","plate":"ZZ-999-ZZ"},
	  "evidence":{"proof_of_conformity":"` + strings.Repeat("a", 64) + `"}}`

	status, body := post(t, ts, "/api/v1/workflows/first_registration/propose", clerkToken, proposal)
	if status != http.StatusOK {
		t.Fatalf("propose = %d (%v)", status, body)
	}
	task, _ := body["task"].(map[string]any)
	taskID, _ := task["id"].(string)
	if taskID == "" {
		t.Fatalf("no task id in %v", body)
	}

	// The clerk proposed; the clerk may not decide.
	if status, _ = post(t, ts, "/api/v1/tasks/"+taskID+"/decide", clerkToken, `{"approve":true}`); status != http.StatusForbidden {
		t.Errorf("clerk decision = %d, want 403", status)
	}

	status, body = post(t, ts, "/api/v1/tasks/"+taskID+"/decide", registrarToken,
		`{"approve":true,"reason":"documents in order"}`)
	if status != http.StatusOK {
		t.Fatalf("decide = %d (%v)", status, body)
	}
	applied, _ := body["applied"].(map[string]any)
	if applied == nil {
		t.Fatalf("the approval committed nothing: %v", body)
	}

	// A messageless transaction cannot be constructed through the API:
	// the summary comes from the workflow's template when the caller
	// gives none, and the envelope refuses an empty one either way.
	status, body = get(t, ts, "/api/v1/log?limit=1", registrarToken)
	if status != http.StatusOK {
		t.Fatalf("log = %d", status)
	}
	entries, _ := body["transactions"].([]any)
	entry, _ := entries[0].(map[string]any)
	envelope, _ := entry["envelope"].(map[string]any)
	if summary, _ := envelope["message"].(string); summary == "" {
		t.Error("the committed transaction has no message")
	}
}

func TestExplorerAndOpenAPIAreServed(t *testing.T) {
	ts, _, _ := newTestServer(t)
	resp, err := ts.Client().Get(ts.URL + "/explorer/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "Register explorer") {
		t.Errorf("explorer = %d, %d bytes", resp.StatusCode, len(body))
	}

	resp, err = ts.Client().Get(ts.URL + "/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	doc, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(doc), "openapi:") {
		t.Errorf("openapi = %d, %d bytes", resp.StatusCode, len(doc))
	}
}

// The evidence a caller receives over HTTP must verify with the public
// key the register publishes. Anything that changes on the way out —
// an encoder that reorders, a number that loses its form — breaks the
// signature, and it must break it here rather than in a courtroom.
func TestEvidenceOverHTTPVerifies(t *testing.T) {
	ts, srv, reg := newTestServer(t)
	srv.Ready(reg, auth.DevVerifier{})

	// Commit something first, so the evidence is anchored by a
	// checkpoint issued at runtime rather than the one from bootstrap.
	clerkToken := "dev:clerk-1:Clerk:register:clerk"
	proposal := `{"payload":{"vin":"VF3CCHMZ3PT000077","make":"Peugeot","model":"208",
	  "year":2024,"colour":"red","fuel":"petrol","engine_cc":1199,
	  "first_registration":"2024-06-01","plate":"YY-777-YY"},
	  "evidence":{"proof_of_conformity":"` + strings.Repeat("a", 64) + `"}}`
	if _, err := reg.IssueCheckpoint(register.ReasonBootstrap); err != nil {
		t.Fatal(err)
	}
	if status, body := post(t, ts, "/api/v1/workflows/first_registration/propose", clerkToken, proposal); status != http.StatusOK {
		t.Fatalf("propose = %d (%v)", status, body)
	}

	keyID, publicKeyB64 := reg.VerificationKey()
	_ = keyID
	pub, err := checkpoint.ParsePublicKey(publicKeyB64)
	if err != nil {
		t.Fatal(err)
	}

	raw := getRaw(t, ts, "/api/v1/proofs/natural-keys/vehicle/WVWZZZ1JZXW000001", registrarToken)
	var bundle model.EvidenceBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatalf("decode bundle: %v", err)
	}
	if err := checkpoint.VerifyBundleProof(&bundle); err != nil {
		t.Errorf("proof: %v", err)
	}
	if err := checkpoint.VerifyBundleSignature(pub, &bundle); err != nil {
		t.Errorf("bundle signature after an HTTP round trip: %v", err)
	}
	if bundle.Checkpoint == nil {
		t.Fatal("the bundle carries no anchor")
	}
	if err := checkpoint.VerifyCheckpoint(pub, bundle.Checkpoint); err != nil {
		t.Errorf("checkpoint signature after an HTTP round trip: %v", err)
	}
	if err := checkpoint.VerifyBundleAgainstCheckpoint(&bundle, &bundle.Checkpoint.Checkpoint); err != nil {
		t.Errorf("anchor: %v", err)
	}

	// And every checkpoint the chain endpoint serves.
	chainRaw := getRaw(t, ts, "/api/v1/checkpoints?limit=50", registrarToken)
	var chain struct {
		Checkpoints []model.SignedCheckpoint `json:"checkpoints"`
	}
	if err := json.Unmarshal(chainRaw, &chain); err != nil {
		t.Fatal(err)
	}
	if len(chain.Checkpoints) < 2 {
		t.Fatalf("expected a chain, got %d", len(chain.Checkpoints))
	}
	for i := range chain.Checkpoints {
		sc := chain.Checkpoints[i]
		if err := checkpoint.VerifyCheckpoint(pub, &sc); err != nil {
			t.Errorf("checkpoint %d: %v", sc.Checkpoint.Version, err)
		}
	}
}

func getRaw(t *testing.T, ts *httptest.Server, path, token string) []byte {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, ts.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s = %d: %s", path, resp.StatusCode, body)
	}
	return body
}
