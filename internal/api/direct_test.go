package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Privasys/container-app-register/internal/auth"
)

// On a direct adopter name the runtime ends TLS in the enclave with a public
// certificate, stamps the transport, and identifies a signed-in user from a
// privasys.id token it verified: the register sees the subject and how the
// person signed in, never the token.
func TestDirectLegIsReportedAndAssuranceIsRecorded(t *testing.T) {
	ts, srv, reg := newTestServer(t)
	srv.TrustSession = true
	srv.Ready(reg, auth.DevVerifier{})

	// The page learns it is on a direct name from the runtime config.
	for _, tc := range []struct {
		transport string
		direct    bool
	}{{"", false}, {"sealed", false}, {"direct", true}} {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/app-config.js", nil)
		req.Host = "diom-dar.test.privasys.org"
		if tc.transport != "" {
			req.Header.Set("X-Privasys-Transport", tc.transport)
		}
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if got := strings.Contains(string(body), `"direct":true`); got != tc.direct {
			t.Fatalf("transport %q: direct flag %v in %s", tc.transport, got, body)
		}
	}

	// A caller identified by the runtime carries the sign-in assurance.
	for _, tc := range []struct {
		level string
		want  string
	}{{"", ""}, {"verified", "verified"}, {"unverified", "unverified"}, {"bogus", ""}} {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/me", nil)
		req.Header.Set("X-Privasys-Sub", "sub-direct")
		if tc.level != "" {
			req.Header.Set("X-Privasys-Attestation-Level", tc.level)
		}
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("level %q: status %d %s", tc.level, resp.StatusCode, body)
		}
		has := strings.Contains(string(body), `"assurance":"`+tc.want+`"`)
		if tc.want == "" {
			has = !strings.Contains(string(body), `"assurance"`)
		}
		if !has {
			t.Fatalf("level %q: want assurance %q in %s", tc.level, tc.want, body)
		}
	}
}

// An adopter narrows the federated identities its gate offers through the
// runtime config; the register itself has no opinion.
func TestSignInProvidersReachThePage(t *testing.T) {
	ts, srv, reg := newTestServer(t)
	srv.TrustSession = true
	srv.Ready(reg, auth.DevVerifier{})
	for _, tc := range []struct {
		providers []string
		want      string
	}{{nil, ""}, {[]string{"microsoft"}, `"providers":["microsoft"]`}} {
		srv.SignInProviders = tc.providers
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/app-config.js", nil)
		req.Host = "diom-dar.test.privasys.org"
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if tc.want == "" && strings.Contains(string(body), `"providers"`) {
			t.Fatalf("no providers set, got %s", body)
		}
		if tc.want != "" && !strings.Contains(string(body), tc.want) {
			t.Fatalf("want %s in %s", tc.want, body)
		}
	}
}

// The page asks for a token whose audience is the app, so it must learn the
// app's identifier from the runtime configuration, and only when there is one.
func TestAppIDReachesThePage(t *testing.T) {
	ts, srv, reg := newTestServer(t)
	srv.TrustSession = true
	srv.Ready(reg, auth.DevVerifier{})
	for _, tc := range []struct{ appID, want string }{{"", ""}, {"bf8c3811703b4f5c85607486c31154b7", `"appId":"bf8c3811703b4f5c85607486c31154b7"`}} {
		srv.AppID = tc.appID
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/app-config.js", nil)
		req.Host = "diom-dar.test.privasys.org"
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if tc.want == "" && strings.Contains(string(body), `"appId"`) {
			t.Fatalf("no app id set, got %s", body)
		}
		if tc.want != "" && !strings.Contains(string(body), tc.want) {
			t.Fatalf("want %s in %s", tc.want, body)
		}
	}
}

// The identity provider keeps no profile, so only the first request after a
// sign-in says who the person is: the register records the address and the
// name then, and knows the person from the record on every later request.
// What the runtime would never have written is not recorded.
func TestTheProfileAssertedAtSignInIsKeptForLaterRequests(t *testing.T) {
	ts, srv, reg := newTestServer(t)
	srv.TrustSession = true
	srv.Ready(reg, auth.DevVerifier{})
	me := func(sub, email, name string) map[string]any {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/me", nil)
		req.Header.Set("X-Privasys-Sub", sub)
		if email != "" {
			req.Header.Set("X-Privasys-Email", email)
		}
		if name != "" {
			req.Header.Set("X-Privasys-Name", name)
		}
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d: %v", resp.StatusCode, err)
		}
		return out
	}
	expect := func(out map[string]any, display, email string) {
		t.Helper()
		if out["display"] != display || (email == "" && out["email"] != nil) || (email != "" && out["email"] != email) {
			t.Fatalf("want display %q email %q, got display %v email %v", display, email, out["display"], out["email"])
		}
	}

	// Never seen: the register knows only the subject.
	expect(me("sub-profile", "", ""), "", "")
	// The first request after the sign-in carries the profile, name percent-encoded.
	expect(me("sub-profile", "b.foing@example.gov.im", "Bertrand%20Foing"), "Bertrand Foing", "b.foing@example.gov.im")
	// Later requests carry nothing, and the person is still known.
	expect(me("sub-profile", "", ""), "Bertrand Foing", "b.foing@example.gov.im")
	// Another subject is another person.
	expect(me("sub-other", "", ""), "", "")
	// A sign-in with a changed name updates it; UTF-8 survives the encoding.
	expect(me("sub-profile", "", "Bertrand%20F%C3%B6ing"), "Bertrand Föing", "b.foing@example.gov.im")
	// What the runtime would never write is ignored: a bad escape, a control
	// character, an address that is not one.
	expect(me("sub-profile", "not an address", "%ZZ"), "Bertrand Föing", "b.foing@example.gov.im")
	expect(me("sub-profile", "", "line%0Abreak"), "Bertrand Föing", "b.foing@example.gov.im")

	// The record is the register's own, readable without a request.
	p, err := reg.Profile("sub-profile")
	if err != nil || p.Name != "Bertrand Föing" || p.Email != "b.foing@example.gov.im" || p.FirstSeen == 0 {
		t.Fatalf("profile %+v: %v", p, err)
	}

	// A grant made without a display, such as the configure call's admins,
	// shows the recorded name in the member listing.
	if err := srv.bootstrapMembers(reg, []byte(`{"admins":"sub-profile"}`), map[string]any{}); err != nil {
		t.Fatal(err)
	}
	status, members := call(t, ts, http.MethodGet, "/api/v1/members", "sub-profile", "")
	listed, _ := members["members"].([]any)
	if status != http.StatusOK || len(listed) != 1 || listed[0].(map[string]any)["display"] != "Bertrand Föing" {
		t.Fatalf("members = %d %v, want the recorded name on the bootstrap grant", status, members)
	}
}

// A configure call that names the installation's client replaces the one
// the image was built with.
func TestConfiguredClientReachesThePage(t *testing.T) {
	ts, srv, reg := newTestServer(t)
	srv.Ready(reg, auth.DevVerifier{})
	srv.ClientID = "built-in"
	get := func() string {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/app-config.js", nil)
		req.Host = "diom-dar-uat.privasys.org"
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return string(body)
	}
	if body := get(); !strings.Contains(body, `"clientId":"built-in"`) {
		t.Fatalf("built-in client missing: %s", body)
	}
	id := "uat-client"
	srv.SignInClient.Store(&id)
	if body := get(); !strings.Contains(body, `"clientId":"uat-client"`) {
		t.Fatalf("configured client missing: %s", body)
	}
}
