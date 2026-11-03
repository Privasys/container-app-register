package api

import (
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
