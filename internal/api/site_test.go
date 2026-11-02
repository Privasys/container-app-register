// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Privasys/container-app-register/internal/auth"
)

// writeSite lays out an adopter site in a temp dir: a layout with a
// content block, two pages, one shell, a static tree.
func writeSite(t *testing.T, siteJSON string) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"site.json":                   siteJSON,
		"templates/layout.html":       `<!doctype html><title>{{.Title}} - {{.Site}}</title><nav>{{range .Pages}}<a href="{{.Path}}">{{.Title}}</a>{{end}}</nav><main>{{block "content" .}}{{end}}</main><footer>{{.Register.Name}} {{.Register.Version}} {{.Register.State}} {{.Now.Year}}</footer>`,
		"templates/home.html":         `{{define "content"}}<h1>Welcome to {{.Site}}</h1>{{end}}{{template "layout.html" .}}`,
		"templates/help.html":         `{{define "content"}}<h1>Help for {{.Path}}</h1>{{end}}{{template "layout.html" .}}`,
		"app/index.html":              `<title>Shell</title>`,
		"static/app/assets/main.js":   `console.log(1)`,
		"static/govuk/govuk.css":      `body{}`,
		"static/brand/logo.svg":       `<svg/>`,
		"static/.hidden":              `no`,
		"static/sub/.hidden/file.txt": `no`,
	}
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const siteJSON = `{
  "title": "Example Register",
  "pages": [
    {"path": "/", "template": "home.html", "title": "Home"},
    {"path": "/help", "template": "help.html", "title": "Help"}
  ],
  "shells": [
    {"prefix": "/workspace", "index": "app/index.html"},
    {"prefix": "/operations", "index": "app/index.html"}
  ],
  "static": {"prefix": "/static/", "dir": "static"},
  "console": "/console",
  "join": "/workspace/join"
}`

// newSiteServer is a server with a console and an adopter site, before
// any register is configured.
func newSiteServer(t *testing.T, siteDir string) (*httptest.Server, *Server) {
	t.Helper()
	srv := NewServer(slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv.Version, srv.Name = "test", "test-register"
	web := t.TempDir()
	if err := os.WriteFile(filepath.Join(web, "index.html"), []byte("<title>Console</title>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(web, "assets"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(web, "assets", "app.js"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv.WebDir, srv.SiteDir = web, siteDir
	if err := srv.LoadSite(); err != nil {
		t.Fatalf("load site: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, srv
}

func fetch(t *testing.T, ts *httptest.Server, p string) (*http.Response, string) {
	t.Helper()
	resp, err := ts.Client().Get(ts.URL + p)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

// The adopter's pages take the root, the shells answer for their whole
// prefix, static files carry the right caching, and the console has
// moved to /console with its root-level files untouched.
func TestAdopterSiteRoutes(t *testing.T) {
	ts, _ := newSiteServer(t, writeSite(t, siteJSON))

	for _, tc := range []struct {
		path        string
		status      int
		contains    string
		contentType string
		cache       string
	}{
		{"/", 200, "<h1>Welcome to Example Register</h1>", "text/html; charset=utf-8", "no-cache"},
		{"/", 200, "<title>Home - Example Register</title>", "text/html; charset=utf-8", "no-cache"},
		{"/", 200, "test-register test awaiting_configuration", "text/html; charset=utf-8", "no-cache"},
		{"/help", 200, "<h1>Help for /help</h1>", "text/html; charset=utf-8", "no-cache"},
		{"/help", 200, `<a href="/help">Help</a>`, "text/html; charset=utf-8", "no-cache"},
		{"/workspace", 200, "<title>Shell</title>", "text/html; charset=utf-8", "no-cache"},
		{"/workspace/", 200, "<title>Shell</title>", "text/html; charset=utf-8", "no-cache"},
		{"/workspace/tasks/42", 200, "<title>Shell</title>", "text/html; charset=utf-8", "no-cache"},
		{"/operations/queue", 200, "<title>Shell</title>", "text/html; charset=utf-8", "no-cache"},
		{"/static/app/assets/main.js", 200, "console.log(1)", "", "public, max-age=31536000, immutable"},
		{"/static/govuk/govuk.css", 200, "body{}", "", "public, max-age=31536000, immutable"},
		{"/static/brand/logo.svg", 200, "<svg/>", "", "no-cache"},
		{"/static/.hidden", 404, "no such endpoint", "", ""},
		{"/static/sub/.hidden/file.txt", 404, "no such endpoint", "", ""},
		{"/static/", 404, "no such endpoint", "", ""},
		{"/static/app/", 404, "no such endpoint", "", ""},
		{"/static/missing.css", 404, "no such endpoint", "", ""},
		{"/console", 200, "<title>Console</title>", "text/html; charset=utf-8", "no-cache"},
		{"/console/", 200, "<title>Console</title>", "text/html; charset=utf-8", "no-cache"},
		{"/assets/app.js", 200, "1", "", "public, max-age=31536000, immutable"},
		{"/nowhere", 404, "no such endpoint", "", ""},
	} {
		resp, body := fetch(t, ts, tc.path)
		if resp.StatusCode != tc.status {
			t.Errorf("GET %s: status %d, want %d (%s)", tc.path, resp.StatusCode, tc.status, body)
			continue
		}
		if !strings.Contains(body, tc.contains) {
			t.Errorf("GET %s: body %q lacks %q", tc.path, body, tc.contains)
		}
		if tc.contentType != "" && resp.Header.Get("Content-Type") != tc.contentType {
			t.Errorf("GET %s: content type %q, want %q", tc.path, resp.Header.Get("Content-Type"), tc.contentType)
		}
		if tc.cache != "" && resp.Header.Get("Cache-Control") != tc.cache {
			t.Errorf("GET %s: cache-control %q, want %q", tc.path, resp.Header.Get("Cache-Control"), tc.cache)
		}
	}

	// The shell is served by the register, not redirected to it.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(ts.URL + "/workspace")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET /workspace without the slash: %d, want the shell, not a redirect", resp.StatusCode)
	}
	resp, err = client.Get(ts.URL + "/api/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("GET /api/v1/status before configuration: %d, want 503 (the API is untouched by a site)", resp.StatusCode)
	}
}

// Once configured, a page may show the pack's title.
func TestAdopterSitePageSeesTheConfiguredRegister(t *testing.T) {
	_, _, reg := newTestServer(t)
	ts, srv := newSiteServer(t, writeSite(t, siteJSON))
	// Replace the home page with one that prints the pack title.
	if err := os.WriteFile(filepath.Join(srv.SiteDir, "templates", "home.html"),
		[]byte(`{{define "content"}}<h1>{{.Register.Title}}</h1>{{end}}{{template "layout.html" .}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := srv.LoadSite(); err != nil {
		t.Fatal(err)
	}
	ts.Close()
	ts = httptest.NewServer(srv.Handler())
	defer ts.Close()

	_, body := fetch(t, ts, "/")
	if !strings.Contains(body, "<h1></h1>") || !strings.Contains(body, "awaiting_configuration") {
		t.Fatalf("before configuration: %s", body)
	}
	srv.Ready(reg, auth.DevVerifier{})
	_, body = fetch(t, ts, "/")
	if !strings.Contains(body, "<h1>"+reg.Pack().Title+"</h1>") || !strings.Contains(body, " ready ") {
		t.Fatalf("after configuration: %s", body)
	}
}

// Without a site nothing moves: the console is at the root and /console
// is nothing.
func TestNoSiteLeavesTheConsoleAtTheRoot(t *testing.T) {
	ts, _, _ := newTestServer(t)
	resp, body := fetch(t, ts, "/")
	if resp.StatusCode != 200 || !strings.Contains(body, "<title>Register</title>") {
		t.Fatalf("GET /: %d %s", resp.StatusCode, body)
	}
	resp, _ = fetch(t, ts, "/console")
	if resp.StatusCode != 404 {
		t.Fatalf("GET /console without a site: %d, want 404", resp.StatusCode)
	}
	resp, _ = fetch(t, ts, "/workspace")
	if resp.StatusCode != 404 {
		t.Fatalf("GET /workspace without a site: %d, want 404", resp.StatusCode)
	}
}

// A site that names a template, an index or a directory that is not
// there is refused before the server listens, with the defect named.
func TestAdopterSiteDefectsAreRefusedAtStartup(t *testing.T) {
	for _, tc := range []struct {
		name string
		json string
		want string
	}{
		{"missing template",
			`{"title":"x","pages":[{"path":"/about","template":"about.html","title":"About"}]}`,
			`page "/about" names template "about.html", which is not in`},
		{"missing shell index",
			`{"title":"x","shells":[{"prefix":"/workspace","index":"app/nope.html"}]}`,
			`shell /workspace index "app/nope.html" is not a file under`},
		{"missing static dir",
			`{"title":"x","static":{"prefix":"/static/","dir":"nope"}}`,
			`static dir "nope" is not a directory under`},
		{"reserved path",
			`{"title":"x","pages":[{"path":"/health","template":"home.html","title":"H"}]}`,
			`page path "/health" is the register's own`},
		{"reserved prefix",
			`{"title":"x","shells":[{"prefix":"/api","index":"app/index.html"}]}`,
			`shell path "/api" is under the register's /api/`},
		{"shell at root",
			`{"title":"x","shells":[{"prefix":"/","index":"app/index.html"}]}`,
			`a shell may not take the root`},
		{"duplicate",
			`{"title":"x","pages":[{"path":"/help","template":"help.html","title":"H"}],"shells":[{"prefix":"/help","index":"app/index.html"}]}`,
			`shell path "/help" is already a page`},
		{"bad join",
			`{"title":"x","join":"workspace/join"}`,
			`join path "workspace/join" must be absolute`},
		{"unknown field",
			`{"title":"x","colour":"red"}`,
			`unknown field "colour"`},
		{"no site.json", "", "site.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeSite(t, tc.json)
			if tc.json == "" {
				os.Remove(filepath.Join(dir, "site.json"))
			}
			srv := NewServer(slog.New(slog.NewTextHandler(io.Discard, nil)))
			srv.SiteDir = dir
			err := srv.LoadSite()
			if err == nil {
				t.Fatal("loaded a defective site")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name the defect %q", err, tc.want)
			}
		})
	}
}

// A site that names a join page gets invitation links that land on it,
// secret in the fragment; without one the console's join page is used.
func TestInvitationLinksFollowTheSiteJoinPage(t *testing.T) {
	_, _, reg := newTestServer(t)

	// With a site and a join page.
	_, srv := newSiteServer(t, writeSite(t, siteJSON))
	out := map[string]any{}
	if err := srv.bootstrapMembers(reg, []byte(`{"admin_invite":true}`), out); err != nil {
		t.Fatal(err)
	}
	link, _ := out["admin_invite"].(string)
	if !strings.HasPrefix(link, "/workspace/join/") || !strings.Contains(link, "#") || strings.Count(link, "/") != 3 {
		t.Fatalf("admin invitation link %q, want /workspace/join/<id>#<secret>", link)
	}
	if got := srv.inviteLink("abc", "s3cret"); got != "/workspace/join/abc#s3cret" {
		t.Fatalf("inviteLink = %q", got)
	}

	// With a site but no join page: the console link.
	plain := strings.Replace(siteJSON, `,
  "join": "/workspace/join"`, "", 1)
	_, srv = newSiteServer(t, writeSite(t, plain))
	if got := srv.inviteLink("abc", "s3cret"); got != "/#/join/abc/s3cret" {
		t.Fatalf("inviteLink without join = %q", got)
	}

	// Without a site at all.
	bare := NewServer(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if got := bare.inviteLink("abc", "s3cret"); got != "/#/join/abc/s3cret" {
		t.Fatalf("inviteLink without a site = %q", got)
	}
}
