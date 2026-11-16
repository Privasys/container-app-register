// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Privasys/container-app-register/internal/auth"
)

// A site page reads the public reader before it renders: a record by the
// path's key, then what that record names, a search from the query string,
// and the site's data files, with no JavaScript. A record that is not
// there is a 404 that still renders the page.
func TestAPageReadsThePublicRegister(t *testing.T) {
	_, srv, reg := newTestServerWith(t, markPublic("vin", "make", "model", "year"))
	srv.Ready(reg, auth.DevVerifier{})
	dir := t.TempDir()
	files := map[string]string{
		"site.json": `{"title":"Vehicles", "data": {"labels": "data/labels.json"},
		  "pages": [
		    {"path": "/vehicles", "template": "list.html", "title": "Search",
		     "reads": {"results": {"class": "vehicle", "q": "{query.q}", "limit": 10}}},
		    {"path": "/vehicles/{key}", "template": "vehicle.html", "title": "Vehicle",
		     "reads": {"vehicle": {"class": "vehicle", "key": "{path.key}", "required": true},
		               "same_make": {"class": "vehicle", "q": "{vehicle.fields.make}", "full": true}}}],
		  "shells": [{"prefix": "/vehicles", "index": "app/index.html"}]}`,
		"data/labels.json":       `{"make": "Manufacturer"}`,
		"app/index.html":         `<title>Shell</title>`,
		"templates/layout.html":  `<main>{{block "content" .}}{{end}}</main>`,
		"templates/list.html":    `{{define "content"}}{{range .Reads.results}}<li>{{.key}} {{upper .fields.make}}</li>{{end}}q={{.Query.Get "q"}}{{end}}{{template "layout.html" .}}`,
		"templates/vehicle.html": `{{define "content"}}{{if .Missing}}Not found: {{.Params.key}}{{else}}{{with .Reads.vehicle}}<h1>{{.key}}</h1>{{index $.Data.labels "make"}}: {{.fields.make}}; {{kind .fields.year}} {{default "none" .fields.colour}}; created {{date .created_at}}{{end}}; same make {{len .Reads.same_make}}, history {{len (index .Reads.same_make 0).history}}{{end}}{{end}}{{template "layout.html" .}}`,
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
	srv.SiteDir = dir
	if err := srv.LoadSite(); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	resp, body := fetch(t, ts, "/vehicles/WVWZZZ1JZXW000001")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "<h1>WVWZZZ1JZXW000001</h1>Manufacturer: Volkswagen; number none; created") ||
		!strings.Contains(body, "same make 1, history 1") {
		t.Fatalf("record page %d: %s", resp.StatusCode, body)
	}
	resp, body = fetch(t, ts, "/vehicles/NOPE")
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(body, "Not found: NOPE") {
		t.Fatalf("missing record %d: %s", resp.StatusCode, body)
	}
	resp, body = fetch(t, ts, "/vehicles?q=VF1")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "<li>VF1RFB00X66000002 RENAULT</li>") || !strings.Contains(body, "q=VF1") ||
		strings.Contains(body, "WVWZZZ") {
		t.Fatalf("search page %d: %s", resp.StatusCode, body)
	}
	// The page took the shell's own path; the shell keeps what is below.
	if resp, body = fetch(t, ts, "/vehicles/app/settings"); !strings.Contains(body, "<title>Shell</title>") {
		t.Fatalf("shell below the page %d: %s", resp.StatusCode, body)
	}
}
