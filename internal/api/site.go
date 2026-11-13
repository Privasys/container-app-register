// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// An adopter site is what an image built on the register puts in front
// of it: public pages rendered from templates, one or more single-page
// shells, and the static files they need. The register knows nothing of
// the adopter's domain; it serves what the site directory declares and
// moves its own console to /console so the root belongs to the adopter.
//
// The site is read once at startup from REGISTER_SITE_DIR (default
// /site when that directory exists). Its pages hold no register data
// and render before the configure gate lifts, like the console shell.
// Everything under /api stays behind the same authentication whatever
// the site declares.

// Site is the parsed site.json plus its templates.
type Site struct {
	Title   string      `json:"title"`
	Pages   []SitePage  `json:"pages"`
	Shells  []SiteShell `json:"shells"`
	Static  *SiteStatic `json:"static,omitempty"`
	Console string      `json:"console"`
	// Join, when set, is the page in one of the shells that redeems an
	// invitation: links become "<join>/<id>#<secret>" instead of the
	// console's "/#/join/<id>/<secret>".
	Join string `json:"join,omitempty"`
	// Records names the page that shows one record of a class, with
	// {key} for its natural key: where an identifier resolves to.
	Records map[string]string `json:"records,omitempty"`

	dir   string
	pages map[string]*template.Template // by page path
}

// SitePage is a server-rendered page.
type SitePage struct {
	Path     string `json:"path"`
	Template string `json:"template"`
	Title    string `json:"title"`
}

// SiteShell is a single-page application served for a whole prefix.
type SiteShell struct {
	Prefix string `json:"prefix"`
	Index  string `json:"index"`
}

// SiteStatic maps a URL prefix onto a directory of files.
type SiteStatic struct {
	Prefix string `json:"prefix"`
	Dir    string `json:"dir"`
}

// siteData is what a page template receives.
type siteData struct {
	Title    string
	Path     string
	Site     string
	Pages    []SitePage
	Register siteRegister
	Now      time.Time
}

// siteRegister is the little a public page may say about the register
// behind it.
type siteRegister struct {
	Name    string
	Version string
	State   string
	// Title is the pack's title once the register is configured.
	Title string
}

// reservedPaths are the register's own routes a site may not shadow.
var reservedPaths = []string{
	"/health", "/readiness", "/app-config.js", "/version", "/privasys.json",
	"/configure", "/openapi.yaml", "/explorer", "/favicon.svg",
}

// reservedPrefixes are subtrees that stay the register's.
var reservedPrefixes = []string{"/api/", "/tools/", "/assets/", "/vendor/", "/brand/", "/explorer/"}

// LoadSite reads the adopter site named by SiteDir. With no SiteDir it
// does nothing, and the register serves as it always has. Any defect
// in the site is refused here, before the server listens, so a broken
// image fails its readiness probe rather than serving half a site.
func (s *Server) LoadSite() error {
	if s.SiteDir == "" {
		return nil
	}
	site, err := loadSite(s.SiteDir)
	if err != nil {
		return err
	}
	s.site = site
	return nil
}

func loadSite(dir string) (*Site, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "site.json"))
	if err != nil {
		return nil, fmt.Errorf("site: %w", err)
	}
	site := &Site{dir: dir}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(site); err != nil {
		return nil, fmt.Errorf("site: %s: %w", filepath.Join(dir, "site.json"), err)
	}
	if site.Console == "" {
		site.Console = "/console"
	}
	if err := site.validate(); err != nil {
		return nil, err
	}
	if err := site.parseTemplates(); err != nil {
		return nil, err
	}
	return site, nil
}

func (site *Site) validate() error {
	seen := map[string]string{}
	claim := func(p, what string) error {
		if p == "" || !strings.HasPrefix(p, "/") {
			return fmt.Errorf("site: %s path %q must start with /", what, p)
		}
		if p != "/" && (strings.HasSuffix(p, "/") || path.Clean(p) != p) {
			return fmt.Errorf("site: %s path %q must be clean and carry no trailing slash", what, p)
		}
		for _, r := range reservedPaths {
			if p == r {
				return fmt.Errorf("site: %s path %q is the register's own", what, p)
			}
		}
		for _, r := range reservedPrefixes {
			if strings.HasPrefix(p+"/", r) {
				return fmt.Errorf("site: %s path %q is under the register's %s", what, p, r)
			}
		}
		if prev, dup := seen[p]; dup {
			return fmt.Errorf("site: %s path %q is already a %s", what, p, prev)
		}
		seen[p] = what
		return nil
	}
	if err := claim(site.Console, "console"); err != nil {
		return err
	}
	for _, p := range site.Pages {
		if err := claim(p.Path, "page"); err != nil {
			return err
		}
		if p.Template == "" || strings.Contains(p.Template, "/") || strings.Contains(p.Template, "\\") {
			return fmt.Errorf("site: page %q names template %q; a template is a file name under templates/", p.Path, p.Template)
		}
	}
	for _, sh := range site.Shells {
		if sh.Prefix == "/" {
			return errors.New("site: a shell may not take the root; declare a page for / instead")
		}
		if err := claim(sh.Prefix, "shell"); err != nil {
			return err
		}
		if err := site.exists(sh.Index, "shell "+sh.Prefix+" index"); err != nil {
			return err
		}
	}
	if site.Join != "" {
		if !strings.HasPrefix(site.Join, "/") || strings.HasSuffix(site.Join, "/") || path.Clean(site.Join) != site.Join {
			return fmt.Errorf("site: join path %q must be absolute, clean and carry no trailing slash", site.Join)
		}
		for _, r := range reservedPrefixes {
			if strings.HasPrefix(site.Join+"/", r) {
				return fmt.Errorf("site: join path %q is under the register's %s", site.Join, r)
			}
		}
	}
	if st := site.Static; st != nil {
		if st.Prefix == "" || !strings.HasPrefix(st.Prefix, "/") || !strings.HasSuffix(st.Prefix, "/") || st.Prefix == "/" {
			return fmt.Errorf("site: static prefix %q must start and end with / and not be the root", st.Prefix)
		}
		if err := claim(strings.TrimSuffix(st.Prefix, "/"), "static"); err != nil {
			return err
		}
		if st.Dir == "" {
			return errors.New("site: static dir is empty")
		}
		fi, err := os.Stat(filepath.Join(site.dir, filepath.FromSlash(st.Dir)))
		if err != nil || !fi.IsDir() {
			return fmt.Errorf("site: static dir %q is not a directory under %s", st.Dir, site.dir)
		}
	}
	return nil
}

// exists checks a site-relative file, refusing anything that escapes
// the site directory.
func (site *Site) exists(rel, what string) error {
	clean := path.Clean("/" + filepath.ToSlash(rel))
	if rel == "" || strings.HasPrefix(clean, "/..") {
		return fmt.Errorf("site: %s %q is not a file under %s", what, rel, site.dir)
	}
	fi, err := os.Stat(filepath.Join(site.dir, filepath.FromSlash(clean)))
	if err != nil || fi.IsDir() {
		return fmt.Errorf("site: %s %q is not a file under %s", what, rel, site.dir)
	}
	return nil
}

// parseTemplates builds one template per page. Every *.html under
// templates/ that is not itself a page (the layout, partials) is shared
// by all pages; each page file is parsed on its own clone of that base,
// so two pages may each define a "content" block without colliding.
func (site *Site) parseTemplates() error {
	tdir := filepath.Join(site.dir, "templates")
	files, err := filepath.Glob(filepath.Join(tdir, "*.html"))
	if err != nil {
		return fmt.Errorf("site: %w", err)
	}
	sort.Strings(files)
	isPage := map[string]bool{}
	for _, p := range site.Pages {
		isPage[p.Template] = true
	}
	base := template.New("")
	for _, f := range files {
		if isPage[filepath.Base(f)] {
			continue
		}
		if _, err := base.ParseFiles(f); err != nil {
			return fmt.Errorf("site: %w", err)
		}
	}
	site.pages = map[string]*template.Template{}
	for _, p := range site.Pages {
		file := filepath.Join(tdir, p.Template)
		if fi, err := os.Stat(file); err != nil || fi.IsDir() {
			return fmt.Errorf("site: page %q names template %q, which is not in %s", p.Path, p.Template, tdir)
		}
		set, err := base.Clone()
		if err != nil {
			return fmt.Errorf("site: %w", err)
		}
		if _, err := set.ParseFiles(file); err != nil {
			return fmt.Errorf("site: %w", err)
		}
		t := set.Lookup(p.Template)
		if t == nil {
			return fmt.Errorf("site: page %q: template %q did not define itself", p.Path, p.Template)
		}
		site.pages[p.Path] = t
	}
	return nil
}

// registerSite wires the site's routes. It is called before the console
// takes "/", and only when a site is loaded.
func registerSite(mux *http.ServeMux, s *Server) {
	site := s.site

	// The root is the adopter's. Declared, it is a page; otherwise it is
	// nothing, never the console.
	if _, ok := site.pages["/"]; !ok {
		mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
			writeError(w, http.StatusNotFound, "no such endpoint", r.URL.Path)
		})
	}
	for _, p := range site.Pages {
		pattern := "GET " + p.Path
		if p.Path == "/" {
			pattern = "GET /{$}"
		}
		mux.HandleFunc(pattern, s.sitePage(p))
	}
	for _, sh := range site.Shells {
		h := s.siteShell(sh)
		mux.HandleFunc("GET "+sh.Prefix, h)
		mux.HandleFunc("GET "+sh.Prefix+"/", h)
	}
	if st := site.Static; st != nil {
		mux.HandleFunc("GET "+st.Prefix, s.siteStatic(*st))
	}
	console := func(w http.ResponseWriter, r *http.Request) {
		index := filepath.Join(s.WebDir, "index.html")
		if _, err := os.Stat(index); s.WebDir == "" || err != nil {
			writeError(w, http.StatusNotFound, "no console in this build", r.URL.Path)
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeFile(w, r, index)
	}
	mux.HandleFunc("GET "+site.Console, console)
	mux.HandleFunc("GET "+site.Console+"/", console)
}

func (s *Server) sitePage(p SitePage) http.HandlerFunc {
	t := s.site.pages[p.Path]
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		state, reg := s.state, s.reg
		s.mu.RUnlock()
		info := siteRegister{Name: s.Name, Version: s.Version, State: state}
		if reg != nil && state == StateReady {
			info.Title = reg.Pack().Title
		}
		data := siteData{
			Title:    p.Title,
			Path:     p.Path,
			Site:     s.site.Title,
			Pages:    s.site.Pages,
			Register: info,
			Now:      time.Now().UTC(),
		}
		var buf strings.Builder
		if err := t.Execute(&buf, data); err != nil {
			s.log.Error("site page", "path", p.Path, "err", err)
			writeError(w, http.StatusInternalServerError, "the page could not be rendered", "")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write([]byte(buf.String()))
	}
}

func (s *Server) siteShell(sh SiteShell) http.HandlerFunc {
	index := filepath.Join(s.site.dir, filepath.FromSlash(path.Clean("/"+sh.Index)))
	return func(w http.ResponseWriter, r *http.Request) {
		// Any path under the prefix is the application's to route.
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeFile(w, r, index)
	}
}

func (s *Server) siteStatic(st SiteStatic) http.HandlerFunc {
	root := filepath.Join(s.site.dir, filepath.FromSlash(st.Dir))
	return func(w http.ResponseWriter, r *http.Request) {
		rel := strings.TrimPrefix(path.Clean("/"+r.URL.Path), strings.TrimSuffix(st.Prefix, "/"))
		rel = strings.TrimPrefix(rel, "/")
		// No directory listings, no dotfiles, nothing above the root.
		if rel == "" || strings.Contains("/"+rel, "/.") {
			writeError(w, http.StatusNotFound, "no such endpoint", r.URL.Path)
			return
		}
		file := filepath.Join(root, filepath.FromSlash(rel))
		if fi, err := os.Stat(file); err != nil || fi.IsDir() {
			writeError(w, http.StatusNotFound, "no such endpoint", r.URL.Path)
			return
		}
		if strings.HasPrefix(rel, "app/assets/") || strings.HasPrefix(rel, "govuk/") {
			// Hashed build output and the vendored design system never
			// change under one name.
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		http.ServeFile(w, r, file)
	}
}

// inviteLink is the relative link that redeems an invitation. The
// secret rides in the fragment, which a browser never sends to any
// server, so the register sees it again only when the invitee presents
// it. The console's own join page takes it unless the adopter site
// names one of its own.
func (s *Server) inviteLink(id, secret string) string {
	if s.site != nil && s.site.Join != "" {
		return s.site.Join + "/" + id + "#" + secret
	}
	return "/#/join/" + id + "/" + secret
}
