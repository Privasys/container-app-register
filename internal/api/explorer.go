// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	_ "embed"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

//go:embed openapi.yaml
var openapiDoc []byte

// registerExplorer serves the browser UI and the API document.
//
// The UI is static, built into the image and so part of what the
// enclave measures: the page a person runs is code a verifier can read.
// It is a client of the same API everything else uses, so there is no
// privileged path into the register that only the console can take, and
// nothing the console shows that an auditor could not fetch for
// themselves.
//
// The shell is public and holds no data, which is why the image
// declares it readable in the clear: a browser has to load something
// before it can open a sealed session. Everything under /api stays
// sealed whatever the image declares.
func registerExplorer(mux *http.ServeMux, s *Server) {
	mux.HandleFunc("GET /openapi.yaml", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(openapiDoc)
	})
	// The explorer used to live under /explorer/; old links still land.
	for _, old := range []string{"GET /explorer", "GET /explorer/"} {
		mux.HandleFunc(old, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/", http.StatusFound)
		})
	}
	mux.Handle("/", s.staticHandler())
}

func (s *Server) staticHandler() http.Handler {
	dir := s.WebDir
	files := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			writeError(w, http.StatusMethodNotAllowed, "method not allowed", "")
			return
		}
		p := path.Clean("/" + r.URL.Path)
		index := filepath.Join(dir, "index.html")
		if p == "/" {
			if _, err := os.Stat(index); dir == "" || err != nil {
				// A build with no UI still says what it is.
				s.mu.RLock()
				state := s.state
				s.mu.RUnlock()
				writeJSON(w, http.StatusOK, map[string]any{
					"name": s.Name, "version": s.Version, "state": state,
					"api": "/api/v1/status", "openapi": "/openapi.yaml",
				})
				return
			}
			w.Header().Set("Cache-Control", "no-cache")
			http.ServeFile(w, r, index)
			return
		}
		// No directory listings, no dotfiles.
		if dir == "" || strings.Contains(p, "/.") {
			writeError(w, http.StatusNotFound, "no such endpoint", r.URL.Path)
			return
		}
		if fi, err := os.Stat(filepath.Join(dir, filepath.FromSlash(p))); err != nil || fi.IsDir() {
			writeError(w, http.StatusNotFound, "no such endpoint", r.URL.Path)
			return
		}
		if strings.HasPrefix(p, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		files.ServeHTTP(w, r)
	})
}
