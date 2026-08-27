// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed web/*
var explorerFS embed.FS

//go:embed openapi.yaml
var openapiDoc []byte

// registerExplorer serves the operator explorer and the API document.
//
// The explorer is static: it is a client of the same API everything
// else uses, so there is no privileged path into the register that only
// the operator console can take, and nothing the console shows that an
// auditor could not fetch for themselves.
func registerExplorer(mux *http.ServeMux, s *Server) {
	assets, err := fs.Sub(explorerFS, "web")
	if err != nil {
		panic("api: explorer assets: " + err.Error())
	}
	files := http.FileServer(http.FS(assets))
	mux.Handle("GET /explorer/", http.StripPrefix("/explorer/", files))
	mux.HandleFunc("GET /explorer", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/explorer/", http.StatusFound)
	})
	mux.HandleFunc("GET /openapi.yaml", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(openapiDoc)
	})
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			writeError(w, http.StatusNotFound, "no such endpoint", r.URL.Path)
			return
		}
		s.mu.RLock()
		state := s.state
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"name": s.Name, "version": s.Version, "state": state,
			"explorer": "/explorer/", "api": "/api/v1/status", "openapi": "/openapi.yaml",
		})
	})
}
