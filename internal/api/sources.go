// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"context"
	"errors"
	"fmt"

	"github.com/Privasys/container-app-register/internal/source"
)

// fetchFromSource reads one document from a configured source, once the
// caller is known to be allowed to import from it. The fetch happens
// outside any transaction: a slow source must not hold the store.
func (s *Server) fetchFromSource(ctx context.Context, req *request, name, key string) (map[string]any, error) {
	src, err := req.reg.CanImport(req.p, name)
	if err != nil {
		return nil, err
	}
	fetchers := s.Sources.Load()
	if fetchers == nil || (*fetchers)[name] == nil {
		return nil, fmt.Errorf("the source %s is not configured on this register", name)
	}
	doc, err := (*fetchers)[name].Fetch(ctx, src.PathFor(key))
	if errors.Is(err, source.ErrNotFound) {
		return nil, fmt.Errorf("no such record at %s: %s", name, key)
	}
	return doc, err
}

// describeSource shows what the source holds for a key and whether the
// register already holds it, without recording anything.
func (s *Server) describeSource(req *request) (any, error) {
	name, key := req.r.PathValue("name"), req.r.PathValue("key")
	doc, err := s.fetchFromSource(req.r.Context(), req, name, key)
	if err != nil {
		return nil, err
	}
	return req.reg.DescribeSource(req.p, name, key, doc)
}

// importFromSource records what the source holds for a key.
func (s *Server) importFromSource(req *request) (any, error) {
	name, key := req.r.PathValue("name"), req.r.PathValue("key")
	doc, err := s.fetchFromSource(req.r.Context(), req, name, key)
	if err != nil {
		return nil, err
	}
	record, txn, err := req.reg.ImportFromSource(req.p, name, key, doc)
	if err != nil {
		return nil, err
	}
	return map[string]any{"record": record, "transaction": txn}, nil
}
