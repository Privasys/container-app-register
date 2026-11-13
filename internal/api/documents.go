// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// MaxDocument bounds one uploaded document.
const MaxDocument = 25 << 20

// uploadDocument keeps a document on the sealed volume, named by its
// SHA-256, and answers with the digest. The document itself never enters
// the ledger, which would grow with every file: a proposal records only the
// digest, which proves the document unchanged. The same document uploaded
// twice is kept once.
func (s *Server) uploadDocument(req *request) (any, error) {
	if s.Documents == "" {
		return nil, errors.New("this register keeps no documents")
	}
	if req.p == nil {
		return nil, errors.New("a document is uploaded by a member of the register")
	}
	if err := os.MkdirAll(s.Documents, 0o700); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(s.Documents, "upload-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, hash), io.LimitReader(req.r.Body, MaxDocument+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	if n > MaxDocument {
		return nil, fmt.Errorf("a document is at most %d MiB", MaxDocument>>20)
	}
	if n == 0 {
		return nil, errors.New("the document is empty")
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	final := filepath.Join(s.Documents, digest)
	if _, err := os.Stat(final); errors.Is(err, os.ErrNotExist) {
		if err := os.Rename(tmp.Name(), final); err != nil {
			return nil, err
		}
	}
	return map[string]any{"digest": digest, "algorithm": "SHA-256", "size": n}, nil
}

// written says a handler has written its own response.
type written struct{}

// downloadDocument hands back a document the caller may read: one whose
// digest a proposal they can see names in its evidence. The register keeps
// no file name or type, so the type is detected and the name is the
// evidence's own (dedication_instrument.pdf, for instance).
func (s *Server) downloadDocument(req *request) (any, error) {
	digest := req.r.PathValue("digest")
	if !sha256Hex.MatchString(digest) {
		return nil, errors.New("a document is named by its SHA-256 digest")
	}
	taskID := req.r.URL.Query().Get("task")
	if taskID == "" {
		return nil, errors.New("name the proposal the document belongs to")
	}
	task, err := req.reg.Task(req.p, taskID)
	if err != nil {
		return nil, err
	}
	name := ""
	for key, v := range task.Evidence {
		if d, _ := v.(string); d == digest {
			name = key
		}
	}
	if name == "" || s.Documents == "" {
		return nil, fmt.Errorf("no document %s in proposal %s", digest, taskID)
	}
	f, err := os.Open(filepath.Join(s.Documents, digest))
	if err != nil {
		return nil, fmt.Errorf("no document %s in proposal %s", digest, taskID)
	}
	defer f.Close()
	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	kind := http.DetectContentType(head[:n])
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	ext := ""
	switch {
	case strings.HasPrefix(kind, "application/pdf"):
		ext = ".pdf"
	case strings.HasPrefix(kind, "text/plain"):
		ext = ".txt"
	}
	h := req.w.Header()
	h.Set("Content-Type", kind)
	h.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s%s"`, name, ext))
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "private, no-store")
	req.w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(req.w, f)
	return written{}, nil
}
