// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

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
