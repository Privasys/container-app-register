// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package drafts keeps the proposals people are still writing.
//
// A draft is not a record of the register: it is saved on every answer, and
// writing each save into the ledger would fill it with versions nobody will
// ever need. Drafts live beside the store, on the same sealed volume, so they
// are encrypted at rest and never leave the enclave; they are never kept in
// the browser. A draft becomes part of the ledger only when it is submitted,
// as a proposal, and is deleted then.
//
// A draft belongs to an owner: the person's organisation when they belong
// to one, so a colleague can carry on with it, and otherwise the person.
package drafts

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// MaxPayload bounds a draft, as a request body is bounded.
const MaxPayload = 1 << 20

// ErrConflict says the draft changed since the revision the writer read.
var ErrConflict = errors.New("the draft was changed elsewhere since you opened it")

// ErrNotFound says there is no such draft for this owner.
var ErrNotFound = errors.New("no such draft")

// Draft is one proposal in writing.
type Draft struct {
	ID       string         `json:"id"`
	Owner    string         `json:"owner"`
	Workflow string         `json:"workflow"`
	Title    string         `json:"title"`
	Payload  map[string]any `json:"payload,omitempty"`
	// Scheme is the version of the pack the draft was written against, so
	// a draft from an earlier version can be carried over or flagged.
	Scheme    string `json:"scheme"`
	CreatedBy string `json:"created_by"`
	CreatedAt int64  `json:"created_at"`
	UpdatedBy string `json:"updated_by"`
	UpdatedAt int64  `json:"updated_at"`
	Revision  int    `json:"revision"`
}

// Store keeps drafts in a directory, one file per draft, under a directory
// per owner named by a hash, so no name or subject appears on disk.
type Store struct {
	dir string
	mu  sync.Mutex
	now func() time.Time
}

// Open prepares a store in dir.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("drafts: %w", err)
	}
	return &Store{dir: dir, now: time.Now}, nil
}

// SetClock replaces the clock, for tests.
func (s *Store) SetClock(now func() time.Time) { s.now = now }

func (s *Store) ownerDir(tenant, owner string) string {
	sum := sha256.Sum256([]byte(tenant + "\x00" + owner))
	return filepath.Join(s.dir, hex.EncodeToString(sum[:16]))
}

func validID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func (s *Store) path(tenant, owner, id string) (string, error) {
	if !validID(id) {
		return "", ErrNotFound
	}
	return filepath.Join(s.ownerDir(tenant, owner), id+".json"), nil
}

func (s *Store) read(path string) (*Draft, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("drafts: %w", err)
	}
	var d Draft
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("drafts: %w", err)
	}
	return &d, nil
}

func (s *Store) write(path string, d *Draft) error {
	raw, err := json.Marshal(d)
	if err != nil {
		return err
	}
	if len(raw) > MaxPayload {
		return fmt.Errorf("a draft is at most %d KiB", MaxPayload/1024)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("drafts: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("drafts: %w", err)
	}
	return os.Rename(tmp, path)
}

// Create starts a draft.
func (s *Store) Create(tenant, owner, author, workflow, title, scheme string, payload map[string]any) (*Draft, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	at := s.now().Unix()
	d := &Draft{
		ID: hex.EncodeToString(raw), Owner: owner, Workflow: workflow, Title: title, Payload: payload, Scheme: scheme,
		CreatedBy: author, CreatedAt: at, UpdatedBy: author, UpdatedAt: at, Revision: 1,
	}
	path, _ := s.path(tenant, owner, d.ID)
	return d, s.write(path, d)
}

// Get reads one draft.
func (s *Store) Get(tenant, owner, id string) (*Draft, error) {
	path, err := s.path(tenant, owner, id)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.read(path)
}

// Save replaces a draft's title and payload, if it is still at the revision
// the writer read; the answer is the draft at its new revision.
func (s *Store) Save(tenant, owner, author, id string, revision int, title string, payload map[string]any) (*Draft, error) {
	path, err := s.path(tenant, owner, id)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.read(path)
	if err != nil {
		return nil, err
	}
	if d.Revision != revision {
		return d, ErrConflict
	}
	d.Title, d.Payload = title, payload
	d.UpdatedBy, d.UpdatedAt, d.Revision = author, s.now().Unix(), d.Revision+1
	return d, s.write(path, d)
}

// Delete removes a draft.
func (s *Store) Delete(tenant, owner, id string) error {
	path, err := s.path(tenant, owner, id)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(path); errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("drafts: %w", err)
	}
	return nil
}

// List returns an owner's drafts without their payloads, newest first.
func (s *Store) List(tenant, owner string) ([]*Draft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.ownerDir(tenant, owner))
	if errors.Is(err, os.ErrNotExist) {
		return []*Draft{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("drafts: %w", err)
	}
	out := []*Draft{}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		d, err := s.read(filepath.Join(s.ownerDir(tenant, owner), e.Name()))
		if err != nil {
			continue
		}
		d.Payload = nil
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt > out[j].UpdatedAt })
	return out, nil
}
