// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package source fetches documents from the external registers a pack
// declares, or from a stand-in for one.
//
// Where a source is lives in configuration, not in the pack: the same
// pack runs against a mock in testing and against the real source in
// production, and production simply never names the mock.
package source

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ErrNotFound says the source holds no document at that location.
var ErrNotFound = errors.New("the source holds no such record")

// Fetcher reads one document from a source.
type Fetcher interface {
	Fetch(ctx context.Context, path string) (map[string]any, error)
}

// Setting is where one source is: a mock file or an https address.
type Setting struct {
	// Mock names a JSON file in the image mapping each path to its
	// document, for testing and demonstrations.
	Mock string `json:"mock,omitempty"`
	// URL is the source's https base address.
	URL string `json:"url,omitempty"`
}

// Fetcher builds the fetcher a setting describes.
func (s Setting) Fetcher() (Fetcher, error) {
	switch {
	case s.Mock != "" && s.URL != "":
		return nil, errors.New("source: a source is either a mock or an address, not both")
	case s.Mock != "":
		return LoadMock(s.Mock)
	case strings.HasPrefix(s.URL, "https://"):
		base, err := url.Parse(strings.TrimRight(s.URL, "/"))
		if err != nil {
			return nil, fmt.Errorf("source: %w", err)
		}
		return &HTTP{Base: base, Client: &http.Client{Timeout: 15 * time.Second}}, nil
	default:
		return nil, errors.New("source: give a mock file or an https address")
	}
}

const settingsFile = "sources.json"

// LoadSettings reads the source settings an earlier configure call left on
// the volume; empty when there are none.
func LoadSettings(dir string) (map[string]Setting, error) {
	raw, err := os.ReadFile(filepath.Join(dir, settingsFile))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]Setting{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("source: %w", err)
	}
	out := map[string]Setting{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("source: %s: %w", settingsFile, err)
	}
	return out, nil
}

// SaveSettings writes the source settings to the volume.
func SaveSettings(dir string, settings map[string]Setting) error {
	raw, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, settingsFile), raw, 0o600)
}

// Mock answers from a file of documents keyed by path.
type Mock struct {
	docs map[string]map[string]any
}

// LoadMock reads a mock file.
func LoadMock(file string) (*Mock, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("source: mock: %w", err)
	}
	m := &Mock{}
	if err := json.Unmarshal(raw, &m.docs); err != nil {
		return nil, fmt.Errorf("source: mock %s: %w", file, err)
	}
	return m, nil
}

// NewMock builds a mock from documents keyed by path.
func NewMock(docs map[string]map[string]any) *Mock { return &Mock{docs: docs} }

func (m *Mock) Fetch(_ context.Context, path string) (map[string]any, error) {
	doc, ok := m.docs[path]
	if !ok {
		return nil, ErrNotFound
	}
	return doc, nil
}

// HTTP fetches over https. Authentication to the real source is added when
// it is agreed with its operator.
type HTTP struct {
	Base   *url.URL
	Client *http.Client
}

func (h *HTTP) Fetch(ctx context.Context, path string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.Base.String()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := h.Client.Do(req)
	if err != nil {
		return nil, errors.New("source: the source could not be reached")
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, ErrNotFound
	default:
		return nil, fmt.Errorf("source: the source answered %d", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return nil, errors.New("source: the source gave an unreadable answer")
	}
	return doc, nil
}
