// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Privasys/container-app-register/internal/config"
	"github.com/Privasys/container-app-register/internal/source"
)

// configureSources applies the "sources" part of a configure call, and
// brings back what an earlier call kept on the volume. A call names a
// source to set it and leaves the others as they are.
//
// A mock is a file of the image's site, under mock/, named without a
// path: a configure call can switch a mock on, but cannot make the
// register read any other file.
func (a *application) configureSources(document []byte) (string, error) {
	if a.cfg.Mode == config.ModeStandby {
		return "", nil
	}
	var doc struct {
		Sources map[string]source.Setting `json:"sources"`
	}
	if len(document) > 0 {
		if err := json.Unmarshal(document, &doc); err != nil {
			return "", fmt.Errorf("configuration: %w", err)
		}
	}
	held, err := source.LoadSettings(a.cfg.DataDir)
	if err != nil {
		return "", err
	}
	for name, setting := range doc.Sources {
		held[name] = setting
	}
	if len(doc.Sources) > 0 {
		if err := source.SaveSettings(a.cfg.DataDir, held); err != nil {
			return "", err
		}
	}
	if len(held) == 0 {
		return "", nil
	}
	fetchers := map[string]source.Fetcher{}
	var states []string
	for name, setting := range held {
		if setting.Mock != "" {
			if setting.Mock != filepath.Base(setting.Mock) || strings.HasPrefix(setting.Mock, ".") {
				return "", fmt.Errorf("configuration: source %s: a mock is named by its file name only", name)
			}
			setting.Mock = filepath.Join(a.cfg.SiteDir, "mock", setting.Mock)
		}
		fetcher, err := setting.Fetcher()
		if err != nil {
			return "", fmt.Errorf("configuration: source %s: %w", name, err)
		}
		fetchers[name] = fetcher
		kind := "address"
		if setting.Mock != "" {
			kind = "mock"
		}
		states = append(states, name+": "+kind)
	}
	a.server.Sources.Store(&fetchers)
	sort.Strings(states)
	return strings.Join(states, ", "), nil
}
