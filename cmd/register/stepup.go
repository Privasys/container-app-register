// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/Privasys/container-app-register/internal/api"
	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/config"
	"github.com/Privasys/container-app-register/internal/platform"
)

// stepUpFile holds the approval settings a configure call gave, on the
// volume, so a restart keeps them.
const stepUpFile = "stepup.json"

// stepUpConfiguration is the approval part of the deployer's document:
// the platform's control plane, which pushes approvals to wallets, and the
// identity provider that signs links and answers. Each field is optional;
// a call sets what it names and keeps the rest. Nothing secret is held:
// the register calls the control plane with its own attested identity.
type stepUpConfiguration struct {
	PlatformURL string `json:"step_up_platform_url,omitempty"`
	Issuer      string `json:"step_up_issuer,omitempty"`
}

// configureStepUp applies a configure call to the approval path, and
// brings back what a previous call kept. With development sign-in, the
// stand-in approves everything at once.
func (a *application) configureStepUp(document []byte) (string, error) {
	if a.cfg.Mode == config.ModeStandby {
		return "", nil
	}
	if a.cfg.DevAuth {
		a.server.Approvals.Store(&api.ApprovalService{Approvals: auth.DevApprovals{}})
		return "development", nil
	}
	var doc stepUpConfiguration
	if len(document) > 0 {
		if err := json.Unmarshal(document, &doc); err != nil {
			return "", fmt.Errorf("configuration: %w", err)
		}
	}
	path := filepath.Join(a.cfg.DataDir, stepUpFile)
	var held stepUpConfiguration
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return "", fmt.Errorf("step-up: %w", err)
	default:
		if err := json.Unmarshal(raw, &held); err != nil {
			return "", fmt.Errorf("step-up: %s: %w", stepUpFile, err)
		}
	}
	given := doc != (stepUpConfiguration{})
	if doc.PlatformURL == "" {
		doc.PlatformURL = held.PlatformURL
	}
	if doc.Issuer == "" {
		doc.Issuer = held.Issuer
	}
	if given {
		for _, u := range []string{doc.PlatformURL, doc.Issuer} {
			if parsed, err := url.Parse(u); u != "" && (err != nil || parsed.Scheme != "https" || parsed.Host == "") {
				return "", fmt.Errorf("configuration: %q is not an https address", u)
			}
		}
		out, err := json.Marshal(doc)
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(path, out, 0o600); err != nil {
			return "", fmt.Errorf("step-up: %w", err)
		}
	}
	if doc.PlatformURL == "" {
		return "", nil
	}
	issuer := doc.Issuer
	if issuer == "" {
		issuer = a.cfg.Issuer
	}
	client := a.cfg.ClientID
	if id := a.server.SignInClient.Load(); id != nil && *id != "" {
		client = *id
	}
	appID := config.AppIDUUID(a.cfg.AppID)
	notifier := platform.NewNotifier(doc.PlatformURL,
		platform.NewManager(a.cfg.ManagerURL, a.cfg.ContainerName, a.cfg.ContainerToken))
	if issuer == "" || client == "" || appID == "" || notifier == nil {
		a.server.Approvals.Store(nil)
		return "not ready: approvals need the platform (its manager and this app's id), an issuer and a sign-in client", nil
	}
	a.server.Approvals.Store(&api.ApprovalService{Approvals: auth.NewWalletApprovals(issuer, appID, client, notifier.Notify)})
	return "ready: app " + appID, nil
}
