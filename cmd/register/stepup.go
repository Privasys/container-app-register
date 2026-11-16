// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Privasys/container-app-register/internal/api"
	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/config"
)

// stepUpFile holds the approval settings a configure call gave, on the
// sealed volume, as the mail settings are.
const stepUpFile = "stepup.json"

// stepUpConfiguration is the approval part of the deployer's document:
// the identity provider that puts acts in front of wallets, and the
// confidential client the register asks it as. Each field is optional;
// a call sets what it names and keeps the rest.
type stepUpConfiguration struct {
	Issuer       string `json:"step_up_issuer,omitempty"`
	ClientID     string `json:"step_up_client_id,omitempty"`
	ClientSecret string `json:"step_up_client_secret,omitempty"`
}

// configureStepUp applies a configure call to the approval service, and
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
	if doc.Issuer == "" {
		doc.Issuer = held.Issuer
	}
	if doc.ClientID == "" {
		doc.ClientID = held.ClientID
	}
	if doc.ClientSecret == "" {
		doc.ClientSecret = held.ClientSecret
	}
	if given {
		if doc.ClientID != "" && !clientIDRe.MatchString(doc.ClientID) {
			return "", errors.New("configuration: step_up_client_id is not a client identifier")
		}
		out, err := json.Marshal(doc)
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(path, out, 0o600); err != nil {
			return "", fmt.Errorf("step-up: %w", err)
		}
	}
	if doc == (stepUpConfiguration{}) {
		return "", nil
	}
	issuer, client := doc.Issuer, doc.ClientID
	if issuer == "" {
		issuer = a.cfg.Issuer
	}
	if client == "" {
		if id := a.server.SignInClient.Load(); id != nil {
			client = *id
		}
	}
	if client == "" {
		client = a.cfg.Audience
	}
	if issuer == "" || client == "" || doc.ClientSecret == "" {
		a.server.Approvals.Store(nil)
		return "not ready: give step_up_issuer, step_up_client_id and step_up_client_secret", nil
	}
	a.server.Approvals.Store(&api.ApprovalService{Approvals: auth.NewIdentityApprovals(issuer, client, doc.ClientSecret)})
	return "ready: client " + client, nil
}
