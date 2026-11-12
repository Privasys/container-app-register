// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/Privasys/container-app-register/internal/config"
)

// signInFile holds the sign-in settings a configure call gave, on the
// volume, so a restart keeps them without the deployer sending them again.
const signInFile = "signin.json"

// clientIDRe admits what identity providers issue as client identifiers.
var clientIDRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// signInConfiguration is the sign-in part of the deployer's document.
// client_id names the identity-provider client the pages sign people in
// as. Each installation registers its own, so one image serves every
// installation, and the value overrides REGISTER_CLIENT_ID.
type signInConfiguration struct {
	ClientID string `json:"client_id,omitempty"`
}

// configureSignIn applies a configure call to the sign-in client, and
// brings back the one a previous call kept on the volume.
func (a *application) configureSignIn(document []byte) (string, error) {
	if a.cfg.Mode == config.ModeStandby {
		return "", nil
	}
	var doc signInConfiguration
	if len(document) > 0 {
		if err := json.Unmarshal(document, &doc); err != nil {
			return "", fmt.Errorf("configuration: %w", err)
		}
	}
	path := filepath.Join(a.cfg.DataDir, signInFile)
	if doc.ClientID != "" {
		if !clientIDRe.MatchString(doc.ClientID) {
			return "", errors.New("configuration: client_id is not a client identifier")
		}
		raw, err := json.Marshal(doc)
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			return "", fmt.Errorf("sign-in: %w", err)
		}
	} else {
		raw, err := os.ReadFile(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
			return "", nil
		case err != nil:
			return "", fmt.Errorf("sign-in: %w", err)
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			return "", fmt.Errorf("sign-in: %s: %w", signInFile, err)
		}
	}
	id := doc.ClientID
	a.server.SignInClient.Store(&id)
	return "client " + id, nil
}
