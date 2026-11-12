// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package main

import (
	"log/slog"
	"testing"

	"github.com/Privasys/container-app-register/internal/api"
	"github.com/Privasys/container-app-register/internal/config"
)

// The client a configure call names is kept on the volume, so a restart's
// configure call, which does not repeat it, keeps it.
func TestSignInClientSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	app := func() *application {
		return &application{cfg: &config.Config{DataDir: dir, Mode: config.ModeActive}, log: slog.Default(), server: api.NewServer(slog.Default())}
	}
	first := app()
	if state, err := first.configureSignIn([]byte(`{"client_id":"e7abe4fee0915453151a8e673eaeb6f9"}`)); err != nil || state != "client e7abe4fee0915453151a8e673eaeb6f9" {
		t.Fatalf("state %q, err %v", state, err)
	}
	again := app()
	if _, err := again.configureSignIn([]byte(`{"tenant":"iom"}`)); err != nil {
		t.Fatal(err)
	}
	if id := again.server.SignInClient.Load(); id == nil || *id != "e7abe4fee0915453151a8e673eaeb6f9" {
		t.Fatalf("client not kept: %v", id)
	}
	if _, err := again.configureSignIn([]byte(`{"client_id":"bad id/"}`)); err == nil {
		t.Fatal("a malformed client id was accepted")
	}
	none := &application{cfg: &config.Config{DataDir: t.TempDir(), Mode: config.ModeActive}, log: slog.Default(), server: api.NewServer(slog.Default())}
	if state, err := none.configureSignIn(nil); err != nil || state != "" || none.server.SignInClient.Load() != nil {
		t.Fatalf("nothing configured, got %q %v", state, err)
	}
}
