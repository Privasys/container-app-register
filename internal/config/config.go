// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package config reads the register's runtime configuration from the
// environment the platform injects.
package config

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the process-level configuration. Everything a deployer
// chooses per register (tenant, commitment key, schema pack, retention,
// customer key) arrives later through the attested configure call, not
// from here.
type Config struct {
	// Port is the host-network port the platform assigned. Required:
	// there is no fallback, because a hard-coded port collides with
	// co-located apps and fails the readiness probe.
	Port int

	// DataDir is the per-app sealed volume. Its LUKS key is released to
	// the measured build at boot, so everything under it is encrypted at
	// rest under a key the host never sees.
	DataDir string

	// Name identifies this instance in checkpoints and log lines.
	Name string

	// ImageDigest is the workload measurement the platform injects. It
	// is stamped into every checkpoint so a reader knows which build
	// signed it.
	ImageDigest string

	// ManagerURL, ContainerName and ContainerToken are the in-enclave
	// SDK callback credentials. They are runtime secrets and are not
	// part of the attested spec.
	ManagerURL     string
	ContainerName  string
	ContainerToken string
	AppID          string

	// OIDC issuer and audience for end-user bearer tokens.
	Issuer   string
	Audience string

	// DevAuth accepts "dev:<sub>:<role>[,<role>…]" bearer tokens instead
	// of verifying against the identity provider. Local development and
	// tests only; refused when the platform callback credentials are
	// present.
	DevAuth bool

	// Mode is "active" or "standby".
	Mode string

	// PrimaryURL is the active register a standby follows.
	PrimaryURL string

	// SelfConfigure boots straight into a working register instead of
	// waiting for the configure call. Development, and the standby
	// role, which is configured from its primary rather than by a
	// deployer.
	SelfConfigure bool

	// CommitmentKeyHex, when set, supplies the ledger commitment key
	// from the environment rather than through the configure call.
	CommitmentKeyHex string

	// Tenant is the default tenant for a self-configured register.
	Tenant string

	// PackPath is a schema pack baked into the image, loaded when the
	// register self-configures.
	PackPath string

	// CheckpointInterval is how often a root checkpoint is issued on a
	// quiet register; significant events issue one regardless.
	CheckpointInterval time.Duration

	// StandbyInterval is how often a standby pulls from its primary.
	StandbyInterval time.Duration
}

// Modes.
const (
	ModeActive  = "active"
	ModeStandby = "standby"
)

// Load reads the environment.
func Load() (*Config, error) {
	c := &Config{
		DataDir:            env("REGISTER_DATA_DIR", "/data"),
		Name:               env("REGISTER_NAME", env("PRIVASYS_CONTAINER_NAME", "register")),
		ImageDigest:        os.Getenv("PRIVASYS_IMAGE_DIGEST"),
		ManagerURL:         os.Getenv("PRIVASYS_MANAGER_URL"),
		ContainerName:      os.Getenv("PRIVASYS_CONTAINER_NAME"),
		ContainerToken:     os.Getenv("PRIVASYS_CONTAINER_TOKEN"),
		AppID:              os.Getenv("PRIVASYS_APP_ID"),
		Issuer:             env("REGISTER_OIDC_ISSUER", "https://privasys.id"),
		Audience:           os.Getenv("REGISTER_OIDC_AUDIENCE"),
		Mode:               env("REGISTER_MODE", ModeActive),
		PrimaryURL:         os.Getenv("REGISTER_PRIMARY_URL"),
		CommitmentKeyHex:   os.Getenv("REGISTER_COMMITMENT_KEY"),
		Tenant:             env("REGISTER_TENANT", "default"),
		PackPath:           os.Getenv("REGISTER_PACK"),
		CheckpointInterval: duration("REGISTER_CHECKPOINT_INTERVAL", 24*time.Hour),
		StandbyInterval:    duration("REGISTER_STANDBY_INTERVAL", 30*time.Second),
	}

	port := os.Getenv("PORT")
	if port == "" {
		return nil, errors.New("config: PORT is required (the platform assigns it per app)")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n <= 0 || n > 65535 {
		return nil, errors.New("config: PORT is not a valid port number")
	}
	c.Port = n

	c.DevAuth = truthy(os.Getenv("REGISTER_DEV_AUTH"))
	if c.DevAuth && c.ContainerToken != "" {
		return nil, errors.New("config: REGISTER_DEV_AUTH must not be set on the platform")
	}
	c.SelfConfigure = truthy(os.Getenv("REGISTER_SELF_CONFIGURE")) || c.Mode == ModeStandby

	switch c.Mode {
	case ModeActive:
	case ModeStandby:
		if c.PrimaryURL == "" {
			return nil, errors.New("config: REGISTER_MODE=standby needs REGISTER_PRIMARY_URL")
		}
	default:
		return nil, errors.New("config: REGISTER_MODE must be active or standby")
	}
	return c, nil
}

// OnPlatform reports whether the enclave manager callback credentials
// are present, i.e. the register is running as a platform container
// rather than on a developer's machine.
func (c *Config) OnPlatform() bool {
	return c.ContainerName != "" && c.ContainerToken != "" && c.ManagerURL != ""
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func duration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}
