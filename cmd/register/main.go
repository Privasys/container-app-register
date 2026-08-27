// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Command register runs the Privasys register as a confidential
// container.
//
// Startup is in two halves, because the platform's configure-then-
// freeze gate divides it. The process binds its port and serves its
// health probe immediately; everything else stays behind HTTP 503 until
// the deployer posts a configuration, which carries the tenant, the
// schema pack and, in the deployments that want it, the ledger
// commitment key. The gate re-arms on every restart, so a key delivered
// that way is never written down.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/Privasys/container-app-register/internal/api"
	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/config"
	"github.com/Privasys/container-app-register/internal/keys"
	"github.com/Privasys/container-app-register/internal/pack"
	"github.com/Privasys/container-app-register/internal/platform"
	"github.com/Privasys/container-app-register/internal/register"
	"github.com/Privasys/container-app-register/internal/store"
	"github.com/Privasys/container-app-register/internal/webhook"
)

// version is stamped at build time.
var version = "dev"

//nolint:gochecknoglobals // the manifest is served verbatim at /privasys.json
var manifest []byte

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	if err := run(log); err != nil {
		log.Error("register stopped", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if raw, err := os.ReadFile("/privasys.json"); err == nil {
		manifest = raw
	}

	material, err := keys.Load(filepath.Join(cfg.DataDir, "keys"))
	if err != nil {
		return err
	}

	server := api.NewServer(log)
	server.Version, server.Name, server.Manifest = version, cfg.Name, manifest

	app := &application{cfg: cfg, log: log, material: material, server: server}
	server.Configure = app.configure
	server.Standby = app.standbyStatus
	server.Deliveries = app.deliveries

	if cfg.SelfConfigure {
		// A register that configures itself is one of two things: a
		// developer's copy, or a standby, which takes its configuration
		// from the primary it follows rather than from a deployer.
		document, err := app.selfConfiguration()
		if err != nil {
			return err
		}
		reg, verifier, err := app.configure(document)
		if err != nil {
			return err
		}
		server.Ready(reg, verifier)
	}

	handler := server.Handler()
	srv := &http.Server{
		Addr:              net.JoinHostPort("0.0.0.0", fmt.Sprint(cfg.Port)),
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errs := make(chan error, 1)
	go func() {
		log.Info("register listening",
			"port", cfg.Port, "name", cfg.Name, "mode", cfg.Mode,
			"platform", cfg.OnPlatform(), "measurement", cfg.ImageDigest)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- err
		}
	}()

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}

	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	app.close()
	return nil
}

// application holds what survives a configure call.
type application struct {
	cfg      *config.Config
	log      *slog.Logger
	material *keys.Material
	server   *api.Server

	st      *store.Store
	reg     *register.Register
	hooks   *webhook.Dispatcher
	manager *platform.Manager
	cancel  context.CancelFunc

	standbyMu    sync.RWMutex
	standbyState map[string]any
}

// configuration is the deployer's document.
type configuration struct {
	Tenant        string          `json:"tenant,omitempty"`
	CommitmentKey string          `json:"commitment_key,omitempty"`
	Pack          json.RawMessage `json:"pack,omitempty"`
	PackRef       string          `json:"pack_ref,omitempty"`
	CustomerKEK   *struct {
		ID        string `json:"id"`
		Algorithm string `json:"algo"`
		PublicKey string `json:"public_key"`
	} `json:"customer_kek,omitempty"`
	CheckpointInterval string `json:"checkpoint_interval,omitempty"`
}

// selfConfiguration builds the document a self-configuring register
// would have been sent.
func (a *application) selfConfiguration() ([]byte, error) {
	doc := configuration{
		Tenant:        a.cfg.Tenant,
		CommitmentKey: a.cfg.CommitmentKeyHex,
	}
	if a.cfg.PackPath != "" {
		raw, err := os.ReadFile(a.cfg.PackPath)
		if err != nil {
			return nil, fmt.Errorf("read pack %s: %w", a.cfg.PackPath, err)
		}
		doc.Pack = raw
	} else {
		doc.PackRef = "car-register"
	}
	return json.Marshal(doc)
}

// configure brings the register up. Returning without an error is what
// lifts the platform's freeze gate.
func (a *application) configure(document []byte) (*register.Register, auth.Verifier, error) {
	var doc configuration
	if len(document) > 0 {
		if err := json.Unmarshal(document, &doc); err != nil {
			return nil, nil, fmt.Errorf("configuration: %w", err)
		}
	}

	packDoc, err := a.resolvePack(doc)
	if err != nil {
		return nil, nil, err
	}
	loaded, err := pack.Load(packDoc)
	if err != nil {
		return nil, nil, err
	}

	var delivered *[32]byte
	if doc.CommitmentKey != "" {
		raw, err := hex.DecodeString(doc.CommitmentKey)
		if err != nil || len(raw) != 32 {
			return nil, nil, errors.New("configuration: commitment_key must be 64 hex characters")
		}
		var ck [32]byte
		copy(ck[:], raw)
		delivered = &ck
	}
	ck, source, err := a.material.CommitmentKey(delivered)
	if err != nil {
		return nil, nil, err
	}

	st, err := store.Open(filepath.Join(a.cfg.DataDir, "register"), ck)
	if err != nil {
		return nil, nil, err
	}

	tenant := doc.Tenant
	if tenant == "" {
		tenant = a.cfg.Tenant
	}
	reg, err := register.New(st, loaded, a.material, register.Options{
		Name: a.cfg.Name, Tenant: tenant, ImageDigest: a.cfg.ImageDigest, KeySource: source,
	})
	if err != nil {
		st.Close()
		return nil, nil, err
	}

	hooks := webhook.New(st, a.log)
	hooks.Start()
	reg.SetNotifier(hooks)

	verifier, err := a.verifier()
	if err != nil {
		st.Close()
		return nil, nil, err
	}

	a.close()
	a.st, a.reg, a.hooks = st, reg, hooks
	a.manager = platform.NewManager(a.cfg.ManagerURL, a.cfg.ContainerName, a.cfg.ContainerToken)

	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel

	if err := a.publishConfiguration(ctx, ck); err != nil {
		// A register that cannot advertise the key it was given is not
		// broken, but a verifying client will notice the extension is
		// missing, so the reason belongs in the log.
		a.log.Warn("could not publish the configuration commitment", "error", err)
	}
	if _, err := reg.IssueCheckpoint(register.ReasonBootstrap); err != nil {
		a.log.Warn("could not issue the bootstrap checkpoint", "error", err)
	}
	a.publishRoot(ctx)

	if doc.CustomerKEK != nil {
		if err := a.enrolCustomerKey(reg, tenant, doc.CustomerKEK.ID,
			doc.CustomerKEK.Algorithm, doc.CustomerKEK.PublicKey); err != nil {
			a.log.Warn("could not enrol the customer key", "error", err)
		}
	}

	interval := a.cfg.CheckpointInterval
	if doc.CheckpointInterval != "" {
		if parsed, err := time.ParseDuration(doc.CheckpointInterval); err == nil && parsed > 0 {
			interval = parsed
		}
	}
	go a.checkpointLoop(ctx, reg, interval)
	if a.cfg.Mode == config.ModeStandby {
		go a.followPrimary(ctx, reg)
	}

	status, _ := reg.Status()
	a.log.Info("register configured",
		"pack", loaded.Name, "pack_version", loaded.Version, "tenant", tenant,
		"commitment_key", source, "root", status.Root, "ledger_version", status.LedgerVersion)
	return reg, verifier, nil
}

// resolvePack finds the pack document: inline in the configuration, or
// one baked into the image by name.
func (a *application) resolvePack(doc configuration) ([]byte, error) {
	if len(doc.Pack) > 0 {
		return doc.Pack, nil
	}
	name := doc.PackRef
	if name == "" {
		return nil, errors.New("configuration: give a pack, or a pack_ref naming one baked into the image")
	}
	if filepath.Base(name) != name {
		return nil, errors.New("configuration: pack_ref is a name, not a path")
	}
	raw, err := os.ReadFile(filepath.Join("/packs", name, "pack.json"))
	if err != nil {
		return nil, fmt.Errorf("configuration: no pack %q is baked into this image", name)
	}
	return raw, nil
}

func (a *application) verifier() (auth.Verifier, error) {
	if a.cfg.DevAuth {
		a.log.Warn("development authentication is enabled: bearer tokens are not verified")
		return auth.DevVerifier{}, nil
	}
	if a.cfg.Audience == "" {
		a.log.Warn("no audience configured: tokens from any audience this issuer signs will be accepted",
			"issuer", a.cfg.Issuer)
	}
	return auth.NewJWKSVerifier(a.cfg.Issuer, a.cfg.Audience), nil
}

func (a *application) enrolCustomerKey(reg *register.Register, tenant, id, algo, publicKey string) error {
	principal := &auth.Principal{
		Sub: "system:configure", Display: "Deployer", Tenant: tenant,
		Roles: []string{"system"}, Acting: "system",
	}
	principal.Grant(auth.PermKeys)
	_, err := reg.EnrolKEK(principal, id, algo, publicKey)
	return err
}

// publishConfiguration commits the delivered key's fingerprint to the
// RA-TLS leaf.
func (a *application) publishConfiguration(ctx context.Context, ck [32]byte) error {
	if a.manager == nil {
		return nil
	}
	return a.manager.SetExtension(ctx, platform.OIDConfiguration, keys.Fingerprint(ck))
}

func (a *application) publishRoot(ctx context.Context) {
	if a.manager == nil || a.reg == nil {
		return
	}
	status, err := a.reg.Status()
	if err != nil {
		return
	}
	if err := a.manager.PublishRoot(ctx, status.Root); err != nil {
		a.log.Warn("could not publish the ledger root", "error", err)
	}
}

// checkpointLoop issues a checkpoint on a cadence. A quiet register
// issues none: a checkpoint that repeats the previous one is not more
// evidence.
func (a *application) checkpointLoop(ctx context.Context, reg *register.Register, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := reg.IssueCheckpoint(register.ReasonScheduled); err != nil {
				a.log.Error("scheduled checkpoint failed", "error", err)
				continue
			}
			a.publishRoot(ctx)
		}
	}
}

func (a *application) close() {
	if a.cancel != nil {
		a.cancel()
		a.cancel = nil
	}
	if a.hooks != nil {
		a.hooks.Close()
		a.hooks = nil
	}
	if a.st != nil {
		_ = a.st.Close()
		a.st = nil
	}
	a.reg = nil
}
