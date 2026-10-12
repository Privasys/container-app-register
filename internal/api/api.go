// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package api is the register's HTTP surface: the REST API, the
// operator explorer, and the configure endpoint the platform's
// configure-then-freeze gate drives.
//
// Transport security is the enclave's: RA-TLS terminates in front of
// this handler, so a client that verified the certificate has already
// verified the measurement of the build serving it. What is left to
// this package is who the caller is, what their role permits, and
// refusing everything else.
//
// A caller is known one of two ways. A person in a browser arrives over
// a sealed session, and the runtime asserts who they are in the
// X-Privasys-Sub header, which it strips from everything inbound. A
// machine arrives with a bearer token, verified here against the
// identity provider's published keys.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/register"
	"github.com/Privasys/container-app-register/internal/webhook"
)

// State is the register's lifecycle position, which the platform's
// freeze gate makes visible: a container serves nothing but its health
// probe and its configure endpoint until the deployer has configured
// it.
const (
	StateAwaitingConfiguration = "awaiting_configuration"
	StateReady                 = "ready"
	StateFailed                = "failed"
)

// Server is the HTTP surface. It is created before the register exists,
// because the configure call is what brings the register into being.
type Server struct {
	log *slog.Logger

	mu       sync.RWMutex
	state    string
	failure  string
	reg      *register.Register
	verifier auth.Verifier

	// Configure is called by POST /configure with the deployer's
	// document. Returning nil is what lifts the platform's freeze gate.
	Configure func(document []byte) (*register.Register, auth.Verifier, error)

	// Version is the build version reported at /version.
	Version string
	// Name identifies the register instance.
	Name string
	// Manifest is the app manifest served at /privasys.json.
	Manifest []byte
	// Standby reports the follower's position, when this register is one.
	Standby func() map[string]any
	// Deliveries reports recent webhook outcomes. They are held in
	// memory rather than in the ledger: whether somebody else's endpoint
	// answered is not a fact about this register.
	Deliveries func() []webhook.Delivery

	// TrustSession accepts the X-Privasys-Sub header as the caller's
	// identity. It is true on the platform, where the runtime strips the
	// header from every inbound request before asserting it, and false
	// everywhere else, where anybody could write it.
	TrustSession bool
	// WebDir holds the built browser UI. Empty, the register serves its
	// API and nothing to look at.
	WebDir string
	// ClientID, when set, is the identity-provider client the console
	// signs in as, in place of the one built into the page.
	ClientID string
}

// NewServer builds the HTTP surface in its unconfigured state.
func NewServer(log *slog.Logger) *Server {
	return &Server{log: log, state: StateAwaitingConfiguration}
}

// Ready installs a configured register.
func (s *Server) Ready(reg *register.Register, verifier auth.Verifier) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reg, s.verifier, s.state, s.failure = reg, verifier, StateReady, ""
}

// Fail records a configuration failure so the operator sees why the
// register is not serving.
func (s *Server) Fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state, s.failure = StateFailed, err.Error()
}

func (s *Server) register() (*register.Register, auth.Verifier, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.reg, s.verifier, s.state == StateReady
}

// Handler builds the router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Always available: the readiness probe, the build version, the
	// manifest, and the configure call itself.
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("GET /readiness", s.readiness)
	mux.HandleFunc("GET /app-config.js", s.appConfig)
	mux.HandleFunc("GET /version", s.version)
	mux.HandleFunc("GET /privasys.json", s.manifest)
	mux.HandleFunc("POST /configure", s.configure)

	// The register proper.
	mux.HandleFunc("GET /api/v1/status", s.wrap(s.status))
	mux.HandleFunc("GET /api/v1/pack", s.wrap(s.packDocument))
	mux.HandleFunc("GET /api/v1/me", s.wrapCaller(s.me))

	// Membership. The first two answer a person who holds no role yet:
	// an invitation is how they come to hold one.
	mux.HandleFunc("POST /api/v1/invites/{id}/check", s.wrapCaller(s.checkInvite))
	mux.HandleFunc("POST /api/v1/invites/{id}/redeem", s.wrapCaller(s.redeemInvite))
	mux.HandleFunc("GET /api/v1/invites", s.wrap(s.listInvites))
	mux.HandleFunc("POST /api/v1/invites", s.wrap(s.createInvite))
	mux.HandleFunc("DELETE /api/v1/invites/{id}", s.wrap(s.revokeInvite))
	mux.HandleFunc("GET /api/v1/members", s.wrap(s.listMembers))
	mux.HandleFunc("POST /api/v1/members", s.wrap(s.grantMember))
	mux.HandleFunc("DELETE /api/v1/members/{sub}/{role}", s.wrap(s.revokeMember))

	mux.HandleFunc("GET /api/v1/records", s.wrap(s.listRecords))
	mux.HandleFunc("GET /api/v1/records/{id}", s.wrap(s.getRecord))
	mux.HandleFunc("GET /api/v1/records/{id}/history", s.wrap(s.recordHistory))
	mux.HandleFunc("GET /api/v1/records/{id}/versions/{version}", s.wrap(s.getRecordVersion))

	mux.HandleFunc("GET /api/v1/tasks", s.wrap(s.listTasks))
	mux.HandleFunc("GET /api/v1/tasks/{id}", s.wrap(s.getTask))
	mux.HandleFunc("POST /api/v1/workflows/{name}/propose", s.wrap(s.propose))
	mux.HandleFunc("POST /api/v1/tasks/{id}/accept", s.wrap(s.accept))
	mux.HandleFunc("POST /api/v1/tasks/{id}/decide", s.wrap(s.decide))
	mux.HandleFunc("POST /api/v1/tasks/{id}/withdraw", s.wrap(s.withdraw))

	mux.HandleFunc("GET /api/v1/log", s.wrap(s.log_))
	mux.HandleFunc("GET /api/v1/log/{txid}", s.wrap(s.transaction))

	mux.HandleFunc("GET /api/v1/queries", s.wrap(s.listQueries))
	mux.HandleFunc("POST /api/v1/queries/{name}", s.wrap(s.runQuery))

	mux.HandleFunc("GET /api/v1/proofs/records/{id}/{version}", s.wrap(s.recordProof))
	mux.HandleFunc("GET /api/v1/proofs/natural-keys/{class}/{key}", s.wrap(s.naturalKeyProof))

	mux.HandleFunc("GET /api/v1/checkpoints", s.wrap(s.listCheckpoints))
	mux.HandleFunc("GET /api/v1/checkpoints/latest", s.wrap(s.latestCheckpoint))
	mux.HandleFunc("GET /api/v1/checkpoints/key", s.wrap(s.checkpointKey))
	mux.HandleFunc("POST /api/v1/checkpoints", s.wrap(s.issueCheckpoint))

	mux.HandleFunc("GET /api/v1/audit/lineage", s.wrap(s.lineage))
	mux.HandleFunc("GET /api/v1/audit/roots", s.wrap(s.auditRoots))
	mux.HandleFunc("GET /api/v1/audit/changes/{version}", s.wrap(s.auditChanges))
	mux.HandleFunc("POST /api/v1/audit/verify", s.wrap(s.auditVerify))
	mux.HandleFunc("POST /api/v1/audit/close", s.wrap(s.auditClose))

	mux.HandleFunc("GET /api/v1/retention", s.wrap(s.horizons))
	mux.HandleFunc("POST /api/v1/retention/prune", s.wrap(s.prune))
	mux.HandleFunc("POST /api/v1/retention/erase", s.wrap(s.erase))

	mux.HandleFunc("POST /api/v1/keys", s.wrap(s.enrolKey))
	mux.HandleFunc("GET /api/v1/keys/{scope}/recovery-wrap", s.wrap(s.recoveryWrap))

	mux.HandleFunc("GET /api/v1/export", s.wrap(s.export))
	mux.HandleFunc("GET /api/v1/standby", s.wrap(s.standby))
	mux.HandleFunc("POST /api/v1/webhooks", s.wrap(s.addWebhook))
	mux.HandleFunc("GET /api/v1/webhooks", s.wrap(s.listWebhooks))

	// Tool endpoints, declared in the app manifest so the developer
	// portal, the CLI and agents can drive the register over MCP.
	mux.HandleFunc("POST /tools/lookup", s.wrap(s.toolLookup))
	mux.HandleFunc("POST /tools/propose", s.wrap(s.toolPropose))
	mux.HandleFunc("POST /tools/log", s.wrap(s.toolLog))
	mux.HandleFunc("POST /tools/query", s.wrap(s.toolQuery))
	mux.HandleFunc("POST /tools/status", s.wrap(s.toolStatus))
	mux.HandleFunc("POST /tools/checkpoint", s.wrap(s.toolCheckpoint))

	registerExplorer(mux, s)

	return logging(s.log, securityHeaders(mux))
}

// -- request plumbing ------------------------------------------------------

// request carries what a handler needs: the authenticated caller and
// the running register.
type request struct {
	w   http.ResponseWriter
	r   *http.Request
	reg *register.Register
	p   *auth.Principal
	// id and tenant are who is calling, before any role is considered.
	id     *auth.Identity
	tenant string
	// refusal is why the caller holds no principal, on the routes that
	// admit such a caller.
	refusal error
}

type handler func(*request) (any, error)

// wrap authenticates the caller, resolves their role, and turns a
// handler's return value into a JSON response.
func (s *Server) wrap(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reg, verifier, ready := s.register()
		if !ready {
			s.mu.RLock()
			state, failure := s.state, s.failure
			s.mu.RUnlock()
			writeError(w, http.StatusServiceUnavailable,
				fmt.Sprintf("register is %s", state), failure)
			return
		}
		id, tenant, err := s.identify(r, reg, verifier)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "not authenticated", err.Error())
			return
		}
		principal, err := reg.Pack().Model().Resolve(id, tenant, actingRole(r))
		if errors.Is(err, auth.ErrNoRole) {
			// Known, and not a member: a different answer from not
			// being known at all, so the page can say what to do next.
			writeError(w, http.StatusForbidden, "no register role", err.Error())
			return
		}
		if err != nil {
			writeError(w, http.StatusForbidden, "not authorised", err.Error())
			return
		}
		result, err := h(&request{w: w, r: r, reg: reg, p: principal, id: id, tenant: tenant})
		if err != nil {
			status, detail := classify(err)
			writeError(w, status, err.Error(), detail)
			return
		}
		if result == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

// wrapCaller admits anyone the register can identify, whether or not
// they hold a role: the handler gets a nil principal for a caller who
// holds none. It is for the two things such a person can do, which are
// to learn that, and to redeem an invitation.
func (s *Server) wrapCaller(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reg, verifier, ready := s.register()
		if !ready {
			s.mu.RLock()
			state, failure := s.state, s.failure
			s.mu.RUnlock()
			writeError(w, http.StatusServiceUnavailable,
				fmt.Sprintf("register is %s", state), failure)
			return
		}
		id, tenant, err := s.identify(r, reg, verifier)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "not authenticated", err.Error())
			return
		}
		req := &request{w: w, r: r, reg: reg, id: id, tenant: tenant}
		req.p, req.refusal = reg.Pack().Model().Resolve(id, tenant, actingRole(r))
		if req.refusal != nil {
			req.p = nil
		}
		result, err := h(req)
		if err != nil {
			status, detail := classify(err)
			writeError(w, status, err.Error(), detail)
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

// identify works out who is calling, and loads the roles this register
// granted them.
func (s *Server) identify(r *http.Request, reg *register.Register, verifier auth.Verifier) (*auth.Identity, string, error) {
	var id *auth.Identity
	if sub := strings.TrimSpace(r.Header.Get("X-Privasys-Sub")); s.TrustSession && sub != "" {
		if len(sub) > 256 {
			return nil, "", errors.New("the session subject is malformed")
		}
		id = &auth.Identity{Sub: sub, Issuer: "privasys-session"}
	} else {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			return nil, "", errors.New("sign in, or present a bearer token")
		}
		var err error
		if id, err = verifier.Verify(r.Context(), strings.TrimPrefix(header, "Bearer ")); err != nil {
			return nil, "", err
		}
	}
	tenant := r.Header.Get("X-Register-Tenant")
	if tenant == "" {
		tenant = reg.Options().Tenant
	}
	granted, display, err := reg.GrantedRoles(tenant, id.Sub)
	if err != nil {
		return nil, "", fmt.Errorf("membership lookup: %w", err)
	}
	id.Granted = granted
	if id.Display == "" {
		id.Display = display
	}
	return id, tenant, nil
}

func actingRole(r *http.Request) string {
	if role := r.Header.Get("X-Register-Role"); role != "" {
		return role
	}
	return r.URL.Query().Get("role")
}

// securityHeaders are set on everything, the browser shell included.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		// The platform edge has no plain-HTTP listener, so an address typed
		// without https:// fails; after one visit the browser upgrades itself.
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("Content-Security-Policy", "frame-ancestors 'none'; object-src 'none'; base-uri 'self'")
		next.ServeHTTP(w, r)
	})
}

// classify maps a core error onto a status code. The core returns plain
// errors with human-readable text; the distinctions that matter to a
// caller are "you may not", "there is no such thing" and "that is not
// something this register can do".
func classify(err error) (int, string) {
	var pruned *register.PruneError
	if errors.As(err, &pruned) {
		return http.StatusGone, "the content was removed under a retention policy; the record and its history remain"
	}
	text := err.Error()
	switch {
	case errors.Is(err, register.ErrInvite):
		return http.StatusGone, ""
	case strings.Contains(text, "may not"), strings.Contains(text, "separation of duties"),
		strings.Contains(text, "is not a proposing role"), strings.Contains(text, "only the proposer"),
		strings.Contains(text, "only ") && strings.Contains(text, "can answer"):
		return http.StatusForbidden, ""
	case strings.Contains(text, "is not registered"), strings.Contains(text, "no such"),
		strings.HasPrefix(text, "no workflow named"), strings.HasPrefix(text, "no class named"),
		strings.HasPrefix(text, "no query named"), strings.HasPrefix(text, "no proposal"),
		strings.HasPrefix(text, "no transaction"), strings.HasPrefix(text, "no retention policy"),
		strings.HasPrefix(text, "no key for scope"):
		return http.StatusNotFound, ""
	case strings.Contains(text, "already registered"), strings.Contains(text, "already been erased"),
		strings.Contains(text, "is not awaiting"), strings.Contains(text, "is not waiting"),
		strings.Contains(text, "is the only member"):
		return http.StatusConflict, ""
	default:
		return http.StatusBadRequest, ""
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(body)
}

func writeError(w http.ResponseWriter, status int, message, detail string) {
	body := map[string]any{"error": message}
	if detail != "" {
		body["detail"] = detail
	}
	writeJSON(w, status, body)
}

func decode(r *http.Request, into any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 4<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("request body: %w", err)
	}
	return nil
}

func intParam(r *http.Request, name string, fallback int) int {
	v := r.URL.Query().Get(name)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func int64Param(r *http.Request, name string) int64 {
	n, _ := strconv.ParseInt(r.URL.Query().Get(name), 10, 64)
	return n
}

func boolParam(r *http.Request, name string) bool {
	switch strings.ToLower(r.URL.Query().Get(name)) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// logging records one line per request. Bodies are never logged: a
// register's request bodies are the register's data.
func logging(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if r.URL.Path == "/health" && rec.status == http.StatusOK {
			return
		}
		log.Info("request",
			"method", r.Method, "path", r.URL.Path, "status", rec.status,
			"duration_ms", time.Since(started).Milliseconds())
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
