// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/register"
)

// -- always available ------------------------------------------------------

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	state, failure := s.state, s.failure
	s.mu.RUnlock()
	body := map[string]any{"status": "healthy", "state": state}
	if failure != "" {
		body["error"] = failure
	}
	writeJSON(w, http.StatusOK, body)
}

// readiness is what the platform polls after a configure call: 200 once
// the register is serving, 503 until then.
func (s *Server) readiness(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	state, failure := s.state, s.failure
	s.mu.RUnlock()
	if state != StateReady {
		writeError(w, http.StatusServiceUnavailable, fmt.Sprintf("register is %s", state), failure)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
}

var hostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[0-9]{1,5})?$`)

// appConfig tells the page which host it is being served as. On a
// custom domain the page's own address is the adopter's name, but a
// sealed session is attested against the platform hostname, so the page
// is told rather than left to guess from its location.
func (s *Server) appConfig(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.Host)
	if !hostRe.MatchString(host) {
		writeError(w, http.StatusBadRequest, "bad host", "")
		return
	}
	env := "production"
	if strings.HasSuffix(strings.Split(host, ":")[0], ".test.privasys.org") {
		env = "test"
	}
	doc := map[string]any{
		"appHost": host, "environment": env, "version": s.Version, "name": s.Name,
		"session": s.TrustSession,
	}
	if s.ClientID != "" {
		doc["clientId"] = s.ClientID
	}
	cfg, _ := json.Marshal(doc)
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write([]byte("window.__REGISTER__=" + string(cfg) + ";\n"))
}

func (s *Server) version(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"version": s.Version, "name": s.Name})
}

func (s *Server) manifest(w http.ResponseWriter, _ *http.Request) {
	if len(s.Manifest) == 0 {
		writeError(w, http.StatusNotFound, "no manifest is baked into this build", "")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(s.Manifest)
}

// configure is the endpoint the platform's freeze gate watches. Until
// it answers 2xx the enclave manager keeps every other path at 503; the
// gate re-arms on every restart, so the deployer re-delivers the
// configuration, and with it the commitment key, each time the register
// starts. That is the point: the key that binds the register's whole
// state arrives over an attested channel and lives in memory.
func (s *Server) configure(w http.ResponseWriter, r *http.Request) {
	if s.Configure == nil {
		writeError(w, http.StatusNotImplemented, "this build cannot be configured over HTTP", "")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not read the configuration", err.Error())
		return
	}
	// A register that is already serving keeps serving. Its pack, tenant
	// and commitment key are fixed for the life of the process, and
	// opening the store a second time would only fail and take the
	// running register down with it. What a later call can still do is
	// name administrators.
	if running, _, ready := s.register(); ready {
		out := map[string]any{"status": "already_configured"}
		if err := bootstrapMembers(running, body, out); err != nil {
			writeError(w, http.StatusBadRequest, "configuration refused", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	reg, verifier, err := s.Configure(body)
	if err != nil {
		s.Fail(err)
		writeError(w, http.StatusBadRequest, "configuration refused", err.Error())
		return
	}
	out := map[string]any{"status": "configured"}
	if err := bootstrapMembers(reg, body, out); err != nil {
		s.Fail(err)
		writeError(w, http.StatusBadRequest, "configuration refused", err.Error())
		return
	}
	s.Ready(reg, verifier)
	status, err := reg.Status()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "configured, but the register would not report", err.Error())
		return
	}
	out["register"] = status
	writeJSON(w, http.StatusOK, out)
}

// bootstrapMembers names the register's first administrators.
//
// The configure call runs again on every restart, because the gate
// re-arms, so both halves are written to be repeated: a subject who
// already holds the role is left alone, and an invitation is only
// minted while nobody can manage membership, which is the one moment it
// is needed.
func bootstrapMembers(reg *register.Register, document []byte, out map[string]any) error {
	var doc struct {
		Admins      string `json:"admins"`
		AdminInvite any    `json:"admin_invite"`
		AdminRole   string `json:"admin_role"`
	}
	if len(document) > 0 {
		_ = json.Unmarshal(document, &doc)
	}
	wantInvite := doc.AdminInvite == true || doc.AdminInvite == "true"
	if doc.Admins == "" && !wantInvite {
		return nil
	}
	role := doc.AdminRole
	if role == "" {
		var err error
		if role, err = reg.MembersRole(); err != nil {
			return err
		}
	}
	added := 0
	for _, sub := range strings.Split(doc.Admins, ",") {
		if sub = strings.TrimSpace(sub); sub == "" {
			continue
		}
		held, _, err := reg.GrantedRoles(reg.Options().Tenant, sub)
		if err != nil {
			return err
		}
		if slices.Contains(held, role) {
			continue
		}
		if _, err := reg.BootstrapMember(sub, role); err != nil {
			return fmt.Errorf("admin %q: %w", sub, err)
		}
		added++
	}
	out["admins_added"] = added
	if wantInvite {
		administered, err := reg.Administered()
		if err != nil {
			return err
		}
		if !administered {
			inv, secret, err := reg.BootstrapInvite(role, 24*time.Hour)
			if err != nil {
				return fmt.Errorf("admin invite: %w", err)
			}
			out["admin_invite"] = "/#/join/" + inv.ID + "/" + secret
			out["admin_role"] = role
		}
	}
	return nil
}

// -- status and shape ------------------------------------------------------

func (s *Server) status(req *request) (any, error) { return req.reg.Status() }

// me answers "who am I here". A person who is signed in and holds no
// role gets an answer too, because that is the state an invitation
// starts from.
func (s *Server) me(req *request) (any, error) {
	pk := req.reg.Pack()
	out := map[string]any{
		"sub": req.id.Sub, "display": req.id.Display, "tenant": req.tenant,
		"register": map[string]any{
			"name": req.reg.Options().Name, "pack": pk.Name, "title": pk.Title,
		},
	}
	if req.p == nil {
		out["status"] = "no_role"
		if !errors.Is(req.refusal, auth.ErrNoRole) {
			// Roles are held, and may not be acted under: say which rule.
			out["status"], out["refusal"] = "refused", req.refusal.Error()
		}
		return out, nil
	}
	titles := map[string]string{}
	for _, name := range req.p.Roles {
		if spec := pk.Model().Role(name); spec != nil {
			titles[name] = spec.Title
		}
	}
	out["status"] = "member"
	out["principal"] = req.p
	out["permissions"] = req.p.Permissions()
	out["role_titles"] = titles
	return out, nil
}

// -- membership ------------------------------------------------------------

func (s *Server) listMembers(req *request) (any, error) {
	members, err := req.reg.Members(req.p)
	if err != nil {
		return nil, err
	}
	roles := make([]map[string]any, 0)
	for _, spec := range req.reg.Pack().Model().Roles() {
		roles = append(roles, map[string]any{
			"name": spec.Name, "title": spec.Title, "permissions": spec.Permissions,
			"pii": spec.PII, "incompatible_with": spec.IncompatibleWith,
		})
	}
	return map[string]any{"members": members, "roles": roles}, nil
}

func (s *Server) grantMember(req *request) (any, error) {
	var in struct {
		Sub     string `json:"sub"`
		Role    string `json:"role"`
		Display string `json:"display"`
		Reason  string `json:"reason"`
	}
	if err := decode(req.r, &in); err != nil {
		return nil, err
	}
	txn, err := req.reg.GrantRole(req.p, in.Sub, in.Role, in.Display, in.Reason)
	if err != nil {
		return nil, err
	}
	return map[string]any{"transaction": txn}, nil
}

func (s *Server) revokeMember(req *request) (any, error) {
	txn, err := req.reg.RevokeRole(req.p, req.r.PathValue("sub"), req.r.PathValue("role"),
		req.r.URL.Query().Get("reason"))
	if err != nil {
		return nil, err
	}
	return map[string]any{"transaction": txn}, nil
}

func (s *Server) listInvites(req *request) (any, error) {
	invites, err := req.reg.Invites(req.p)
	if err != nil {
		return nil, err
	}
	return map[string]any{"invites": invites}, nil
}

func (s *Server) createInvite(req *request) (any, error) {
	var in struct {
		Role      string `json:"role"`
		Label     string `json:"label"`
		ValidDays int    `json:"valid_days"`
	}
	if err := decode(req.r, &in); err != nil {
		return nil, err
	}
	inv, secret, err := req.reg.CreateInvite(req.p, in.Role, in.Label, time.Duration(in.ValidDays)*24*time.Hour)
	if err != nil {
		return nil, err
	}
	// The secret is served here and nowhere else. It goes in the link's
	// fragment, which a browser does not send to any server.
	return map[string]any{"invite": inv, "link": "/#/join/" + inv.ID + "/" + secret}, nil
}

func (s *Server) revokeInvite(req *request) (any, error) {
	txn, err := req.reg.RevokeInvite(req.p, req.r.PathValue("id"))
	if err != nil {
		return nil, err
	}
	return map[string]any{"transaction": txn}, nil
}

type inviteSecret struct {
	Secret string `json:"secret"`
}

func (s *Server) checkInvite(req *request) (any, error) {
	var in inviteSecret
	if err := decode(req.r, &in); err != nil {
		return nil, err
	}
	inv, err := req.reg.CheckInvite(req.tenant, req.r.PathValue("id"), in.Secret)
	if err != nil {
		return nil, err
	}
	title := inv.Role
	if spec := req.reg.Pack().Model().Role(inv.Role); spec != nil && spec.Title != "" {
		title = spec.Title
	}
	return map[string]any{"role": inv.Role, "role_title": title, "label": inv.Label, "expires_at": inv.ExpiresAt}, nil
}

func (s *Server) redeemInvite(req *request) (any, error) {
	var in inviteSecret
	if err := decode(req.r, &in); err != nil {
		return nil, err
	}
	inv, txn, err := req.reg.RedeemInvite(req.tenant, req.id.Sub, req.id.Display, req.r.PathValue("id"), in.Secret)
	if err != nil {
		return nil, err
	}
	return map[string]any{"role": inv.Role, "transaction": txn}, nil
}

// packDocument describes the register's shape to a client: what it
// holds, what can be proposed about it, who may do what, and which
// queries are available. The explorer and the CLI are generic over it.
func (s *Server) packDocument(req *request) (any, error) {
	p := req.reg.Pack()
	classes := make([]map[string]any, 0, len(p.Classes))
	for _, c := range p.Classes {
		projections := make([]map[string]any, 0)
		for _, proj := range c.Compiled().Projections() {
			projections = append(projections, map[string]any{
				"property": proj.Property, "column": proj.Column,
				"type": proj.Type, "indexed": proj.Indexed, "unique": proj.Unique,
			})
		}
		classes = append(classes, map[string]any{
			"name": c.Name, "title": c.Title, "natural_key": c.NaturalKey,
			"statuses": c.Statuses, "initial_status": c.Initial,
			"encryption": c.Encryption, "personal_data": c.Compiled().PIIFields(),
			"queryable": projections, "schema": rawJSON(c.Schema),
		})
	}
	workflows := make([]map[string]any, 0, len(p.Workflows))
	for _, w := range p.Workflows {
		workflows = append(workflows, map[string]any{
			"name": w.Name, "title": w.Title, "class": w.Class, "action": w.Action,
			"propose_roles": w.ProposeRoles, "approve_roles": w.ApproveRoles,
			"independence": w.Independence, "evidence": w.Evidence,
			"counterparty": w.Counterparty, "auto_approve": w.AutoApprove,
			"conditions": w.Conditions, "may_propose": req.p.CanOn(auth.PermPropose, w.Name),
			"may_decide": req.p.CanOn(auth.PermApprove, w.Name),
		})
	}
	return map[string]any{
		"name": p.Name, "title": p.Title, "version": p.Version, "description": p.Description,
		"classes": classes, "workflows": workflows, "roles": p.Model().Roles(),
		"retention": p.Retention, "queries": p.Queries,
	}, nil
}

// -- records ---------------------------------------------------------------

func (s *Server) listRecords(req *request) (any, error) {
	q := req.r.URL.Query()
	filter := register.ListFilter{
		Class:  q.Get("class"),
		Status: q.Get("status"),
		Search: q.Get("q"),
		Order:  q.Get("order"),
		Desc:   boolParam(req.r, "desc"),
		Limit:  intParam(req.r, "limit", 50),
		Offset: intParam(req.r, "offset", 0),
		Match:  matchParams(q),
	}
	records, err := req.reg.ListObjects(req.p, filter)
	if err != nil {
		return nil, err
	}
	return map[string]any{"records": records, "count": len(records)}, nil
}

// matchParams reads the "match.<column>=<value>" query parameters that
// filter on a class's projected properties.
func matchParams(q url.Values) map[string]string {
	out := map[string]string{}
	for key, values := range q {
		if strings.HasPrefix(key, "match.") && len(values) > 0 {
			out[strings.TrimPrefix(key, "match.")] = values[0]
		}
	}
	return out
}

func (s *Server) getRecord(req *request) (any, error) {
	return req.reg.GetObject(req.p, req.r.PathValue("id"))
}

func (s *Server) getRecordVersion(req *request) (any, error) {
	version, err := strconv.ParseUint(req.r.PathValue("version"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("the version must be a whole number")
	}
	return req.reg.GetVersion(req.p, req.r.PathValue("id"), version)
}

func (s *Server) recordHistory(req *request) (any, error) {
	entries, err := req.reg.History(req.p, req.r.PathValue("id"))
	if err != nil {
		return nil, err
	}
	return map[string]any{"history": entries, "count": len(entries)}, nil
}

// -- workflows -------------------------------------------------------------

func (s *Server) listTasks(req *request) (any, error) {
	tasks, err := req.reg.Tasks(req.p, req.r.URL.Query().Get("state"), intParam(req.r, "limit", 50))
	if err != nil {
		return nil, err
	}
	return map[string]any{"tasks": tasks, "count": len(tasks)}, nil
}

func (s *Server) getTask(req *request) (any, error) {
	return req.reg.Task(req.p, req.r.PathValue("id"))
}

func (s *Server) propose(req *request) (any, error) {
	var body register.ProposeRequest
	if err := decode(req.r, &body); err != nil {
		return nil, err
	}
	return req.reg.Propose(req.p, req.r.PathValue("name"), body)
}

func (s *Server) accept(req *request) (any, error) {
	var body struct {
		Accept bool   `json:"accept"`
		Reason string `json:"reason,omitempty"`
	}
	if err := decode(req.r, &body); err != nil {
		return nil, err
	}
	return req.reg.Accept(req.p, req.r.PathValue("id"), body.Accept, body.Reason)
}

func (s *Server) decide(req *request) (any, error) {
	var body register.Decision
	if err := decode(req.r, &body); err != nil {
		return nil, err
	}
	return req.reg.Decide(req.p, req.r.PathValue("id"), body)
}

func (s *Server) withdraw(req *request) (any, error) {
	var body struct {
		Reason string `json:"reason,omitempty"`
	}
	if err := decode(req.r, &body); err != nil {
		return nil, err
	}
	return req.reg.Withdraw(req.p, req.r.PathValue("id"), body.Reason)
}

// -- the transaction log ---------------------------------------------------

func (s *Server) log_(req *request) (any, error) {
	q := req.r.URL.Query()
	entries, err := req.reg.Log(req.p, register.LogFilter{
		Class: q.Get("class"), ObjectID: q.Get("object_id"),
		Author: q.Get("author"), Role: q.Get("role"), Kind: q.Get("kind"),
		RefType: q.Get("ref_type"), Target: q.Get("target"),
		From: int64Param(req.r, "from"), To: int64Param(req.r, "to"),
		Limit: intParam(req.r, "limit", 50), Offset: intParam(req.r, "offset", 0),
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"transactions": entries, "count": len(entries)}, nil
}

func (s *Server) transaction(req *request) (any, error) {
	return req.reg.Transaction(req.p, req.r.PathValue("txid"))
}

// -- saved queries ---------------------------------------------------------

func (s *Server) listQueries(req *request) (any, error) {
	return map[string]any{"queries": req.reg.Pack().Queries}, nil
}

func (s *Server) runQuery(req *request) (any, error) {
	var body struct {
		Params map[string]string `json:"params,omitempty"`
	}
	if req.r.ContentLength > 0 {
		if err := decode(req.r, &body); err != nil {
			return nil, err
		}
	}
	rows, err := req.reg.RunQuery(req.p, req.r.PathValue("name"), body.Params)
	if err != nil {
		return nil, err
	}
	return map[string]any{"rows": rows, "count": len(rows)}, nil
}

// -- proofs ----------------------------------------------------------------

func (s *Server) recordProof(req *request) (any, error) {
	version, err := strconv.ParseUint(req.r.PathValue("version"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("the version must be a whole number")
	}
	return req.reg.RecordEvidence(req.p, req.r.PathValue("id"), version)
}

func (s *Server) naturalKeyProof(req *request) (any, error) {
	key, err := url.PathUnescape(req.r.PathValue("key"))
	if err != nil {
		return nil, fmt.Errorf("the key is not valid")
	}
	return req.reg.NaturalKeyEvidence(req.p, req.r.PathValue("class"), key)
}

// -- checkpoints -----------------------------------------------------------

func (s *Server) listCheckpoints(req *request) (any, error) {
	list, err := req.reg.Checkpoints(req.p, intParam(req.r, "limit", 50))
	if err != nil {
		return nil, err
	}
	return map[string]any{"checkpoints": list, "count": len(list)}, nil
}

func (s *Server) latestCheckpoint(req *request) (any, error) {
	if !req.p.Can(auth.PermCheckpoints) {
		return nil, fmt.Errorf("%s may not read checkpoints", req.p.Acting)
	}
	cp := req.reg.LatestCheckpoint()
	if cp == nil {
		return nil, fmt.Errorf("no checkpoint has been issued yet")
	}
	return cp, nil
}

func (s *Server) checkpointKey(req *request) (any, error) {
	keyID, public := req.reg.VerificationKey()
	return map[string]any{"key_id": keyID, "alg": "ed25519", "public_key": public}, nil
}

func (s *Server) issueCheckpoint(req *request) (any, error) {
	if !req.p.Can(auth.PermCheckpoints) {
		return nil, fmt.Errorf("%s may not issue checkpoints", req.p.Acting)
	}
	var body struct {
		Reason string `json:"reason,omitempty"`
	}
	if req.r.ContentLength > 0 {
		if err := decode(req.r, &body); err != nil {
			return nil, err
		}
	}
	reason := body.Reason
	if reason == "" {
		reason = register.ReasonManual
	}
	return req.reg.IssueCheckpoint(reason)
}

// -- retention and erasure -------------------------------------------------

func (s *Server) horizons(req *request) (any, error) {
	horizons, err := req.reg.Horizons(req.p)
	if err != nil {
		return nil, err
	}
	return map[string]any{"policies": horizons}, nil
}

func (s *Server) prune(req *request) (any, error) {
	var body register.PruneRequest
	if err := decode(req.r, &body); err != nil {
		return nil, err
	}
	return req.reg.Prune(req.p, body)
}

func (s *Server) erase(req *request) (any, error) {
	var body register.ErasureRequest
	if err := decode(req.r, &body); err != nil {
		return nil, err
	}
	return req.reg.Erase(req.p, body)
}

// -- keys ------------------------------------------------------------------

func (s *Server) enrolKey(req *request) (any, error) {
	var body struct {
		ID        string `json:"id"`
		Algorithm string `json:"algo"`
		PublicKey string `json:"public_key"`
	}
	if err := decode(req.r, &body); err != nil {
		return nil, err
	}
	return req.reg.EnrolKEK(req.p, body.ID, body.Algorithm, body.PublicKey)
}

func (s *Server) recoveryWrap(req *request) (any, error) {
	scope, err := url.PathUnescape(req.r.PathValue("scope"))
	if err != nil {
		return nil, fmt.Errorf("the scope is not valid")
	}
	return req.reg.RecoveryWrap(req.p, scope)
}

// -- operations ------------------------------------------------------------

func (s *Server) export(req *request) (any, error) {
	return req.reg.Export(req.p, req.r.URL.Query().Get("after"), intParam(req.r, "limit", 200))
}

func (s *Server) standby(req *request) (any, error) {
	if !req.p.Can(auth.PermAdmin) && !req.p.Can(auth.PermExplorer) {
		return nil, fmt.Errorf("%s may not read the standby report", req.p.Acting)
	}
	if s.Standby == nil {
		return map[string]any{"role": "active"}, nil
	}
	return s.Standby(), nil
}

func (s *Server) addWebhook(req *request) (any, error) {
	var body struct {
		ID     string   `json:"id"`
		URL    string   `json:"url"`
		Events []string `json:"events,omitempty"`
		Active *bool    `json:"active,omitempty"`
	}
	if err := decode(req.r, &body); err != nil {
		return nil, err
	}
	active := true
	if body.Active != nil {
		active = *body.Active
	}
	hook, txn, err := req.reg.SetWebhook(req.p, register.Webhook{
		ID: body.ID, URL: body.URL, Events: body.Events, Active: active,
	})
	if err != nil {
		return nil, err
	}
	// The signing secret is shown once, here. The register keeps it to
	// sign with; it does not serve it again, and it is not in the log.
	return map[string]any{"webhook": hook, "transaction": txn}, nil
}

func (s *Server) listWebhooks(req *request) (any, error) {
	hooks, err := req.reg.Webhooks(req.p)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"webhooks": hooks}
	if s.Deliveries != nil {
		out["deliveries"] = s.Deliveries()
	}
	return out, nil
}

// -- tool endpoints --------------------------------------------------------

func (s *Server) toolLookup(req *request) (any, error) {
	var body struct {
		Class      string `json:"class"`
		NaturalKey string `json:"natural_key"`
	}
	if err := decode(req.r, &body); err != nil {
		return nil, err
	}
	bundle, err := req.reg.NaturalKeyEvidence(req.p, body.Class, body.NaturalKey)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"registered": bundle.Present, "evidence": bundle}
	if bundle.Present {
		if id, ok := bundle.Row["object_id"].(string); ok {
			view, err := req.reg.GetObject(req.p, id)
			if err != nil {
				return nil, err
			}
			out["record"] = view
		}
	}
	return out, nil
}

func (s *Server) toolPropose(req *request) (any, error) {
	var body struct {
		Workflow string `json:"workflow"`
		register.ProposeRequest
	}
	if err := decode(req.r, &body); err != nil {
		return nil, err
	}
	return req.reg.Propose(req.p, body.Workflow, body.ProposeRequest)
}

func (s *Server) toolLog(req *request) (any, error) {
	var body struct {
		Class    string `json:"class,omitempty"`
		ObjectID string `json:"object_id,omitempty"`
		Kind     string `json:"kind,omitempty"`
		Limit    int    `json:"limit,omitempty"`
	}
	if req.r.ContentLength > 0 {
		if err := decode(req.r, &body); err != nil {
			return nil, err
		}
	}
	entries, err := req.reg.Log(req.p, register.LogFilter{
		Class: body.Class, ObjectID: body.ObjectID, Kind: body.Kind, Limit: body.Limit,
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"transactions": summarise(entries), "count": len(entries)}, nil
}

// summarise renders the log the way a reader wants it: one line each,
// like git log.
func summarise(entries []*model.Transaction) []map[string]any {
	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		out = append(out, map[string]any{
			"txid": e.TxID, "seq": e.Seq, "kind": e.Envelope.Kind,
			"author": e.Envelope.Author.Sub, "role": e.Envelope.Author.Role,
			"at":      time.Unix(e.Envelope.Timestamp, 0).UTC().Format(time.RFC3339),
			"summary": e.Envelope.Summary(), "version": e.VersionAfter,
		})
	}
	return out
}

func (s *Server) toolQuery(req *request) (any, error) {
	var body struct {
		Name   string            `json:"name"`
		Params map[string]string `json:"params,omitempty"`
	}
	if err := decode(req.r, &body); err != nil {
		return nil, err
	}
	rows, err := req.reg.RunQuery(req.p, body.Name, body.Params)
	if err != nil {
		return nil, err
	}
	return map[string]any{"rows": rows, "count": len(rows)}, nil
}

func (s *Server) toolStatus(req *request) (any, error) { return req.reg.Status() }

func (s *Server) toolCheckpoint(req *request) (any, error) {
	if !req.p.Can(auth.PermCheckpoints) {
		return nil, fmt.Errorf("%s may not issue checkpoints", req.p.Acting)
	}
	var body struct {
		Reason string `json:"reason,omitempty"`
	}
	if req.r.ContentLength > 0 {
		if err := decode(req.r, &body); err != nil {
			return nil, err
		}
	}
	if body.Reason == "" {
		body.Reason = register.ReasonManual
	}
	return req.reg.IssueCheckpoint(body.Reason)
}

// rawJSON keeps an already-encoded document from being escaped again on
// the way out.
func rawJSON(doc []byte) any {
	if len(doc) == 0 {
		return nil
	}
	return jsonRaw(doc)
}

type jsonRaw []byte

func (j jsonRaw) MarshalJSON() ([]byte, error) { return j, nil }

// -- audit -----------------------------------------------------------------

// The audit surface exists so an auditor does not have to take the
// register's word for anything. The lineage endpoint hands over the
// chain head with the proof that binds it to the live root; the roots
// endpoint hands over the sequence between two anchors. Folding one
// through the link function and comparing with the other is a check
// that needs no commitment key and no trust in the answer.

func (s *Server) lineage(req *request) (any, error) {
	return req.reg.Lineage(req.p)
}

func (s *Server) auditRoots(req *request) (any, error) {
	from := uint64(int64Param(req.r, "from"))
	to := uint64(int64Param(req.r, "to"))
	return req.reg.Roots(req.p, from, to)
}

func (s *Server) auditChanges(req *request) (any, error) {
	version, err := strconv.ParseUint(req.r.PathValue("version"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("the version must be a whole number")
	}
	return req.reg.ChangesAt(req.p, version, boolParam(req.r, "values"))
}

func (s *Server) auditVerify(req *request) (any, error) {
	var body struct {
		FromVersion uint64 `json:"from_version"`
		FromHead    string `json:"from_head,omitempty"`
	}
	if req.r.ContentLength > 0 {
		if err := decode(req.r, &body); err != nil {
			return nil, err
		}
	}
	if err := req.reg.VerifyLineage(req.p, body.FromVersion, body.FromHead); err != nil {
		return nil, err
	}
	return map[string]any{
		"verified": true, "from_version": body.FromVersion,
		"note": "this is the register vouching for itself; the independent check is to fold " +
			"GET /api/v1/audit/roots through the link function between two signed anchors",
	}, nil
}

func (s *Server) auditClose(req *request) (any, error) {
	var body register.AuditRequest
	if err := decode(req.r, &body); err != nil {
		return nil, err
	}
	return req.reg.Audit(req.p, body)
}
