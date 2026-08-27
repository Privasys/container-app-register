// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/register"
	"github.com/Privasys/container-app-register/internal/store"
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
	reg, verifier, err := s.Configure(body)
	if err != nil {
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
	writeJSON(w, http.StatusOK, map[string]any{"status": "configured", "register": status})
}

// -- status and shape ------------------------------------------------------

func (s *Server) status(req *request) (any, error) { return req.reg.Status() }

func (s *Server) me(req *request) (any, error) {
	return map[string]any{
		"principal":   req.p,
		"permissions": req.p.Permissions(),
	}, nil
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
	if !req.p.Can(auth.PermAdmin) {
		return nil, fmt.Errorf("%s may not manage webhooks", req.p.Acting)
	}
	var body struct {
		ID     string   `json:"id"`
		URL    string   `json:"url"`
		Events []string `json:"events,omitempty"`
		Active *bool    `json:"active,omitempty"`
	}
	if err := decode(req.r, &body); err != nil {
		return nil, err
	}
	if body.ID == "" || body.URL == "" {
		return nil, fmt.Errorf("a webhook needs an id and a url")
	}
	if !strings.HasPrefix(body.URL, "https://") {
		return nil, fmt.Errorf("a webhook url must be https")
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	active := true
	if body.Active != nil {
		active = *body.Active
	}
	err := req.reg.Store().Do(func(tx *store.Tx) error {
		if err := tx.Exec("DELETE FROM `webhooks` WHERE id = " + store.Lit(body.ID)); err != nil {
			return err
		}
		return tx.Exec(store.Insert("webhooks", map[string]any{
			"id": body.ID, "tenant": req.p.Tenant, "url": body.URL,
			"secret": secret, "events": strings.Join(body.Events, ","),
			"active": active, "created_at": time.Now().UTC().Unix(),
		}))
	})
	if err != nil {
		return nil, err
	}
	// The signing secret is shown once, here. The register keeps it to
	// sign with; it does not serve it again.
	return map[string]any{
		"id": body.ID, "url": body.URL, "active": active,
		"secret": base64.StdEncoding.EncodeToString(secret),
	}, nil
}

func (s *Server) listWebhooks(req *request) (any, error) {
	if !req.p.Can(auth.PermAdmin) {
		return nil, fmt.Errorf("%s may not manage webhooks", req.p.Acting)
	}
	rows, err := req.reg.Store().Query("SELECT id, tenant, url, events, active, created_at FROM `webhooks`")
	if err != nil {
		return nil, err
	}
	return map[string]any{"webhooks": rows}, nil
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
			"summary": e.Envelope.Summary(), "root_after": e.RootAfter,
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
