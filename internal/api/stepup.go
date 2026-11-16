// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/register"
)

// Step-up over HTTP.
//
// An act the pack names is refused with 428 and the approval the register
// sent to the member's wallet: its identifier, the title the wallet shows,
// and whether the push went out. The wallet confirms the request is open
// (GET /.well-known/privasys/approval), the person answers, and the
// wallet delivers the identity provider's signed answer to the callback.
// The page polls GET /api/v1/step-up/{approval_id}; once it says
// "approved" it sends the same request again with the header
// Step-Up-Approval: <approval_id> (or ?step_up_approval=<id>, for a
// transport that sets no headers). The register holds the signed answer,
// so it never passes through the browser, and admits the act only if what
// it is about to commit is what was approved. Acting with no wallet bound
// is refused with 412.
//
// Binding a wallet is a link: the page asks for a nonce, the wallet links
// the person's Privasys ID with it, and the identity provider's token for
// that link names the subject the register then sends approvals to.

// StepUpHeader carries the approval an act is sent again with.
const StepUpHeader = "Step-Up-Approval"

// StepUpParam names the approval in the query, for a transport that
// cannot set headers; the header wins when both are given.
const StepUpParam = "step_up_approval"

// stepUpCallback is where wallets deliver their answers.
const stepUpCallback = "/api/v1/step-up/answer"

// ApprovalService is the approval path, set by configuration; nil, acts
// that need an approval cannot be approved.
type ApprovalService struct{ auth.Approvals }

// approvalBook keeps the approvals sent and the link nonces issued, in
// memory: each lives for minutes, and a restart only means asking again.
type approvalBook struct {
	mu     sync.Mutex
	m      map[string]*askedApproval
	nonces map[string]*linkNonce
}

type askedApproval struct {
	sub, tenant string
	opHash      string
	digest      string
	expires     int64
	state       string
	approval    *auth.Approval
}

type linkNonce struct {
	sub, tenant string
	expires     int64
}

func (b *approvalBook) put(id string, a *askedApproval) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.m == nil {
		b.m = map[string]*askedApproval{}
	}
	now := time.Now().Unix()
	for k, v := range b.m {
		if v.expires < now-600 {
			delete(b.m, k)
		}
	}
	b.m[id] = a
}

// get returns a copy of an approval's entry, current as to expiry.
func (b *approvalBook) get(id string) *askedApproval {
	b.mu.Lock()
	defer b.mu.Unlock()
	a := b.m[id]
	if a == nil {
		return nil
	}
	if a.state == auth.ApprovalPending && time.Now().Unix() > a.expires {
		a.state = auth.ApprovalExpired
	}
	c := *a
	return &c
}

func (b *approvalBook) answer(id string, state string, approval *auth.Approval) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if a := b.m[id]; a != nil && a.state == auth.ApprovalPending {
		a.state, a.approval = state, approval
	}
}

func (b *approvalBook) forget(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.m, id)
}

// nonce issues a single-use link nonce for a member's session.
func (b *approvalBook) nonce(sub, tenant string) (string, int64) {
	raw := make([]byte, 24)
	_, _ = rand.Read(raw)
	n := base64.RawURLEncoding.EncodeToString(raw)
	exp := time.Now().Add(10 * time.Minute).Unix()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.nonces == nil {
		b.nonces = map[string]*linkNonce{}
	}
	now := time.Now().Unix()
	for k, v := range b.nonces {
		if v.expires < now {
			delete(b.nonces, k)
		}
	}
	b.nonces[n] = &linkNonce{sub: sub, tenant: tenant, expires: exp}
	return n, exp
}

// spendNonce takes a nonce back, once, if it was issued to this member
// and is still fresh.
func (b *approvalBook) spendNonce(n, sub, tenant string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	v := b.nonces[n]
	delete(b.nonces, n)
	return v != nil && v.sub == sub && v.tenant == tenant && time.Now().Unix() <= v.expires
}

var (
	errNoApproval      = errors.New("no such approval: ask again")
	errNotApproved     = errors.New("the approval has not been given")
	errDeclined        = errors.New("the approval was declined")
	errNoApprovals     = errors.New("approvals are not configured on this register")
	errApprovalExpired = errors.New("the approval has expired: ask again")
)

// askApproval answers an act that needs an approval: it sends the
// approval to the member's wallet, keeps it, and replies 428.
func (s *Server) askApproval(w http.ResponseWriter, r *http.Request, p *auth.Principal, need *register.StepUpRequired) {
	svc := s.Approvals.Load()
	if svc == nil || svc.Approvals == nil {
		writeError(w, http.StatusServiceUnavailable, errNoApprovals.Error(), need.Summary)
		return
	}
	asked, err := svc.Ask(r.Context(), auth.ApprovalRequest{
		Wallet: need.Wallet, Title: need.Summary, Lines: need.Lines, ActDigest: need.OpHash,
		Assurance: need.Assurance, Callback: stepUpCallback, TTL: auth.ApprovalTTL,
	})
	if err != nil {
		s.log.Warn("could not send an approval", "error", err)
		writeError(w, http.StatusBadGateway, "the approval could not be sent to your wallet", err.Error())
		return
	}
	entry := &askedApproval{
		sub: p.Sub, tenant: p.Tenant, opHash: need.OpHash, digest: asked.Digest,
		expires: asked.ExpiresAt, state: auth.ApprovalPending,
	}
	if asked.Answer != nil {
		entry.state, entry.approval = auth.ApprovalApproved, asked.Answer
	}
	s.approvals.put(asked.ID, entry)
	writeJSON(w, http.StatusPreconditionRequired, map[string]any{
		"error": "step_up_required", "act": need.Act, "summary": need.Summary, "assurance": need.Assurance,
		"approval_id": asked.ID, "push_sent": asked.PushSent, "expires_at": asked.ExpiresAt,
	})
}

// stepUpState is GET /api/v1/step-up/{id}: pending, approved, declined
// or expired.
func (s *Server) stepUpState(req *request) (any, error) {
	a := s.approvals.get(req.r.PathValue("id"))
	if a == nil || a.sub != req.p.Sub || a.tenant != req.p.Tenant {
		return nil, errNoApproval
	}
	return map[string]any{"state": a.state, "expires_at": a.expires}, nil
}

// approvalOpen is GET /.well-known/privasys/approval?id=&digest=: the
// wallet asks whether the register is waiting on this approval, and
// shows no buttons until it is told so.
func (s *Server) approvalOpen(w http.ResponseWriter, r *http.Request) {
	id, digest := r.URL.Query().Get("id"), r.URL.Query().Get("digest")
	a := s.approvals.get(id)
	if a == nil || a.state != auth.ApprovalPending || a.digest != digest {
		writeError(w, http.StatusNotFound, "no such approval is open", "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"open": true, "id": id, "approval_digest": digest})
}

// approvalAnswer is POST /api/v1/step-up/answer {approval_id, decision,
// token}: the wallet delivers the identity provider's signed answer. It
// is kept against the approval it answers; the act it admits is checked
// again when the page sends it.
func (s *Server) approvalAnswer(w http.ResponseWriter, r *http.Request) {
	svc := s.Approvals.Load()
	if svc == nil || svc.Approvals == nil {
		writeError(w, http.StatusServiceUnavailable, errNoApprovals.Error(), "")
		return
	}
	var in struct {
		ApprovalID string `json:"approval_id"`
		Decision   string `json:"decision"`
		Token      string `json:"token"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "")
		return
	}
	a := s.approvals.get(in.ApprovalID)
	if a == nil || a.state != auth.ApprovalPending {
		writeError(w, http.StatusNotFound, "no such approval is open", "")
		return
	}
	answer, err := svc.VerifyAnswer(r.Context(), in.Token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "the answer is not valid", err.Error())
		return
	}
	switch {
	case answer.ApprovalID != in.ApprovalID || answer.ApprovalDigest != a.digest:
		writeError(w, http.StatusConflict, "the answer is for another approval", "")
		return
	case answer.OpHash != a.opHash:
		writeError(w, http.StatusConflict, "the answer approves another act", "")
		return
	case answer.Decision != in.Decision:
		writeError(w, http.StatusConflict, "the answer says otherwise than its token", "")
		return
	}
	state := auth.ApprovalApproved
	if answer.Decision != "approve" {
		state = auth.ApprovalDeclined
	}
	s.approvals.answer(in.ApprovalID, state, answer)
	writeJSON(w, http.StatusOK, map[string]any{"state": state})
}

// approvalFor finds the approval a request is sent again with.
func (s *Server) approvalFor(r *http.Request, p *auth.Principal) (string, *auth.Approval, error) {
	id := r.Header.Get(StepUpHeader)
	if id == "" {
		// A transport that sets no headers names it in the query.
		id = r.URL.Query().Get(StepUpParam)
	}
	if id == "" {
		return "", nil, nil
	}
	a := s.approvals.get(id)
	if a == nil || a.sub != p.Sub || a.tenant != p.Tenant {
		return id, nil, errNoApproval
	}
	switch a.state {
	case auth.ApprovalApproved:
		return id, a.approval, nil
	case auth.ApprovalDeclined:
		return id, nil, errDeclined
	case auth.ApprovalExpired:
		return id, nil, errApprovalExpired
	}
	return id, nil, errNotApproved
}

// walletNonce is POST /api/v1/me/wallets/nonce: a single-use nonce for
// linking a wallet from this session.
func (s *Server) walletNonce(req *request) (any, error) {
	n, exp := s.approvals.nonce(req.p.Sub, req.p.Tenant)
	return map[string]any{"nonce": n, "expires_at": exp}, nil
}

// bindWallet is POST /api/v1/me/wallets {id_token, nonce, label}: the
// identity provider's token for the link made with the nonce names the
// wallet bound to the caller.
func (s *Server) bindWallet(req *request) (any, error) {
	svc := s.Approvals.Load()
	if svc == nil || svc.Approvals == nil {
		return nil, errNoApprovals
	}
	var in struct {
		IDToken string `json:"id_token"`
		Nonce   string `json:"nonce"`
		Label   string `json:"label"`
	}
	if req.r.ContentLength != 0 {
		if err := decode(req.r, &in); err != nil {
			return nil, err
		}
	}
	if !s.approvals.spendNonce(in.Nonce, req.p.Sub, req.p.Tenant) {
		return nil, errors.New("the link nonce is not this session's, or has expired: ask for another")
	}
	name := req.p.Sub
	if in.Label != "" {
		name += ":" + in.Label
	}
	wallet, err := svc.VerifyLink(req.r.Context(), in.IDToken, in.Nonce, name)
	if err != nil {
		return nil, err
	}
	bound, txn, err := req.reg.BindWallet(req.p, wallet, in.Label)
	if err != nil {
		return nil, err
	}
	return map[string]any{"wallet": bound, "transaction": txn}, nil
}

func (s *Server) myWallets(req *request) (any, error) {
	list, err := req.reg.MyWallets(req.p)
	if err != nil {
		return nil, err
	}
	return map[string]any{"wallets": list}, nil
}

func (s *Server) removeMyWallet(req *request) (any, error) {
	txn, err := req.reg.RemoveMyWallet(req.p, req.r.PathValue("wallet"), req.r.URL.Query().Get("reason"))
	if err != nil {
		return nil, err
	}
	return map[string]any{"transaction": txn}, nil
}

func (s *Server) listWalletBindings(req *request) (any, error) {
	list, err := req.reg.WalletBindings(req.p, req.r.URL.Query().Get("member"))
	if err != nil {
		return nil, err
	}
	return map[string]any{"wallets": list}, nil
}

func (s *Server) removeWallet(req *request) (any, error) {
	txn, err := req.reg.RemoveWallet(req.p, req.r.PathValue("member"), req.r.PathValue("wallet"),
		req.r.URL.Query().Get("reason"))
	if err != nil {
		return nil, err
	}
	return map[string]any{"transaction": txn}, nil
}
