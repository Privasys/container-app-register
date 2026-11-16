// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"context"
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
// asked the identity provider for: its identifier, the summary the wallet
// shows, whether a push reached the wallet, and a link to show as a QR
// code when it did not. The page polls GET /api/v1/step-up/{approval_id};
// once the answer is "approved" it sends the same request again with the
// header Step-Up-Approval: <approval_id>. The register holds the token
// the identity provider issued, so it never passes through the browser,
// and admits the act only if what it is about to commit is what was
// approved. Acting with no wallet bound is refused with 412.

// StepUpHeader carries the approval an act is sent again with.
const StepUpHeader = "Step-Up-Approval"

// ApprovalService is the identity provider's approval service, set by
// configuration; nil, acts that need an approval cannot be approved.
type ApprovalService struct{ auth.Approvals }

// approvalBook keeps the approvals asked for, in memory: each lives for
// minutes, and a restart only means asking again.
type approvalBook struct {
	mu sync.Mutex
	m  map[string]*askedApproval
}

type askedApproval struct {
	mu          sync.Mutex
	sub, tenant string
	opHash      string
	expires     int64
	state       string
	approval    *auth.Approval
}

func (b *approvalBook) put(id string, a *askedApproval) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.m == nil {
		b.m = map[string]*askedApproval{}
	}
	now := time.Now().Unix()
	for k, v := range b.m {
		if v.expires < now-60 {
			delete(b.m, k)
		}
	}
	b.m[id] = a
}

func (b *approvalBook) get(id string) *askedApproval {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.m[id]
}

func (b *approvalBook) forget(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.m, id)
}

var (
	errNoApproval      = errors.New("no such approval: ask again")
	errNotApproved     = errors.New("the approval has not been given")
	errNoApprovals     = errors.New("approvals are not configured on this register")
	errApprovalMoved   = errors.New("the approval does not match what was asked")
	errApprovalExpired = errors.New("the approval has expired: ask again")
)

// askApproval answers an act that needs an approval: it asks the
// identity provider, keeps the request, and replies 428.
func (s *Server) askApproval(w http.ResponseWriter, r *http.Request, p *auth.Principal, need *register.StepUpRequired) {
	svc := s.Approvals.Load()
	if svc == nil || svc.Approvals == nil {
		writeError(w, http.StatusServiceUnavailable, errNoApprovals.Error(), need.Summary)
		return
	}
	var (
		asked *auth.PendingApproval
		err   error
	)
	if need.Bind() {
		asked, err = svc.BeginBind(r.Context(), p.Sub, need.OpHash, need.Summary)
	} else {
		asked, err = svc.Begin(r.Context(), need.Wallet, need.OpHash, need.Summary)
	}
	if err != nil {
		s.log.Warn("could not ask for an approval", "error", err)
		writeError(w, http.StatusBadGateway, "the approval could not be asked for", err.Error())
		return
	}
	s.approvals.put(asked.ID, &askedApproval{
		sub: p.Sub, tenant: p.Tenant, opHash: need.OpHash, expires: asked.ExpiresAt, state: auth.ApprovalPending,
	})
	writeJSON(w, http.StatusPreconditionRequired, map[string]any{
		"error": "step_up_required", "act": need.Act, "summary": need.Summary,
		"approval_id": asked.ID, "push_sent": asked.PushSent, "wallet_link": asked.WalletLink,
		"expires_at": asked.ExpiresAt,
	})
}

// poll brings an asked approval up to date with the identity provider.
func (s *Server) poll(ctx context.Context, id string, p *auth.Principal) (*askedApproval, error) {
	a := s.approvals.get(id)
	if a == nil || a.sub != p.Sub || a.tenant != p.Tenant {
		return nil, errNoApproval
	}
	// One poll at a time: the identity provider hands the token out once.
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state != auth.ApprovalPending {
		return a, nil
	}
	if time.Now().Unix() > a.expires {
		a.state = auth.ApprovalExpired
		return a, nil
	}
	svc := s.Approvals.Load()
	if svc == nil || svc.Approvals == nil {
		return nil, errNoApprovals
	}
	state, token, err := svc.Poll(ctx, id)
	if err != nil {
		return nil, err
	}
	if state == auth.ApprovalApproved {
		approval, err := svc.Verify(ctx, token)
		if err != nil {
			return nil, err
		}
		if approval.OpHash != a.opHash {
			return nil, errApprovalMoved
		}
		a.approval = approval
	}
	a.state = state
	return a, nil
}

// stepUpState is GET /api/v1/step-up/{id}: pending, approved, declined
// or expired.
func (s *Server) stepUpState(req *request) (any, error) {
	a, err := s.poll(req.r.Context(), req.r.PathValue("id"), req.p)
	if err != nil {
		return nil, err
	}
	return map[string]any{"state": a.state, "expires_at": a.expires}, nil
}

// approvalFor finds the approval a request is sent again with.
func (s *Server) approvalFor(r *http.Request, p *auth.Principal) (string, *auth.Approval, error) {
	id := r.Header.Get(StepUpHeader)
	if id == "" {
		return "", nil, nil
	}
	a, err := s.poll(r.Context(), id, p)
	if err != nil {
		return id, nil, err
	}
	switch a.state {
	case auth.ApprovalApproved:
		return id, a.approval, nil
	case auth.ApprovalExpired:
		return id, nil, errApprovalExpired
	}
	return id, nil, errNotApproved
}

func (s *Server) bindWallet(req *request) (any, error) {
	binding, txn, err := req.reg.BindWallet(req.p)
	if err != nil {
		return nil, err
	}
	return map[string]any{"binding": binding, "transaction": txn}, nil
}

func (s *Server) listWalletBindings(req *request) (any, error) {
	list, err := req.reg.WalletBindings(req.p)
	if err != nil {
		return nil, err
	}
	if list == nil {
		list = []*register.WalletBinding{}
	}
	return map[string]any{"bindings": list}, nil
}

func (s *Server) confirmWallet(req *request) (any, error) {
	binding, txn, err := req.reg.ConfirmWallet(req.p, req.r.PathValue("sub"))
	if err != nil {
		return nil, err
	}
	return map[string]any{"binding": binding, "transaction": txn}, nil
}

func (s *Server) unbindWallet(req *request) (any, error) {
	txn, err := req.reg.UnbindWallet(req.p, req.r.PathValue("sub"), req.r.URL.Query().Get("reason"))
	if err != nil {
		return nil, err
	}
	return map[string]any{"transaction": txn}, nil
}
