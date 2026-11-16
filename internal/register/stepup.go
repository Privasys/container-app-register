// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/canon"
	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/pack"
	"github.com/Privasys/container-app-register/internal/store"
)

// Step-up: acts a person approves on their wallet.
//
// The pack names the acts (decisions on given workflows, grants and
// removals of given roles, erasures). Such an act is refused with
// StepUpRequired, which carries the operation's hash and a summary for
// the wallet, until the request carries an approval of that same
// operation, given on the wallet bound to the acting member. The
// operation is computed from the request the register is about to
// commit, so an approval of anything else (another decision, another
// reason, a task that has moved on) does not match. The approval is
// spent in the act's own transaction, which records it in its envelope.

// StepUpRequired refuses an act until the person approves it.
type StepUpRequired struct {
	// Act names the kind of act.
	Act string
	// OpHash is the hash of the operation to approve.
	OpHash string
	// Summary is the line the wallet shows.
	Summary string
	// Wallet is the bound wallet to ask; empty when the act binds one.
	Wallet string
	// Member is the acting member.
	Member string
}

func (e *StepUpRequired) Error() string {
	return "step_up_required: approve this on your wallet: " + e.Summary
}

// Bind reports whether the approval binds a wallet, so goes to whoever
// scans the link rather than to a bound wallet.
func (e *StepUpRequired) Bind() bool { return e.Act == actBindWallet }

// ErrWalletNotBound refuses an act needing an approval from a member
// with no wallet bound and confirmed.
var ErrWalletNotBound = errors.New("wallet_not_bound: bind a wallet before acting")

// Wallet binding states.
const (
	WalletNone                = "none"
	WalletPendingConfirmation = "pending_confirmation"
	WalletBound               = "bound"
)

const (
	actBindWallet    = "bind_wallet"
	actConfirmWallet = "confirm_wallet"
	approvalNote     = "step_up.approval"
	maxWalletSummary = 140
)

// operation is what a person approves. Its canonical form is hashed.
type operation struct {
	Act      string `json:"act"`
	Register string `json:"register"`
	Tenant   string `json:"tenant"`
	Member   string `json:"member"`
	Request  any    `json:"request"`
}

func (r *Register) operationHash(p *auth.Principal, act string, request any) (string, error) {
	raw, err := canon.Marshal(operation{Act: act, Register: r.pk.Name, Tenant: p.Tenant, Member: p.Sub, Request: request})
	if err != nil {
		return "", err
	}
	return auth.OperationHash(raw), nil
}

// stepUp admits an act that needs an approval, and keeps the approval
// with the transaction, for commit to record and spend. Called inside
// the act's store transaction, after its own checks.
func (r *Register) stepUp(tx *store.Tx, p *auth.Principal, act string, request any, summary string) error {
	hash, err := r.operationHash(p, act, request)
	if err != nil {
		return err
	}
	binding, err := r.walletBinding(tx, p.Tenant, p.Sub)
	if err != nil {
		return err
	}
	switch {
	case binding == nil:
		return ErrWalletNotBound
	case binding.State != WalletBound:
		return fmt.Errorf("%w: the wallet bound to you waits for an administrator to confirm it", ErrWalletNotBound)
	}
	a := p.Approval
	if a == nil || a.OpHash != hash {
		return &StepUpRequired{Act: act, OpHash: hash, Summary: walletSummary(summary), Wallet: binding.Wallet, Member: p.Sub}
	}
	if a.Wallet != binding.Wallet {
		return fmt.Errorf("the approval may not be used: it was given on a wallet not bound to you")
	}
	return r.keepApproval(tx, a)
}

func (r *Register) keepApproval(tx *store.Tx, a *auth.Approval) error {
	spent, err := tx.QueryOne("SELECT id FROM `step_up_approvals` WHERE id = " + store.Lit(a.ID))
	if err != nil {
		return err
	}
	if spent != nil {
		return fmt.Errorf("the approval may not be used: it has been used already")
	}
	tx.Attach(approvalNote, &model.Approval{
		OpHash: a.OpHash, SummaryHash: a.SummaryHash, Wallet: a.Wallet, ID: a.ID, ApprovedAt: a.IssuedAt,
	})
	return nil
}

// spendApproval records, in the transaction being committed, the
// approval its act was admitted with.
func spendApproval(tx *store.Tx, env *model.Envelope) []model.WriteOp {
	a, _ := tx.Detach(approvalNote).(*model.Approval)
	if a == nil {
		return nil
	}
	env.Approval = a
	return []model.WriteOp{{
		Table: "step_up_approvals",
		Key:   map[string]any{"id": a.ID},
		Values: map[string]any{
			"tenant": env.Tenant, "sub": env.Author.Sub, "wallet": a.Wallet, "op_hash": a.OpHash,
			"approved_at": a.ApprovedAt, "txid": model.TxIDPlaceholder,
		},
	}}
}

func walletSummary(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > maxWalletSummary {
		s = string(r[:maxWalletSummary-1]) + "…"
	}
	return s
}

// WalletBinding is the wallet a member approves their acts on.
type WalletBinding struct {
	Sub         string `json:"sub"`
	Wallet      string `json:"wallet"`
	State       string `json:"state"`
	BoundAt     int64  `json:"bound_at"`
	ConfirmedBy string `json:"confirmed_by,omitempty"`
	ConfirmedAt int64  `json:"confirmed_at,omitempty"`
	TxID        string `json:"txid"`
}

func bindingID(tenant, sub string) string { return tenant + "|" + sub }

func decodeBinding(row store.Row) *WalletBinding {
	return &WalletBinding{
		Sub: row.Str("sub"), Wallet: row.Str("wallet"), State: row.Str("state"),
		BoundAt: row.Int("bound_at"), ConfirmedBy: row.Str("confirmed_by"),
		ConfirmedAt: row.Int("confirmed_at"), TxID: row.Str("txid"),
	}
}

func (r *Register) walletBinding(tx *store.Tx, tenant, sub string) (*WalletBinding, error) {
	row, err := tx.QueryOne("SELECT * FROM `wallet_bindings` WHERE id = " + store.Lit(bindingID(tenant, sub)))
	if err != nil || row == nil {
		return nil, err
	}
	return decodeBinding(row), nil
}

// WalletState says whether a member has a wallet bound: none,
// pending_confirmation or bound.
func (r *Register) WalletState(tenant, sub string) (string, error) {
	state := WalletNone
	err := r.st.Do(func(tx *store.Tx) error {
		b, err := r.walletBinding(tx, tenant, sub)
		if b != nil {
			state = b.State
		}
		return err
	})
	return state, err
}

// BindWallet binds to the caller the wallet that approves the binding.
// The first call is refused with StepUpRequired, which the identity
// provider turns into a link for the wallet to scan; the call made again
// with that approval binds the wallet whose subject it names. When the
// pack asks for confirmation, the binding then waits for an
// administrator, except the first in the register, which nobody could
// confirm.
func (r *Register) BindWallet(p *auth.Principal) (*WalletBinding, *model.Transaction, error) {
	if !r.pk.StepUpUsed() {
		return nil, nil, fmt.Errorf("this register asks for no approvals, so binds no wallets")
	}
	var (
		out *WalletBinding
		txn *model.Transaction
	)
	err := r.st.Do(func(tx *store.Tx) error {
		held, err := r.walletBinding(tx, p.Tenant, p.Sub)
		if err != nil {
			return err
		}
		if held != nil {
			return fmt.Errorf("a wallet is already bound to you; an administrator must unbind it first")
		}
		hash, err := r.operationHash(p, actBindWallet, map[string]any{})
		if err != nil {
			return err
		}
		a := p.Approval
		if a == nil || a.OpHash != hash {
			return &StepUpRequired{Act: actBindWallet, OpHash: hash, Member: p.Sub,
				Summary: walletSummary("Link your wallet to " + orDefault(r.pk.Title, r.pk.Name))}
		}
		other, err := tx.QueryOne("SELECT sub FROM `wallet_bindings` WHERE tenant = " + store.Lit(p.Tenant) +
			" AND wallet = " + store.Lit(a.Wallet))
		if err != nil {
			return err
		}
		if other != nil {
			return fmt.Errorf("this wallet is already bound to another member")
		}
		if err := r.keepApproval(tx, a); err != nil {
			return err
		}
		state := WalletBound
		if r.pk.StepUpBindConfirmation() {
			any, err := tx.QueryOne("SELECT id FROM `wallet_bindings` WHERE tenant = " + store.Lit(p.Tenant) +
				" AND state = " + store.Lit(WalletBound) + " LIMIT 1")
			if err != nil {
				return err
			}
			if any != nil {
				state = WalletPendingConfirmation
			}
		}
		at := r.now()
		body := "The wallet now approves this member's acts."
		if state == WalletPendingConfirmation {
			body = "The wallet will approve this member's acts once an administrator confirms it."
		}
		txn, err = r.commit(tx, model.Envelope{
			Kind: model.KindWalletBind, Tenant: p.Tenant, Author: principalAuthor(p), Timestamp: at,
			Message: composeMessage(clip("Bind a wallet to "+clip(p.Sub, 16), model.MaxSummary), body),
		}, []model.WriteOp{{
			Table: "wallet_bindings",
			Key:   map[string]any{"id": bindingID(p.Tenant, p.Sub)},
			Values: map[string]any{
				"tenant": p.Tenant, "sub": p.Sub, "wallet": a.Wallet, "state": state, "bound_at": at,
				"confirmed_by": "", "confirmed_at": int64(0), "txid": model.TxIDPlaceholder,
			},
		}})
		if err != nil {
			return err
		}
		out, err = r.walletBinding(tx, p.Tenant, p.Sub)
		return err
	})
	return out, txn, err
}

// ConfirmWallet confirms a member's newly bound wallet. The confirming
// administrator approves the confirmation on their own wallet, and may
// not confirm their own.
func (r *Register) ConfirmWallet(p *auth.Principal, sub string) (*WalletBinding, *model.Transaction, error) {
	if !p.Can(auth.PermMembers) {
		return nil, nil, fmt.Errorf("%s may not manage members", p.Acting)
	}
	if sub == p.Sub {
		return nil, nil, fmt.Errorf("separation of duties: a member may not confirm their own wallet")
	}
	var (
		out *WalletBinding
		txn *model.Transaction
	)
	err := r.st.Do(func(tx *store.Tx) error {
		b, err := r.walletBinding(tx, p.Tenant, sub)
		if err != nil {
			return err
		}
		if b == nil {
			return fmt.Errorf("no such binding: no wallet is bound to %s", clip(sub, 24))
		}
		if b.State != WalletPendingConfirmation {
			return fmt.Errorf("the wallet of %s is not awaiting confirmation", clip(sub, 24))
		}
		if err := r.stepUp(tx, p, actConfirmWallet, map[string]any{"sub": sub, "wallet": b.Wallet},
			"Confirm the wallet bound to "+r.personName(tx, sub)); err != nil {
			return err
		}
		at := r.now()
		txn, err = r.commit(tx, model.Envelope{
			Kind: model.KindWalletConfirm, Tenant: p.Tenant, Author: principalAuthor(p), Timestamp: at,
			Message: composeMessage(clip("Confirm the wallet of "+clip(sub, 16), model.MaxSummary),
				"The wallet now approves this member's acts."),
		}, []model.WriteOp{{
			Table: "wallet_bindings",
			Key:   map[string]any{"id": bindingID(p.Tenant, sub)},
			Values: map[string]any{
				"tenant": p.Tenant, "sub": sub, "wallet": b.Wallet, "state": WalletBound, "bound_at": b.BoundAt,
				"confirmed_by": p.Sub, "confirmed_at": at, "txid": model.TxIDPlaceholder,
			},
		}})
		if err != nil {
			return err
		}
		out, err = r.walletBinding(tx, p.Tenant, sub)
		return err
	})
	return out, txn, err
}

// UnbindWallet removes a member's wallet, say when a phone is lost; the
// member binds another. It needs a reason, recorded with it.
func (r *Register) UnbindWallet(p *auth.Principal, sub, reason string) (*model.Transaction, error) {
	if !p.Can(auth.PermMembers) {
		return nil, fmt.Errorf("%s may not manage members", p.Acting)
	}
	if strings.TrimSpace(reason) == "" {
		return nil, fmt.Errorf("say why the wallet is unbound")
	}
	var txn *model.Transaction
	err := r.st.Do(func(tx *store.Tx) error {
		b, err := r.walletBinding(tx, p.Tenant, sub)
		if err != nil {
			return err
		}
		if b == nil {
			return fmt.Errorf("no such binding: no wallet is bound to %s", clip(sub, 24))
		}
		txn, err = r.commit(tx, model.Envelope{
			Kind: model.KindWalletUnbind, Tenant: p.Tenant, Author: principalAuthor(p), Timestamp: r.now(),
			Message: composeMessage(clip("Unbind the wallet of "+clip(sub, 16), model.MaxSummary), reason),
		}, []model.WriteOp{{
			Table: "wallet_bindings", Key: map[string]any{"id": bindingID(p.Tenant, sub)}, Delete: true,
		}})
		return err
	})
	return txn, err
}

// WalletBindings lists the wallets bound to members.
func (r *Register) WalletBindings(p *auth.Principal) ([]*WalletBinding, error) {
	if !p.Can(auth.PermMembers) {
		return nil, fmt.Errorf("%s may not manage members", p.Acting)
	}
	var out []*WalletBinding
	err := r.st.Do(func(tx *store.Tx) error {
		rows, err := tx.Query("SELECT * FROM `wallet_bindings` WHERE tenant = " + store.Lit(p.Tenant) + " ORDER BY sub")
		for _, row := range rows {
			out = append(out, decodeBinding(row))
		}
		return err
	})
	return out, err
}

// personName is how a wallet summary names a person: their recorded
// name, else a shortened subject.
func (r *Register) personName(tx *store.Tx, sub string) string {
	if prof, err := r.profileIn(tx, sub); err == nil && prof.Name != "" {
		return prof.Name
	}
	return clip(sub, 16)
}

func decisionName(approve bool) string {
	if approve {
		return pack.StepUpApprove
	}
	return pack.StepUpReject
}

// stepUpDecision admits a reviewer's decision on a workflow the pack
// names. The operation binds the decision to the task as it stands, so
// an approval cannot be carried to another task, nor to this one after
// it has moved on.
func (r *Register) stepUpDecision(tx *store.Tx, p *auth.Principal, wf *pack.Workflow, task *model.Task,
	decision, reason string, d Decision) error {
	if !r.pk.StepUpDecision(wf.Name, decision) {
		return nil
	}
	verb := map[string]string{pack.StepUpApprove: "Approve", pack.StepUpReject: "Reject", pack.StepUpReturn: "Return"}[decision]
	about := task.Message
	if i := strings.IndexByte(about, '\n'); i >= 0 {
		about = about[:i]
	}
	return r.stepUp(tx, p, "decide", map[string]any{
		"task": task.ID, "workflow": wf.Name, "decision": decision, "reason": reason,
		"message": d.Message, "body": d.Body, "refs": d.Refs,
		"state": task.State, "updated_at": task.UpdatedAt,
	}, verb+": "+orDefault(about, displayName(wf)))
}

func (r *Register) roleTitle(role string) string {
	if spec := r.pk.Model().Role(role); spec != nil && spec.Title != "" {
		return spec.Title
	}
	return role
}
