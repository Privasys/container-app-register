// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register

import (
	"errors"
	"fmt"
	"log/slog"
	"sort"
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
// operation, given on a wallet bound to the acting member. The operation
// is computed from the request the register is about to commit, so an
// approval of anything else (another decision, another reason, a task
// that has moved on) does not match. The approval is spent in the act's
// own transaction, which records it in its envelope.
//
// A member binds wallets the way they would register devices: each is a
// row of its own, any of them approves, the member sees and removes their
// own, and an administrator can remove one without touching the others.

// StepUpRequired refuses an act until the person approves it.
type StepUpRequired struct {
	// Act names the kind of act.
	Act string
	// OpHash is the hash of the operation to approve.
	OpHash string
	// Summary is the line the wallet shows.
	Summary string
	// Wallet is the bound wallet to ask (the one used last); empty when
	// the act binds one.
	Wallet string
	// Label is the label a wallet being bound is given.
	Label string
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
// with no wallet bound.
var ErrWalletNotBound = errors.New("wallet_not_bound: bind a wallet before acting")

// Wallet states /me reports.
const (
	WalletNone  = "none"
	WalletBound = "bound"
)

const (
	actBindWallet    = "bind_wallet"
	approvalNote     = "step_up.approval"
	stepUpNote       = "step_up.pending"
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

// stepUp says the act being carried out needs an approval of this
// operation. Nothing is checked yet: the act runs every check of its own
// first, and the approval is asked for, or admitted, only when the act
// is about to be committed (see admitStepUp), so nobody approves on
// their phone an act that would be refused anyway, and a refusal never
// depends on whether a wallet is bound.
func (r *Register) stepUp(tx *store.Tx, p *auth.Principal, act string, request any, summary string) error {
	hash, err := r.operationHash(p, act, request)
	if err != nil {
		return err
	}
	tx.Attach(stepUpNote, &pendingStepUp{p: p, act: act, hash: hash, summary: walletSummary(summary)})
	return nil
}

type pendingStepUp struct {
	p                  *auth.Principal
	act, hash, summary string
}

// admitStepUp runs at commit, after the act's own checks: an act that
// needs an approval goes ahead only with one of this very operation,
// given on a wallet bound to the member, and not spent before.
func (r *Register) admitStepUp(tx *store.Tx) error {
	need, _ := tx.Detach(stepUpNote).(*pendingStepUp)
	if need == nil {
		return nil
	}
	p := need.p
	wallets, err := r.walletsOf(tx, p.Tenant, p.Sub)
	if err != nil {
		return err
	}
	if len(wallets) == 0 {
		return ErrWalletNotBound
	}
	a := p.Approval
	if a == nil || a.OpHash != need.hash {
		return &StepUpRequired{Act: need.act, OpHash: need.hash, Summary: need.summary, Wallet: wallets[0].Wallet, Member: p.Sub}
	}
	for _, w := range wallets {
		if w.Wallet == a.Wallet {
			return r.keepApproval(tx, a)
		}
	}
	return fmt.Errorf("the approval may not be used: it was given on a wallet not bound to you")
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
// approval its act was admitted with, and when the wallet was last used.
func spendApproval(tx *store.Tx, env *model.Envelope) []model.WriteOp {
	a, _ := tx.Detach(approvalNote).(*model.Approval)
	if a == nil {
		return nil
	}
	env.Approval = a
	ops := []model.WriteOp{{
		Table: "step_up_approvals",
		Key:   map[string]any{"id": a.ID},
		Values: map[string]any{
			"tenant": env.Tenant, "sub": env.Author.Sub, "wallet": a.Wallet, "op_hash": a.OpHash,
			"approved_at": a.ApprovedAt, "txid": model.TxIDPlaceholder,
		},
	}}
	if env.Kind != model.KindWalletBind {
		ops = append(ops, model.WriteOp{
			Table:  "member_wallets",
			Key:    map[string]any{"tenant": env.Tenant, "sub": env.Author.Sub, "wallet": a.Wallet},
			Values: map[string]any{"last_used_at": env.Timestamp},
		})
	}
	return ops
}

func walletSummary(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > maxWalletSummary {
		s = string(r[:maxWalletSummary-1]) + "…"
	}
	return s
}

// MemberWallet is one wallet bound to a member.
type MemberWallet struct {
	Sub        string `json:"sub"`
	Name       string `json:"name,omitempty"`
	Wallet     string `json:"wallet"`
	Label      string `json:"label,omitempty"`
	BoundAt    int64  `json:"bound_at"`
	LastUsedAt int64  `json:"last_used_at,omitempty"`
	TxID       string `json:"txid"`
}

func decodeWallet(row store.Row) *MemberWallet {
	return &MemberWallet{
		Sub: row.Str("sub"), Wallet: row.Str("wallet"), Label: row.Str("label"),
		BoundAt: row.Int("bound_at"), LastUsedAt: row.Int("last_used_at"), TxID: row.Str("txid"),
	}
}

// walletsOf lists a member's wallets, the one used last first.
func (r *Register) walletsOf(tx *store.Tx, tenant, sub string) ([]*MemberWallet, error) {
	rows, err := tx.Query("SELECT * FROM `member_wallets` WHERE tenant = " + store.Lit(tenant) +
		" AND sub = " + store.Lit(sub))
	if err != nil {
		return nil, err
	}
	out := make([]*MemberWallet, 0, len(rows))
	for _, row := range rows {
		out = append(out, decodeWallet(row))
	}
	last := func(w *MemberWallet) int64 { return max(w.LastUsedAt, w.BoundAt) }
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && last(out[j]) > last(out[j-1]); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out, nil
}

// WalletState says whether a member has a wallet bound, and how many.
func (r *Register) WalletState(tenant, sub string) (string, int, error) {
	var n int
	err := r.st.Do(func(tx *store.Tx) error {
		list, err := r.walletsOf(tx, tenant, sub)
		n = len(list)
		return err
	})
	if n == 0 {
		return WalletNone, 0, err
	}
	return WalletBound, n, err
}

// BindWallet binds to the caller the wallet that approves the binding.
// The first call is refused with StepUpRequired, which the identity
// provider turns into a link for the wallet to scan; the call made again
// with that approval binds the wallet whose subject it names. A member
// may bind several; a wallet serves one member. The label is the
// member's name for it ("work phone").
func (r *Register) BindWallet(p *auth.Principal, label string) (*MemberWallet, *model.Transaction, error) {
	if !r.pk.StepUpUsed() {
		return nil, nil, fmt.Errorf("this register asks for no approvals, so binds no wallets")
	}
	label = strings.TrimSpace(label)
	if len([]rune(label)) > 64 {
		return nil, nil, fmt.Errorf("a wallet's label is at most 64 characters")
	}
	var (
		out *MemberWallet
		txn *model.Transaction
	)
	err := r.st.Do(func(tx *store.Tx) error {
		hash, err := r.operationHash(p, actBindWallet, map[string]any{"label": label})
		if err != nil {
			return err
		}
		a := p.Approval
		if a == nil || a.OpHash != hash {
			return &StepUpRequired{Act: actBindWallet, OpHash: hash, Member: p.Sub, Label: label,
				Summary: walletSummary("Link this wallet to your access to " + orDefault(r.pk.Title, r.pk.Name))}
		}
		other, err := tx.QueryOne("SELECT sub FROM `member_wallets` WHERE tenant = " + store.Lit(p.Tenant) +
			" AND wallet = " + store.Lit(a.Wallet))
		if err != nil {
			return err
		}
		if other != nil {
			if other.Str("sub") == p.Sub {
				return fmt.Errorf("this wallet is already bound to you")
			}
			return fmt.Errorf("this wallet is already bound to another member")
		}
		if err := r.keepApproval(tx, a); err != nil {
			return err
		}
		at := r.now()
		txn, err = r.commit(tx, model.Envelope{
			Kind: model.KindWalletBind, Tenant: p.Tenant, Author: principalAuthor(p), Timestamp: at,
			Message: composeMessage(clip("Bind a wallet to "+clip(p.Sub, 16), model.MaxSummary),
				strings.TrimSpace("The wallet approves this member's acts from now on. "+label)),
		}, []model.WriteOp{{
			Table: "member_wallets",
			Key:   map[string]any{"tenant": p.Tenant, "sub": p.Sub, "wallet": a.Wallet},
			Values: map[string]any{
				"label": label, "bound_at": at, "last_used_at": int64(0), "txid": model.TxIDPlaceholder,
			},
		}})
		if err != nil {
			return err
		}
		row, err := tx.QueryOne("SELECT * FROM `member_wallets` WHERE tenant = " + store.Lit(p.Tenant) +
			" AND sub = " + store.Lit(p.Sub) + " AND wallet = " + store.Lit(a.Wallet))
		if err == nil && row != nil {
			out = decodeWallet(row)
		}
		return err
	})
	if err == nil {
		r.emitWallet(pack.EventWalletBound, p.Tenant, p.Sub, out, txn, "")
	}
	return out, txn, err
}

// MyWallets lists the caller's own wallets.
func (r *Register) MyWallets(p *auth.Principal) ([]*MemberWallet, error) {
	var out []*MemberWallet
	err := r.st.Do(func(tx *store.Tx) error {
		var err error
		out, err = r.walletsOf(tx, p.Tenant, p.Sub)
		return err
	})
	return out, err
}

// RemoveMyWallet unbinds one of the caller's own wallets.
func (r *Register) RemoveMyWallet(p *auth.Principal, wallet, reason string) (*model.Transaction, error) {
	return r.removeWallet(p, p.Sub, wallet, reason)
}

// RemoveWallet unbinds one wallet of a member, say for a lost phone,
// leaving the member and their other wallets as they are. Whoever
// manages members may, and says why.
func (r *Register) RemoveWallet(p *auth.Principal, member, wallet, reason string) (*model.Transaction, error) {
	if !p.Can(auth.PermMembers) {
		return nil, fmt.Errorf("%s may not manage members", p.Acting)
	}
	if strings.TrimSpace(reason) == "" {
		return nil, fmt.Errorf("say why the wallet is removed")
	}
	return r.removeWallet(p, member, wallet, reason)
}

func (r *Register) removeWallet(p *auth.Principal, member, wallet, reason string) (*model.Transaction, error) {
	var (
		txn *model.Transaction
		w   *MemberWallet
	)
	err := r.st.Do(func(tx *store.Tx) error {
		row, err := tx.QueryOne("SELECT * FROM `member_wallets` WHERE tenant = " + store.Lit(p.Tenant) +
			" AND sub = " + store.Lit(member) + " AND wallet = " + store.Lit(wallet))
		if err != nil {
			return err
		}
		if row == nil {
			return fmt.Errorf("no such wallet: it is not bound to %s", clip(member, 24))
		}
		w = decodeWallet(row)
		summary := "Remove a wallet of " + clip(member, 16)
		if member == p.Sub {
			summary = "Remove one of my wallets"
		}
		txn, err = r.commit(tx, model.Envelope{
			Kind: model.KindWalletUnbind, Tenant: p.Tenant, Author: principalAuthor(p), Timestamp: r.now(),
			Message: composeMessage(clip(summary, model.MaxSummary),
				strings.TrimSpace(orDefault(strings.TrimSpace(reason), "The member removed it.")+" "+w.Label)),
		}, []model.WriteOp{{
			Table: "member_wallets", Delete: true,
			Key: map[string]any{"tenant": p.Tenant, "sub": member, "wallet": wallet},
		}})
		return err
	})
	if err == nil {
		r.emitWallet(pack.EventWalletRemoved, p.Tenant, member, w, txn, reason)
	}
	return txn, err
}

// WalletBindings lists the wallets bound to members, or to one member,
// each with the member's name.
func (r *Register) WalletBindings(p *auth.Principal, member string) ([]*MemberWallet, error) {
	if !p.Can(auth.PermMembers) {
		return nil, fmt.Errorf("%s may not manage members", p.Acting)
	}
	out := []*MemberWallet{}
	err := r.st.Do(func(tx *store.Tx) error {
		q := "SELECT * FROM `member_wallets` WHERE tenant = " + store.Lit(p.Tenant)
		if member != "" {
			q += " AND sub = " + store.Lit(member)
		}
		rows, err := tx.Query(q + " ORDER BY sub, bound_at")
		if err != nil {
			return err
		}
		names := map[string]string{}
		for _, row := range rows {
			w := decodeWallet(row)
			if _, ok := names[w.Sub]; !ok {
				names[w.Sub] = ""
				if prof, err := r.profileIn(tx, w.Sub); err == nil {
					names[w.Sub] = prof.Name
				}
			}
			w.Name = names[w.Sub]
			out = append(out, w)
		}
		return nil
	})
	return out, err
}

// emitWallet resolves and hands on the notices that follow a wallet
// being bound or removed, so a binding nobody expected is noticed.
func (r *Register) emitWallet(event, tenant, member string, w *MemberWallet, txn *model.Transaction, reason string) {
	if r.notices == nil || txn == nil {
		return
	}
	rules := r.pk.NotificationsOn(pack.WalletEvents, event)
	if len(rules) == 0 {
		return
	}
	var notices []Notice
	err := r.st.Do(func(tx *store.Tx) error {
		for _, n := range rules {
			out := Notice{
				Template: n.Template, Workflow: pack.WalletEvents, Event: event, TxID: txn.TxID,
				At: txn.Envelope.Timestamp, Reason: reason, Member: r.personName(tx, member),
			}
			if w != nil {
				out.WalletLabel = w.Label
			}
			subs := []string{}
			add := func(sub string) {
				if sub != "" && !strings.HasPrefix(sub, "system:") && !containsString(subs, sub) {
					subs = append(subs, sub)
				}
			}
			for _, rule := range n.To {
				switch {
				case rule.Member:
					add(member)
				case rule.Role != "":
					holders, err := r.holdersOf(tx, tenant, rule.Role)
					if err != nil {
						return err
					}
					for _, sub := range holders {
						add(sub)
					}
				}
			}
			sort.Strings(subs)
			for _, sub := range subs {
				profile, err := r.profileIn(tx, sub)
				if err != nil {
					return err
				}
				if profile.Email == "" || profile.Erased {
					continue
				}
				out.Recipients = append(out.Recipients, NoticeRecipient{Sub: sub, Name: profile.Name, Email: profile.Email})
			}
			if len(out.Recipients) > 0 {
				notices = append(notices, out)
			}
		}
		return nil
	})
	if err != nil {
		slog.Warn("notifications: recipients not resolved", "event", "wallet:"+event, "error", err)
		return
	}
	for _, n := range notices {
		r.notices.Deliver(n)
	}
}

// personName is how a summary names a person: their recorded name, else
// a shortened subject.
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
