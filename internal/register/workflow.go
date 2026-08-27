// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/canon"
	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/pack"
	"github.com/Privasys/container-app-register/internal/store"
)

// The workflow primitive: propose, optionally have a second party
// accept, then decide. Every step is a transaction of its own, so the
// history shows not only what a record says but the procedure that put
// it there and who took each part in it.

// ProposeRequest is a submission into a workflow.
type ProposeRequest struct {
	// ObjectID is the record the proposal is about. Required for every
	// action except create.
	ObjectID string `json:"object_id,omitempty"`
	// Payload is the proposed record body, or the workflow's declared
	// input for actions that do not carry a whole record.
	Payload map[string]any `json:"payload,omitempty"`
	// Evidence maps a declared evidence key to the SHA-256 digest of the
	// document presented. The register records the digest, never the
	// document.
	Evidence map[string]string `json:"evidence,omitempty"`
	// Message overrides the workflow's commit-message template.
	Message string `json:"message,omitempty"`
	// Body is the long-form part of the commit message.
	Body string `json:"body,omitempty"`
	// Refs are typed links to earlier work, e.g. corrects.
	Refs []model.Ref `json:"refs,omitempty"`
}

// Decision is a reviewer's answer to a proposal.
type Decision struct {
	Approve bool        `json:"approve"`
	Reason  string      `json:"reason,omitempty"`
	Message string      `json:"message,omitempty"`
	Body    string      `json:"body,omitempty"`
	Refs    []model.Ref `json:"refs,omitempty"`
}

// Outcome is what a workflow call produced.
type Outcome struct {
	Task        *model.Task        `json:"task"`
	Transaction *model.Transaction `json:"transaction"`
	// Applied is the transaction that committed the change, present when
	// the proposal was approved (by a reviewer or under policy).
	Applied *model.Transaction `json:"applied,omitempty"`
	// ObjectID is the record the outcome concerns.
	ObjectID string `json:"object_id,omitempty"`
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Propose starts a workflow. When the workflow permits automatic
// approval and every condition holds, the proposal is decided under
// policy in a second transaction rather than silently folded into the
// first: an automatic approval is still an approval, and the log says
// which one it was.
func (r *Register) Propose(p *auth.Principal, workflowName string, req ProposeRequest) (*Outcome, error) {
	wf := r.pk.Workflow(workflowName)
	if wf == nil {
		return nil, fmt.Errorf("no workflow named %q", workflowName)
	}
	if !p.CanOn(auth.PermPropose, workflowName) {
		return nil, fmt.Errorf("%s may not propose %s", p.Acting, workflowName)
	}
	if !containsString(wf.ProposeRoles, p.Acting) {
		return nil, fmt.Errorf("%s is not a proposing role for %s", p.Acting, workflowName)
	}
	class := r.pk.Class(wf.Class)

	if err := validateEvidence(wf, req.Evidence); err != nil {
		return nil, err
	}
	if wf.CompiledInput() != nil {
		if err := wf.CompiledInput().Validate(req.Payload); err != nil {
			return nil, fmt.Errorf("proposal does not match the workflow input: %w", err)
		}
	}
	if wf.Action == pack.ActionCreate {
		if req.ObjectID != "" {
			return nil, fmt.Errorf("%s creates a record and takes no object", workflowName)
		}
		if err := class.Compiled().Validate(req.Payload); err != nil {
			return nil, fmt.Errorf("proposed record does not match the %s schema: %w", class.Name, err)
		}
	} else if req.ObjectID == "" {
		return nil, fmt.Errorf("%s needs the record it is about", workflowName)
	}
	if wf.CompiledInput() == nil && (wf.Action == pack.ActionUpdate || wf.Action == pack.ActionCorrect) {
		// An amendment carries the whole record, not a patch: a register
		// says what a record is, so a proposal has to say what it will
		// be. Validating it here means a reviewer never sees a proposal
		// that could not have been committed.
		if err := class.Compiled().Validate(req.Payload); err != nil {
			return nil, fmt.Errorf("proposed record does not match the %s schema: %w", class.Name, err)
		}
	}

	var out *Outcome
	err := r.st.Do(func(tx *store.Tx) error {
		if req.ObjectID != "" {
			row, err := r.objectRow(tx, p.Tenant, req.ObjectID)
			if err != nil {
				return err
			}
			if row.Str("class") != class.Name {
				return fmt.Errorf("%s is a %s, not a %s", req.ObjectID, row.Str("class"), class.Name)
			}
		}

		taskID, err := NewTaskID()
		if err != nil {
			return err
		}
		at := r.now()
		ctx := r.templateContext(tx, p, taskID, req.ObjectID, req.Payload)
		blockers, reject, err := r.evaluateConditions(tx, wf, ctx)
		if err != nil {
			return err
		}
		if reject != "" {
			return fmt.Errorf("%s cannot be proposed: %s", workflowName, reject)
		}

		counterparty, state := "", model.TaskAwaitingReview
		if wf.Counterparty != nil {
			v, ok := req.Payload[wf.Counterparty.Field]
			if !ok || fmt.Sprint(v) == "" {
				return fmt.Errorf("%s needs %s, the party who must accept", workflowName, wf.Counterparty.Field)
			}
			counterparty = fmt.Sprint(v)
			state = model.TaskAwaitingCounterparty
		}

		w := newWriteCtx(p.Tenant, at)
		payloadJSON, keyOps, err := r.sealProposal(tx, w, r.proposalPII(wf, class), taskID, req.Payload)
		if err != nil {
			return err
		}
		evidenceJSON, err := canon.Marshal(req.Evidence)
		if err != nil {
			return err
		}
		summary := req.Message
		if summary == "" {
			summary = "Propose " + displayName(wf)
		}

		ops := append(keyOps, model.WriteOp{
			Table: "tasks",
			Key:   map[string]any{"id": taskID},
			Values: map[string]any{
				"tenant": p.Tenant, "workflow": wf.Name, "class": class.Name,
				"object_id": req.ObjectID, "state": state,
				"proposer_sub": p.Sub, "proposer_role": p.Acting,
				"counterparty": counterparty, "counterparty_state": "",
				"payload": model.Binary(payloadJSON), "evidence": model.Binary(evidenceJSON),
				"message": clip(summary, 255), "created_at": at, "updated_at": at,
				"decided_by": "", "decided_at": int64(0), "decision_reason": strings.Join(blockers, "; "),
				"txid": model.TxIDPlaceholder,
			},
		})
		env := model.Envelope{
			Kind: model.KindTaskPropose, Tenant: p.Tenant, Class: class.Name,
			Author: principalAuthor(p), Timestamp: at,
			Message: composeMessage(clip(summary, model.MaxSummary), req.Body),
			Refs:    append([]model.Ref{{Type: model.RefRelates, Target: taskID}}, req.Refs...),
		}
		if req.ObjectID != "" {
			env.ObjectIDs = []string{req.ObjectID}
		}
		proposal, err := r.commit(tx, env, ops)
		if err != nil {
			return err
		}

		task, err := r.taskByID(tx, taskID)
		if err != nil {
			return err
		}
		task.Blockers = blockers
		out = &Outcome{Task: task, Transaction: proposal, ObjectID: req.ObjectID}

		if state == model.TaskAwaitingReview && wf.AutoApprove && len(blockers) == 0 {
			applied, decided, err := r.decide(tx, policyPrincipal(p.Tenant), wf, task, Decision{
				Approve: true,
				Reason:  "approved under policy: every condition held",
			})
			if err != nil {
				return err
			}
			out.Applied = applied
			out.Task = decided
			out.ObjectID = decided.ObjectID
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Accept records the second party's answer on a two-party workflow.
// Only the named counterparty can give it, whatever roles they hold.
func (r *Register) Accept(p *auth.Principal, taskID string, accept bool, reason string) (*Outcome, error) {
	var out *Outcome
	err := r.st.Do(func(tx *store.Tx) error {
		task, err := r.taskByID(tx, taskID)
		if err != nil {
			return err
		}
		wf := r.pk.Workflow(task.Workflow)
		if wf == nil || wf.Counterparty == nil {
			return fmt.Errorf("%s is not a two-party workflow", task.Workflow)
		}
		if task.State != model.TaskAwaitingCounterparty {
			return fmt.Errorf("this proposal is %s and is not waiting for you", task.State)
		}
		if task.Counterparty != p.Sub {
			return fmt.Errorf("only %s can answer this proposal", task.Counterparty)
		}
		at := r.now()
		state, answer := model.TaskAwaitingReview, "accepted"
		if !accept {
			state, answer = model.TaskRejected, "declined"
		}
		ops := []model.WriteOp{{
			Table: "tasks",
			Key:   map[string]any{"id": task.ID},
			Values: map[string]any{
				"state": state, "counterparty_state": answer, "updated_at": at,
				"decision_reason": clip(reason, 255),
			},
		}}
		if !accept {
			closed, err := r.closeProposal(tx, task.Tenant, task.ID, at)
			if err != nil {
				return err
			}
			ops = append(ops, closed...)
		}
		kind := model.KindTaskAccept
		if !accept {
			kind = model.KindTaskReject
		}
		env := model.Envelope{
			Kind: kind, Tenant: task.Tenant, Class: task.Class,
			Author: principalAuthor(p), Timestamp: at,
			Message: composeMessage(fmt.Sprintf("Counterparty %s %s", answer, displayName(wf)), reason),
			Refs:    []model.Ref{{Type: model.RefRelates, Target: task.ID}},
		}
		if task.ObjectID != "" {
			env.ObjectIDs = []string{task.ObjectID}
		}
		txn, err := r.commit(tx, env, ops)
		if err != nil {
			return err
		}
		updated, err := r.taskByID(tx, task.ID)
		if err != nil {
			return err
		}
		out = &Outcome{Task: updated, Transaction: txn, ObjectID: task.ObjectID}

		if accept && wf.AutoApprove {
			ctx := r.templateContext(tx, p, task.ID, task.ObjectID, task.Payload)
			blockers, _, err := r.evaluateConditions(tx, wf, ctx)
			if err != nil {
				return err
			}
			if len(blockers) == 0 {
				applied, decided, err := r.decide(tx, policyPrincipal(task.Tenant), wf, updated, Decision{
					Approve: true,
					Reason:  "approved under policy: every condition held",
				})
				if err != nil {
					return err
				}
				out.Applied, out.Task, out.ObjectID = applied, decided, decided.ObjectID
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Decide approves or rejects a proposal under review.
func (r *Register) Decide(p *auth.Principal, taskID string, d Decision) (*Outcome, error) {
	var out *Outcome
	err := r.st.Do(func(tx *store.Tx) error {
		task, err := r.taskByID(tx, taskID)
		if err != nil {
			return err
		}
		wf := r.pk.Workflow(task.Workflow)
		if wf == nil {
			return fmt.Errorf("this register no longer declares workflow %q", task.Workflow)
		}
		if !p.CanOn(auth.PermApprove, wf.Name) || !containsString(wf.ApproveRoles, p.Acting) {
			return fmt.Errorf("%s may not decide %s", p.Acting, wf.Name)
		}
		if wf.Independence && task.ProposerSub == p.Sub {
			return fmt.Errorf("separation of duties: %s proposed this and may not also decide it", p.Sub)
		}
		if task.State != model.TaskAwaitingReview {
			return fmt.Errorf("this proposal is %s and is not awaiting a decision", task.State)
		}
		applied, decided, err := r.decide(tx, p, wf, task, d)
		if err != nil {
			return err
		}
		out = &Outcome{Task: decided, Transaction: applied, Applied: applied, ObjectID: decided.ObjectID}
		if !d.Approve {
			out.Applied = nil
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Withdraw lets a proposer take back their own proposal.
func (r *Register) Withdraw(p *auth.Principal, taskID, reason string) (*Outcome, error) {
	var out *Outcome
	err := r.st.Do(func(tx *store.Tx) error {
		task, err := r.taskByID(tx, taskID)
		if err != nil {
			return err
		}
		if task.ProposerSub != p.Sub {
			return fmt.Errorf("only the proposer can withdraw a proposal")
		}
		if task.State != model.TaskProposed && task.State != model.TaskAwaitingReview &&
			task.State != model.TaskAwaitingCounterparty {
			return fmt.Errorf("this proposal is %s and cannot be withdrawn", task.State)
		}
		at := r.now()
		ops := []model.WriteOp{
			{
				Table: "tasks",
				Key:   map[string]any{"id": task.ID},
				Values: map[string]any{
					"state": model.TaskWithdrawn, "updated_at": at,
					"decided_by": p.Sub, "decided_at": at, "decision_reason": clip(reason, 255),
				},
			},
		}
		closed, err := r.closeProposal(tx, task.Tenant, task.ID, at)
		if err != nil {
			return err
		}
		ops = append(ops, closed...)
		env := model.Envelope{
			Kind: model.KindTaskWithdraw, Tenant: task.Tenant, Class: task.Class,
			Author: principalAuthor(p), Timestamp: at,
			Message: composeMessage("Withdraw "+displayName(r.pk.Workflow(task.Workflow)), reason),
			Refs:    []model.Ref{{Type: model.RefRelates, Target: task.ID}},
		}
		txn, err := r.commit(tx, env, ops)
		if err != nil {
			return err
		}
		updated, err := r.taskByID(tx, task.ID)
		if err != nil {
			return err
		}
		out = &Outcome{Task: updated, Transaction: txn, ObjectID: task.ObjectID}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// decide is the shared body of a human decision and an automatic one.
func (r *Register) decide(tx *store.Tx, p *auth.Principal, wf *pack.Workflow, task *model.Task, d Decision) (*model.Transaction, *model.Task, error) {
	at := r.now()
	ctx := r.templateContext(tx, p, task.ID, task.ObjectID, task.Payload)

	if !d.Approve {
		ops := []model.WriteOp{
			{
				Table: "tasks",
				Key:   map[string]any{"id": task.ID},
				Values: map[string]any{
					"state": model.TaskRejected, "updated_at": at,
					"decided_by": p.Sub, "decided_at": at, "decision_reason": clip(d.Reason, 255),
				},
			},
		}
		closed, err := r.closeProposal(tx, task.Tenant, task.ID, at)
		if err != nil {
			return nil, nil, err
		}
		ops = append(ops, closed...)
		env := model.Envelope{
			Kind: model.KindTaskReject, Tenant: task.Tenant, Class: task.Class,
			Author: principalAuthor(p), Timestamp: at,
			Message: composeMessage(clip(orDefault(d.Message, "Reject "+displayName(wf)), model.MaxSummary), orDefault(d.Body, d.Reason)),
			Refs:    append([]model.Ref{{Type: model.RefRelates, Target: task.ID}}, d.Refs...),
		}
		if task.ObjectID != "" {
			env.ObjectIDs = []string{task.ObjectID}
		}
		txn, err := r.commit(tx, env, ops)
		if err != nil {
			return nil, nil, err
		}
		updated, err := r.taskByID(tx, task.ID)
		return txn, updated, err
	}

	blockers, reject, err := r.evaluateConditions(tx, wf, ctx)
	if err != nil {
		return nil, nil, err
	}
	if reject != "" {
		return nil, nil, fmt.Errorf("cannot approve: %s", reject)
	}
	if len(blockers) > 0 && p.Sub == policySub {
		return nil, nil, fmt.Errorf("cannot approve under policy: %s", strings.Join(blockers, "; "))
	}

	ops, objectID, err := r.effectOps(tx, newWriteCtx(p.Tenant, at), wf, task, ctx)
	if err != nil {
		return nil, nil, err
	}
	ctx.set("object.id", objectID)

	ops = append(ops,
		model.WriteOp{
			Table: "tasks",
			Key:   map[string]any{"id": task.ID},
			Values: map[string]any{
				"state": model.TaskApproved, "object_id": objectID, "updated_at": at,
				"decided_by": p.Sub, "decided_at": at, "decision_reason": clip(d.Reason, 255),
			},
		},
	)
	// The record now holds what the proposal proposed, sealed to the
	// subject. The proposal's own key has no further purpose, and leaving
	// it would leave personal data outside the reach of the erasure that
	// covers the record.
	closed, err := r.closeProposal(tx, task.Tenant, task.ID, at)
	if err != nil {
		return nil, nil, err
	}
	ops = append(ops, closed...)

	summary := d.Message
	if summary == "" {
		summary = render(wf.Message, ctx)
	}
	env := model.Envelope{
		Kind: model.KindTaskApprove, Tenant: task.Tenant, Class: task.Class,
		ObjectIDs: []string{objectID}, Author: principalAuthor(p), Timestamp: at,
		Message: composeMessage(clip(summary, model.MaxSummary), orDefault(d.Body, d.Reason)),
		Refs: append([]model.Ref{
			{Type: model.RefApproves, Target: task.ID},
		}, d.Refs...),
	}
	if wf.Action == pack.ActionCorrect && task.ObjectID != "" {
		env.Kind = model.KindRecordCorrect
		env.Refs = append(env.Refs, model.Ref{Type: model.RefCorrects, Target: task.ObjectID})
	}
	txn, err := r.commit(tx, env, ops)
	if err != nil {
		return nil, nil, err
	}
	updated, err := r.taskByID(tx, task.ID)
	return txn, updated, err
}

// effectOps turns a workflow's declared effects into a write set.
func (r *Register) effectOps(tx *store.Tx, w *writeCtx, wf *pack.Workflow, task *model.Task, ctx *tmplContext) ([]model.WriteOp, string, error) {
	effects := wf.Effects
	if len(effects) == 0 {
		effects = []pack.Effect{{Type: pack.EffectRecord}}
	}
	class := r.pk.Class(wf.Class)
	objectID := task.ObjectID
	var ops []model.WriteOp

	for i, e := range effects {
		var (
			next []model.WriteOp
			err  error
		)
		switch e.Type {
		case pack.EffectRecord:
			switch wf.Action {
			case pack.ActionCreate:
				objectID, next, err = r.createOps(tx, w, class, task.Payload, "")
				ctx.set("object.id", objectID)
			case pack.ActionUpdate, pack.ActionCorrect:
				next, err = r.updateOps(tx, w, class, objectID, task.Payload, "")
			case pack.ActionStatus:
				next, err = r.statusOps(tx, w, class, objectID, wf.Status)
			}
		case pack.EffectSetStatus:
			target := objectID
			if e.Target != "" {
				target = render(e.Target, ctx)
			}
			targetClass := class
			if e.Class != "" {
				targetClass = r.pk.Class(e.Class)
			}
			if target == "" {
				if e.Optional {
					continue
				}
				err = fmt.Errorf("no target record")
			} else {
				next, err = r.statusOps(tx, w, targetClass, target, e.Status)
			}
		case pack.EffectCreate, pack.EffectOpenLink:
			target := r.pk.Class(e.Class)
			payload := renderMap(e.Payload, ctx)
			var created string
			created, next, err = r.createOps(tx, w, target, payload, e.Status)
			if err == nil {
				ctx.set("created."+e.Class+".id", created)
				if e.Type == pack.EffectCreate && objectID == "" {
					objectID = created
				}
			}
		case pack.EffectCloseLink:
			next, err = r.closeLinkOps(tx, w, e, ctx)
		default:
			err = fmt.Errorf("unknown effect %q", e.Type)
		}
		if err != nil {
			return nil, "", fmt.Errorf("%s effect %d (%s): %w", wf.Name, i, e.Type, err)
		}
		ops = append(ops, next...)
	}
	if objectID == "" {
		return nil, "", fmt.Errorf("%s produced no record", wf.Name)
	}
	return ops, objectID, nil
}

// closeLinkOps finds the open link record a transfer supersedes and
// writes the field that closes it. Ownership history is the ledger's
// history: a transfer never edits the previous owner away, it ends one
// link and opens another.
func (r *Register) closeLinkOps(tx *store.Tx, w *writeCtx, e pack.Effect, ctx *tmplContext) ([]model.WriteOp, error) {
	class := r.pk.Class(e.Class)
	clauses := []string{"tenant = " + store.Lit(w.tenant)}
	for _, col := range sortedKeys(e.Match) {
		clauses = append(clauses, store.Ident(col)+" = "+store.Lit(renderValue(e.Match[col], ctx)))
	}
	row, err := tx.QueryOne("SELECT object_id FROM " + store.Ident(class.QueryTable()) +
		" WHERE " + strings.Join(clauses, " AND ") + " LIMIT 1")
	if err != nil {
		return nil, err
	}
	if row == nil {
		if e.Optional {
			return nil, nil
		}
		return nil, fmt.Errorf("no open %s to close", class.Name)
	}
	target := row.Str("object_id")
	current, err := r.headVersion(tx, class, target)
	if err != nil {
		return nil, err
	}
	payload := map[string]any{}
	for k, v := range current.Payload {
		payload[k] = v
	}
	for _, k := range sortedKeys(e.Set) {
		payload[k] = renderValue(e.Set[k], ctx)
	}
	return r.updateOps(tx, w, class, target, payload, e.Status)
}

// -- conditions ------------------------------------------------------------

// evaluateConditions runs a workflow's predicates against the
// register's own SQL. They are checked when a proposal is made and
// again when it is decided: the state a decision is taken in is the
// state the decision applies to, not the state it was proposed in.
func (r *Register) evaluateConditions(tx *store.Tx, wf *pack.Workflow, ctx *tmplContext) (blockers []string, reject string, err error) {
	for _, cond := range wf.Conditions {
		value, err := tx.Count(renderSQL(cond.SQL, ctx))
		if err != nil {
			return nil, "", fmt.Errorf("condition %s: %w", cond.ID, err)
		}
		ok := (cond.Expect == pack.ExpectZero && value == 0) ||
			(cond.Expect == pack.ExpectNonZero && value != 0)
		if ok {
			continue
		}
		message := cond.Message
		if message == "" {
			message = cond.Description
		}
		if message == "" {
			message = "condition " + cond.ID + " does not hold"
		}
		if cond.OnFail == pack.OnFailReject {
			return blockers, message, nil
		}
		blockers = append(blockers, message)
	}
	return blockers, "", nil
}

// -- templates -------------------------------------------------------------

type tmplContext struct{ values map[string]any }

func (c *tmplContext) set(key string, v any) { c.values[key] = v }

func (c *tmplContext) lookup(key string) (any, bool) {
	v, ok := c.values[key]
	return v, ok
}

func (r *Register) templateContext(tx *store.Tx, p *auth.Principal, taskID, objectID string, payload map[string]any) *tmplContext {
	now := r.opts.Now().UTC()
	ctx := &tmplContext{values: map[string]any{
		"task.id":       taskID,
		"object.id":     objectID,
		"actor.sub":     p.Sub,
		"actor.display": p.Display,
		"actor.role":    p.Acting,
		"tenant":        p.Tenant,
		"today":         now.Format("2006-01-02"),
		"now":           now.Format(time.RFC3339),
	}}
	for k, v := range payload {
		ctx.values["payload."+k] = v
	}
	if objectID != "" {
		if row, err := tx.QueryOne("SELECT natural_key, class, status FROM `objects` WHERE id = " + store.Lit(objectID)); err == nil && row != nil {
			ctx.values["object.natural_key"] = row.Str("natural_key")
			ctx.values["object.class"] = row.Str("class")
			ctx.values["object.status"] = row.Str("status")
		}
	}
	return ctx
}

var placeholderRe = regexp.MustCompile(`\{\{([a-zA-Z0-9_.]+)\}\}`)

// render substitutes placeholders into text.
func render(tmpl string, ctx *tmplContext) string {
	return placeholderRe.ReplaceAllStringFunc(tmpl, func(match string) string {
		key := match[2 : len(match)-2]
		if v, ok := ctx.lookup(key); ok {
			return fmt.Sprint(v)
		}
		return ""
	})
}

// renderSQL substitutes placeholders as SQL literals, so a condition
// can refer to the proposal without a value in the proposal being able
// to change the statement's shape.
func renderSQL(tmpl string, ctx *tmplContext) string {
	return placeholderRe.ReplaceAllStringFunc(tmpl, func(match string) string {
		key := match[2 : len(match)-2]
		v, ok := ctx.lookup(key)
		if !ok {
			return "NULL"
		}
		return store.Lit(sqlValue(v))
	})
}

func sqlValue(v any) any {
	switch t := v.(type) {
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return i
		}
		f, _ := t.Float64()
		return f
	case nil:
		return nil
	case string, bool, int64, float64:
		return t
	default:
		return fmt.Sprint(t)
	}
}

// renderValue keeps a value's native type when the template is exactly
// one placeholder, and renders text otherwise.
func renderValue(v any, ctx *tmplContext) any {
	s, ok := v.(string)
	if !ok {
		return v
	}
	if m := placeholderRe.FindStringSubmatch(s); m != nil && m[0] == s {
		if resolved, ok := ctx.lookup(m[1]); ok {
			return resolved
		}
		return ""
	}
	return render(s, ctx)
}

func renderMap(in map[string]any, ctx *tmplContext) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = renderValue(v, ctx)
	}
	return out
}

// -- helpers ---------------------------------------------------------------

const policySub = "policy"

// policyPrincipal is the actor an automatic approval is recorded under.
// It is not a person and does not pretend to be one.
func policyPrincipal(tenant string) *auth.Principal {
	return &auth.Principal{
		Sub: policySub, Display: "Automatic approval under policy",
		Tenant: tenant, Roles: []string{"policy"}, Acting: "policy", PII: true,
	}
}

func validateEvidence(wf *pack.Workflow, evidence map[string]string) error {
	declared := map[string]bool{}
	for _, e := range wf.Evidence {
		declared[e.Key] = true
		if e.Required {
			digest, ok := evidence[e.Key]
			if !ok || digest == "" {
				return fmt.Errorf("%s requires %s", wf.Name, orDefault(e.Title, e.Key))
			}
		}
	}
	for key, digest := range evidence {
		if !declared[key] {
			return fmt.Errorf("%s does not ask for %s", wf.Name, key)
		}
		if !sha256Hex.MatchString(digest) {
			return fmt.Errorf("evidence %s must be a SHA-256 digest in lower-case hex", key)
		}
	}
	return nil
}

// taskByID reads a proposal with its personal data opened for the
// register itself, which needs the whole payload to commit it.
func (r *Register) taskByID(tx *store.Tx, id string) (*model.Task, error) {
	return r.taskByIDAs(tx, nil, id)
}

// taskByIDAs reads a proposal as a particular caller sees it.
func (r *Register) taskByIDAs(tx *store.Tx, p *auth.Principal, id string) (*model.Task, error) {
	row, err := tx.QueryOne("SELECT * FROM `tasks` WHERE id = " + store.Lit(id))
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, fmt.Errorf("no proposal %s", id)
	}
	task, err := decodeTask(row)
	if err != nil {
		return nil, err
	}
	if err := r.openProposal(tx, p, task, row.Bytes("payload")); err != nil {
		return nil, err
	}
	return task, nil
}

func decodeTask(row store.Row) (*model.Task, error) {
	t := &model.Task{
		ID: row.Str("id"), Tenant: row.Str("tenant"), Workflow: row.Str("workflow"),
		Class: row.Str("class"), ObjectID: row.Str("object_id"), State: row.Str("state"),
		ProposerSub: row.Str("proposer_sub"), ProposerRole: row.Str("proposer_role"),
		Counterparty: row.Str("counterparty"), CounterpartyState: row.Str("counterparty_state"),
		Message: row.Str("message"), CreatedAt: row.Int("created_at"), UpdatedAt: row.Int("updated_at"),
		DecidedBy: row.Str("decided_by"), DecidedAt: row.Int("decided_at"),
		DecisionReason: row.Str("decision_reason"), TxID: row.Str("txid"),
	}
	if raw := row.Bytes("evidence"); len(raw) > 0 {
		if err := json.Unmarshal(raw, &t.Evidence); err != nil {
			return nil, fmt.Errorf("register: proposal %s: evidence: %w", t.ID, err)
		}
	}
	return t, nil
}

func displayName(wf *pack.Workflow) string {
	if wf == nil {
		return "proposal"
	}
	if wf.Title != "" {
		return strings.ToLower(wf.Title)
	}
	return strings.ReplaceAll(wf.Name, "_", " ")
}

func composeMessage(summary, body string) string {
	summary = strings.TrimSpace(summary)
	body = strings.TrimSpace(body)
	if body == "" {
		return summary
	}
	return summary + "\n\n" + body
}

func orDefault(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
