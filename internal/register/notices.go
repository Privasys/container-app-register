// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register

import (
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/pack"
	"github.com/Privasys/container-app-register/internal/store"
)

// Notices: who a workflow event is written to.
//
// The pack's notifications name the events and the recipients. The
// register resolves the recipients once the event's transaction has
// committed, from what is true at that moment, and hands each notice to a
// sink, which sends it. Sending never touches the transaction: a mail
// that fails is the sink's to retry, and the record stands either way.

// Notice is one notification of one event, with its resolved recipients.
type Notice struct {
	Template      string
	Workflow      string
	WorkflowTitle string
	Event         string
	TaskID        string
	TxID          string
	// At is when the event was committed, in Unix seconds.
	At         int64
	Class      string
	ClassTitle string
	ObjectID   string
	// Key is the record's natural key, or the one the proposal names.
	Key string
	// Reason is the reviewer's reason, on a rejection or a return.
	Reason string
	// Public holds the record's public fields, for a class that has any.
	Public     map[string]any
	Recipients []NoticeRecipient
}

// NoticeRecipient is one person a notice is written to.
type NoticeRecipient struct {
	Sub   string
	Name  string
	Email string
}

// NoticeSink sends notices. Deliver must not block on sending.
type NoticeSink interface {
	Deliver(n Notice)
}

// SetNoticeSink attaches whatever sends notices; without one, events are
// not resolved at all.
func (r *Register) SetNoticeSink(s NoticeSink) { r.notices = s }

// emit resolves and hands on the notices that follow a workflow event.
// It runs after the event's transaction has committed.
func (r *Register) emit(task *model.Task, event string, txn *model.Transaction, reason string) {
	if r.notices == nil || task == nil {
		return
	}
	rules := r.pk.NotificationsOn(task.Workflow, event)
	if len(rules) == 0 {
		return
	}
	var notices []Notice
	err := r.st.Do(func(tx *store.Tx) error {
		for _, n := range rules {
			notice, err := r.resolveNotice(tx, n, task, event, txn, reason)
			if err != nil {
				return err
			}
			if len(notice.Recipients) > 0 {
				notices = append(notices, notice)
			}
		}
		return nil
	})
	if err != nil {
		slog.Warn("notifications: recipients not resolved", "workflow", task.Workflow, "event", event, "task", task.ID, "error", err)
		return
	}
	for _, n := range notices {
		r.notices.Deliver(n)
	}
}

func (r *Register) resolveNotice(tx *store.Tx, n *pack.Notification, task *model.Task, event string,
	txn *model.Transaction, reason string) (Notice, error) {
	wf := r.pk.Workflow(task.Workflow)
	class := r.pk.Class(task.Class)
	out := Notice{
		Template: n.Template, Workflow: task.Workflow, Event: event, TaskID: task.ID,
		Class: task.Class, ObjectID: task.ObjectID, Reason: reason,
	}
	if wf != nil {
		out.WorkflowTitle = orDefault(wf.Title, wf.Name)
	}
	if txn != nil {
		out.TxID = txn.TxID
		out.At = txn.Envelope.Timestamp
	}
	if class == nil {
		return out, nil
	}
	out.ClassTitle = orDefault(class.Title, class.Name)

	// The record as it stands now, or, before a proposal has made one, the
	// record it proposes.
	payload := task.Payload
	if task.ObjectID != "" {
		row, err := r.objectRow(tx, task.Tenant, task.ObjectID)
		if err != nil {
			return out, err
		}
		out.Key = row.Str("natural_key")
		head, err := r.headVersion(tx, class, task.ObjectID)
		if err == nil {
			payload = head.Payload
			if PublicClass(class) {
				out.Public = publicFields(class.Compiled(), payload)
			}
		}
	}
	if out.Key == "" && class.NaturalKey != "" && payload != nil {
		if v := unwrap(payload[class.NaturalKey]); !emptyValue(v) {
			out.Key = fmt.Sprint(v)
		}
	}

	subs := []string{}
	add := func(sub string) {
		if sub != "" && !strings.HasPrefix(sub, "system:") && !slices.Contains(subs, sub) {
			subs = append(subs, sub)
		}
	}
	for _, rule := range n.To {
		switch {
		case rule.Proposer:
			add(task.ProposerSub)
		case rule.ProposerOrganisation:
			affs, err := r.affiliationsIn(tx, task.Tenant, task.ProposerSub)
			if err != nil {
				return out, err
			}
			for _, a := range affs {
				members, err := r.affiliatesIn(tx, task.Tenant, a.Organisation)
				if err != nil {
					return out, err
				}
				for _, m := range members {
					add(m.Sub)
				}
			}
		case rule.Role != "":
			holders, err := r.holdersOf(tx, task.Tenant, rule.Role)
			if err != nil {
				return out, err
			}
			for _, sub := range holders {
				ok, err := r.roleAdmits(tx, task.Tenant, sub, rule.Role, class, payload)
				if err != nil {
					return out, err
				}
				if ok {
					add(sub)
				}
			}
		}
	}
	sort.Strings(subs)
	for _, sub := range subs {
		profile, err := r.profileIn(tx, sub)
		if err != nil {
			return out, err
		}
		if profile.Email == "" || profile.Erased {
			continue
		}
		out.Recipients = append(out.Recipients, NoticeRecipient{Sub: sub, Name: profile.Name, Email: profile.Email})
	}
	return out, nil
}

// holdersOf lists everyone the register itself gives a role: granted to
// them, inherited from an organisation, or by a current appointment.
// Roles an identity provider asserts at sign-in are not known here.
func (r *Register) holdersOf(tx *store.Tx, tenant, role string) ([]string, error) {
	var out []string
	add := func(sub string) {
		if !slices.Contains(out, sub) {
			out = append(out, sub)
		}
	}
	rows, err := tx.Query("SELECT sub FROM `members` WHERE tenant = " + store.Lit(tenant) + " AND role = " + store.Lit(role))
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		add(row.Str("sub"))
	}
	orgs, err := tx.Query("SELECT organisation FROM `organisation_roles` WHERE tenant = " + store.Lit(tenant) + " AND role = " + store.Lit(role))
	if err != nil {
		return nil, err
	}
	for _, row := range orgs {
		members, err := r.affiliatesIn(tx, tenant, row.Str("organisation"))
		if err != nil {
			return nil, err
		}
		for _, m := range members {
			add(m.Sub)
		}
	}
	held, err := r.holdings(tx, tenant, "")
	if err != nil {
		return nil, err
	}
	for _, h := range held {
		if h.Role == role {
			add(h.Sub)
		}
	}
	sort.Strings(out)
	return out, nil
}

// roleAdmits says whether a person, acting under a role, has the record
// within their scope.
func (r *Register) roleAdmits(tx *store.Tx, tenant, sub, role string, class *pack.Class, payload map[string]any) (bool, error) {
	held, err := r.rolesOf(tx, tenant, sub)
	if err != nil {
		return false, err
	}
	p, err := r.pk.Model().Resolve(&auth.Identity{Sub: sub, Granted: held}, tenant, role)
	if err != nil {
		// Roles the person may not act under together reach nobody.
		return false, nil
	}
	if payload == nil {
		return len(r.pk.ScopesFor(class.Name, role)) == 0, nil
	}
	return r.inScope(tx, p, class, payload)
}

// RecordNotified writes, in the history, that a notice reached sent
// people. Their addresses are not part of the record.
func (r *Register) RecordNotified(n Notice, sent int) (*model.Transaction, error) {
	if sent == 0 {
		return nil, nil
	}
	var txn *model.Transaction
	err := r.st.Do(func(tx *store.Tx) error {
		people := "people"
		if sent == 1 {
			people = "person"
		}
		subject := strings.TrimSpace(n.ClassTitle + " " + n.Key)
		env := model.Envelope{
			Kind: model.KindNotificationSent, Tenant: r.opts.Tenant, Class: n.Class,
			Author: r.systemAuthor("notifications"), Timestamp: r.now(),
			Message: composeMessage(
				clip(fmt.Sprintf("Notified %d %s: %s %s, %s", sent, people, orDefault(n.WorkflowTitle, n.Workflow), n.Event, subject), model.MaxSummary),
				fmt.Sprintf("Template %s, after transaction %s.", n.Template, n.TxID)),
			Refs: []model.Ref{{Type: model.RefRelates, Target: n.TaskID}},
		}
		if n.ObjectID != "" {
			env.ObjectIDs = []string{n.ObjectID}
		}
		var err error
		txn, err = r.commit(tx, env, nil)
		return err
	})
	return txn, err
}
