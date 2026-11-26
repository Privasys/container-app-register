// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/pack"
	"github.com/Privasys/container-app-register/internal/store"
)

// Appointments: a role held because a record names the person to it.
//
// A pack makes a class's records appointments. A person is bound to one
// such record by accepting an invitation to it, and holds the role the
// record gives while the record is current. The binding is a transaction
// like any grant; the end of the appointment is not: when the record
// leaves its initial status or its end property is set, the role lapses
// at once, because the register reads the record each time it asks what
// the person holds.

// AppointmentHolding is one appointment a person holds.
type AppointmentHolding struct {
	Sub   string `json:"sub,omitempty"`
	Class string `json:"class"`
	// Key is the appointment record's natural key.
	Key  string `json:"key"`
	Role string `json:"role"`
	// Keys are the values of the properties the pack names as the
	// appointment's keys: what a scope compares against.
	Keys      map[string]string `json:"keys"`
	GrantedBy string            `json:"granted_by"`
	Since     int64             `json:"since"`
	TxID      string            `json:"txid,omitempty"`
	// Named says the record itself names the holder: amending it is how the
	// holding ends early, not unbinding.
	Named bool `json:"named,omitempty"`
}

// AppointmentRef names an appointment record.
type AppointmentRef struct {
	Class string `json:"class"`
	Key   string `json:"key"`
	// Named says the record itself names its holder.
	Named bool `json:"named,omitempty"`
}

func emptyValue(v any) bool {
	return v == nil || v == ""
}

// currentAppointment reads an appointment record and returns the role it
// gives and its payload, or "" when the record is missing, erased, ended
// or pruned.
func (r *Register) currentAppointment(tx *store.Tx, tenant string, a *pack.Appointment, key string) (string, map[string]any, error) {
	class := r.pk.Class(a.Class)
	row, err := tx.QueryOne("SELECT id, status, erased FROM `objects` WHERE tenant = " + store.Lit(tenant) +
		" AND class = " + store.Lit(class.Name) + " AND natural_key = " + store.Lit(key))
	if err != nil || row == nil {
		return "", nil, err
	}
	if row.Bool("erased") || row.Str("status") != class.Initial {
		return "", nil, nil
	}
	head, err := r.headVersion(tx, class, row.Str("id"))
	var pruned *PruneError
	if errors.As(err, &pruned) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	if a.EndedBy != "" && !emptyValue(unwrap(head.Payload[a.EndedBy])) {
		return "", nil, nil
	}
	return a.RoleFor(head.Payload, unwrap), head.Payload, nil
}

// holdings lists the current appointments held, by one person when sub is
// given and by everyone otherwise. A binding whose record has ended, or
// whose record now gives another role, is not listed: it gives nothing.
func (r *Register) holdings(tx *store.Tx, tenant, sub string) ([]AppointmentHolding, error) {
	if len(r.pk.Appointments) == 0 {
		return nil, nil
	}
	q := "SELECT * FROM `appointment_holders` WHERE tenant = " + store.Lit(tenant)
	if sub != "" {
		q += " AND sub = " + store.Lit(sub)
	}
	rows, err := tx.Query(q)
	if err != nil {
		return nil, err
	}
	out := make([]AppointmentHolding, 0, len(rows))
	for _, row := range rows {
		a := r.pk.AppointmentOf(row.Str("class"))
		if a == nil {
			continue
		}
		role, payload, err := r.currentAppointment(tx, tenant, a, row.Str("natural_key"))
		if err != nil {
			return nil, err
		}
		if role == "" || role != row.Str("role") {
			continue
		}
		h := AppointmentHolding{
			Sub: row.Str("sub"), Class: a.Class, Key: row.Str("natural_key"), Role: role,
			Keys: map[string]string{}, GrantedBy: row.Str("granted_by"), Since: row.Int("since"), TxID: row.Str("txid"),
		}
		for _, k := range a.Keys {
			if v := unwrap(payload[k]); !emptyValue(v) {
				h.Keys[k] = fmt.Sprint(v)
			}
		}
		if a.HolderProperty != "" {
			if h.Named, err = r.namedHolding(tx, tenant, a.Class, h.Key); err != nil {
				return nil, err
			}
		}
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Sub != out[j].Sub {
			return out[i].Sub < out[j].Sub
		}
		if out[i].Class != out[j].Class {
			return out[i].Class < out[j].Class
		}
		return out[i].Key < out[j].Key
	})
	return out, nil
}

// Appointments lists the current appointments a person holds.
func (r *Register) Appointments(tenant, sub string) ([]AppointmentHolding, error) {
	var out []AppointmentHolding
	err := r.st.Do(func(tx *store.Tx) error {
		var err error
		out, err = r.holdings(tx, tenant, sub)
		return err
	})
	for i := range out {
		out[i].Sub = ""
	}
	return out, err
}

// scopeKeys are the keys a scope compares a record against for the
// caller: the keys of their current appointments for the acting role when
// that role is held by appointment, and their organisations' otherwise.
func (r *Register) scopeKeys(tx *store.Tx, p *auth.Principal) ([]string, error) {
	spec := r.pk.Model().Role(p.Acting)
	if spec == nil || spec.Held != HeldByAppointment {
		return r.organisationsOf(tx, p)
	}
	held, err := r.holdings(tx, p.Tenant, p.Sub)
	if err != nil {
		return nil, err
	}
	var keys []string
	for _, h := range held {
		if h.Role != p.Acting {
			continue
		}
		for _, v := range h.Keys {
			if !slices.Contains(keys, v) {
				keys = append(keys, v)
			}
		}
	}
	sort.Strings(keys)
	return keys, nil
}

type inviteAppointment struct {
	class, key string
}

// appointmentFor decides which appointment class an invitation to role
// binds to. A pack's invitation rule names it for the inviter's role;
// whoever manages members may invite to any class that gives the role,
// naming it when several do. through says whether a rule allowed it.
func (r *Register) appointmentFor(p *auth.Principal, role, className string) (a *pack.Appointment, through bool, err error) {
	if rule := r.pk.InvitationRule(p.Acting, role); rule != nil && (className == "" || className == rule.Class) {
		if a := r.pk.AppointmentOf(rule.Class); a != nil {
			return a, true, nil
		}
	}
	if !p.Can(auth.PermMembers) {
		return nil, false, fmt.Errorf("%s may not invite anyone to an appointment as %s", p.Acting, role)
	}
	var candidates []*pack.Appointment
	for _, a := range r.pk.AppointmentsGiving(role) {
		if className == "" || a.Class == className {
			candidates = append(candidates, a)
		}
	}
	switch len(candidates) {
	case 0:
		return nil, false, fmt.Errorf("no appointment in this register gives the role %q", role)
	case 1:
		return candidates[0], false, nil
	}
	return nil, false, fmt.Errorf("several kinds of appointment give the role %q: name the class", role)
}

// inviteToAppointment issues an invitation that binds its person to one
// appointment record.
func (r *Register) inviteToAppointment(tx *store.Tx, p *auth.Principal, req InviteRequest) (*Invite, string, error) {
	if req.Organisation != "" {
		return nil, "", fmt.Errorf("an invitation to an appointment brings no organisation")
	}
	if req.Role == "" {
		return nil, "", fmt.Errorf("an invitation to an appointment names the role it gives")
	}
	a, through, err := r.appointmentFor(p, req.Role, req.AppointmentClass)
	if err != nil {
		return nil, "", err
	}
	class := r.pk.Class(a.Class)
	row, err := tx.QueryOne("SELECT id FROM `objects` WHERE tenant = " + store.Lit(p.Tenant) +
		" AND class = " + store.Lit(class.Name) + " AND natural_key = " + store.Lit(req.Appointment))
	if err != nil {
		return nil, "", err
	}
	label := strings.ReplaceAll(class.Name, "_", " ")
	if row == nil {
		return nil, "", fmt.Errorf("no such %s %q", label, req.Appointment)
	}
	if through {
		if err := r.checkScope(tx, p, class, row.Str("id")); err != nil {
			return nil, "", fmt.Errorf("%s may not invite anyone to %s %s: it is not within their scope", p.Acting, label, req.Appointment)
		}
	}
	if err := r.appointmentOpen(tx, p.Tenant, a, req.Appointment, req.Role); err != nil {
		return nil, "", err
	}
	return r.createInvite(tx, principalAuthor(p), p.Tenant, req.Role, req.Label, req.ValidFor, req.To, nil,
		&inviteAppointment{class: a.Class, key: req.Appointment})
}

// appointmentOpen refuses an appointment that has ended, that gives
// another role, or that someone already holds.
func (r *Register) appointmentOpen(tx *store.Tx, tenant string, a *pack.Appointment, key, role string) error {
	label := strings.ReplaceAll(a.Class, "_", " ")
	gives, _, err := r.currentAppointment(tx, tenant, a, key)
	if err != nil {
		return err
	}
	if gives == "" {
		return fmt.Errorf("%s %s is not current: it has ended, or gives no role", label, key)
	}
	if gives != role {
		return fmt.Errorf("%s %s gives the role %s, not %s", label, key, gives, role)
	}
	held, err := tx.QueryOne("SELECT sub FROM `appointment_holders` WHERE tenant = " + store.Lit(tenant) +
		" AND class = " + store.Lit(a.Class) + " AND natural_key = " + store.Lit(key))
	if err != nil {
		return err
	}
	if held != nil {
		return fmt.Errorf("%s %s is already held by someone", label, key)
	}
	return nil
}

func (r *Register) inviteAppointmentOf(tx *store.Tx, inv *Invite) error {
	row, err := tx.QueryOne("SELECT class, natural_key FROM `invite_appointments` WHERE id = " + store.Lit(inv.ID))
	if err != nil || row == nil {
		return err
	}
	inv.AppointmentClass, inv.Appointment = row.Str("class"), row.Str("natural_key")
	return nil
}

// bindAppointment is the acceptance of an invitation to an appointment:
// the person is bound to the record, in the commit that spends the
// invitation.
func (r *Register) bindAppointment(tx *store.Tx, tenant, sub string, inv *Invite, ops []model.WriteOp, at int64) (*model.Transaction, error) {
	a := r.pk.AppointmentOf(inv.AppointmentClass)
	if a == nil {
		return nil, fmt.Errorf("this register no longer gives roles by %s", strings.ReplaceAll(inv.AppointmentClass, "_", " "))
	}
	if err := r.appointmentOpen(tx, tenant, a, inv.Appointment, inv.Role); err != nil {
		return nil, err
	}
	held, err := r.rolesOf(tx, tenant, sub)
	if err != nil {
		return nil, err
	}
	if err := r.checkCompatible(sub, append(held, inv.Role)); err != nil {
		return nil, err
	}
	label := strings.ReplaceAll(a.Class, "_", " ")
	ops = append(ops, model.WriteOp{
		Table: "appointment_holders",
		Key:   map[string]any{"tenant": tenant, "class": a.Class, "natural_key": inv.Appointment},
		Values: map[string]any{
			"sub": sub, "role": inv.Role, "granted_by": inv.CreatedBy, "since": at, "txid": model.TxIDPlaceholder,
		},
	})
	return r.commit(tx, model.Envelope{
		Kind: model.KindInviteRedeem, Tenant: tenant, Author: model.Author{Sub: sub, Role: "invitee"}, Timestamp: at,
		Message: composeMessage(
			clip(fmt.Sprintf("%s takes %s %s as %s", clip(sub, 16), label, inv.Appointment, inv.Role), model.MaxSummary),
			fmt.Sprintf("%s holds the role %q while %s %s is current.\nInvitation %s, issued by %s.",
				sub, inv.Role, label, inv.Appointment, inv.ID, inv.CreatedBy)),
	}, ops)
}

// EndAppointmentHolding unbinds whoever holds an appointment, before the
// record itself ends. Whoever manages members may, and says why.
func (r *Register) EndAppointmentHolding(p *auth.Principal, class, key, reason string) (*model.Transaction, error) {
	if !p.Can(auth.PermMembers) {
		return nil, fmt.Errorf("%s may not manage members", p.Acting)
	}
	if strings.TrimSpace(reason) == "" {
		return nil, fmt.Errorf("say why the appointment is no longer held")
	}
	var txn *model.Transaction
	err := r.st.Do(func(tx *store.Tx) error {
		row, err := tx.QueryOne("SELECT sub, role FROM `appointment_holders` WHERE tenant = " + store.Lit(p.Tenant) +
			" AND class = " + store.Lit(class) + " AND natural_key = " + store.Lit(key))
		if err != nil {
			return err
		}
		label := strings.ReplaceAll(class, "_", " ")
		if row == nil {
			return fmt.Errorf("nobody holds %s %s", label, key)
		}
		if named, err := r.namedHolding(tx, p.Tenant, class, key); err != nil {
			return err
		} else if named {
			prop := ""
			if a := r.pk.AppointmentOf(class); a != nil {
				prop = " " + a.HolderProperty
			}
			return fmt.Errorf("%s %s names its holder itself: amend the record's%s to end the holding", label, key, prop)
		}
		if r.pk.StepUpRevoke(row.Str("role")) {
			if err := r.stepUp(tx, p, "end_holding", map[string]any{"class": class, "key": key, "reason": reason},
				"End "+r.personName(tx, row.Str("sub"))+"'s holding of "+label+" "+key, auth.ApprovalLine{Label: "Reason", Value: reason}); err != nil {
				return err
			}
		}
		at := r.now()
		txn, err = r.commit(tx, model.Envelope{
			Kind: model.KindMemberRevoke, Tenant: p.Tenant, Author: principalAuthor(p), Timestamp: at,
			Message: composeMessage(
				clip(fmt.Sprintf("Unbind %s from %s %s", clip(row.Str("sub"), 16), label, key), model.MaxSummary),
				strings.TrimSpace(fmt.Sprintf("%s no longer holds the role %q through %s %s.\n%s",
					row.Str("sub"), row.Str("role"), label, key, reason))),
		}, []model.WriteOp{{
			Table: "appointment_holders", Key: map[string]any{"tenant": p.Tenant, "class": class, "natural_key": key}, Delete: true,
		}})
		return err
	})
	return txn, err
}
