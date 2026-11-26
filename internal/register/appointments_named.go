// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register

import (
	"fmt"
	"strings"

	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/store"
)

// A record can name its holder. When the pack gives an appointment class a
// holder property, the subject a record writes there holds the record's
// role, bound in the commit that writes the record, with no invitation to
// accept. Clearing the property, or naming someone else, unbinds them in
// the same way. The binding is the same row an accepted invitation writes,
// so the role lapses with the record, scopes read the record's keys, and
// one person holds each record; appointment_named marks the rows the record
// itself put there.

// namedHolderOps keeps the binding of a record's named holder in step with
// the version being written.
func (r *Register) namedHolderOps(tx *store.Tx, w *writeCtx, d recordDraft, naturalKey, previousKey string) ([]model.WriteOp, error) {
	a := r.pk.AppointmentOf(d.class.Name)
	if a == nil || a.HolderProperty == "" {
		return nil, nil
	}
	label := strings.ReplaceAll(a.Class, "_", " ")
	var ops []model.WriteOp
	unbind := func(key string) {
		for _, table := range []string{"appointment_holders", "appointment_named"} {
			ops = append(ops, model.WriteOp{
				Table: table, Key: map[string]any{"tenant": w.tenant, "class": a.Class, "natural_key": key}, Delete: true,
			})
		}
	}
	// A correction to the natural key moves the binding with the record.
	if previousKey != "" && previousKey != naturalKey {
		if named, err := r.namedHolding(tx, w.tenant, a.Class, previousKey); err != nil {
			return nil, err
		} else if named {
			unbind(previousKey)
		}
	}

	sub, _ := unwrap(d.payload[a.HolderProperty]).(string)
	sub = strings.TrimSpace(sub)
	held, err := tx.QueryOne("SELECT sub, role, granted_by, since FROM `appointment_holders` WHERE tenant = " + store.Lit(w.tenant) +
		" AND class = " + store.Lit(a.Class) + " AND natural_key = " + store.Lit(naturalKey))
	if err != nil {
		return nil, err
	}
	named, err := r.namedHolding(tx, w.tenant, a.Class, naturalKey)
	if err != nil {
		return nil, err
	}
	if sub == "" {
		if held != nil && named {
			unbind(naturalKey)
		}
		return ops, nil
	}
	if held != nil && !named && held.Str("sub") != sub {
		return nil, fmt.Errorf("%s %s is held by someone who accepted an invitation to it: end that holding before naming another holder", label, naturalKey)
	}
	role := a.RoleFor(d.payload, unwrap)
	if held != nil && held.Str("sub") == sub && held.Str("role") == role {
		return ops, nil
	}
	if err := r.checkNamedHolder(tx, w.tenant, sub, label); err != nil {
		return nil, err
	}
	if role != "" {
		roles, err := r.rolesOf(tx, w.tenant, sub)
		if err != nil {
			return nil, err
		}
		if err := r.checkCompatible(sub, append(roles, role)); err != nil {
			return nil, err
		}
	}
	by := w.by
	if by == "" {
		by = "system"
	}
	since := w.at
	if held != nil && held.Str("sub") == sub {
		// The same person, now under another role: the binding keeps its
		// date and who made it.
		since = held.Int("since")
		by = held.Str("granted_by")
	}
	key := map[string]any{"tenant": w.tenant, "class": a.Class, "natural_key": naturalKey}
	return append(ops,
		model.WriteOp{Table: "appointment_holders", Key: key, Values: map[string]any{
			"sub": sub, "role": role, "granted_by": by, "since": since, "txid": model.TxIDPlaceholder,
		}},
		model.WriteOp{Table: "appointment_named", Key: key, Values: map[string]any{"since": since}},
	), nil
}

// checkNamedHolder refuses a holder the register cannot vouch for: someone
// who has never signed in to it, whose identity was erased, or who is no
// member of it yet, holding no role and belonging to no organisation. Who
// may name a holder at all is who may write the record, within their scope.
func (r *Register) checkNamedHolder(tx *store.Tx, tenant, sub, label string) error {
	profile, err := r.profileIn(tx, sub)
	if err != nil {
		return err
	}
	if profile.FirstSeen == 0 || profile.Erased {
		return fmt.Errorf("%s names a holder who has never signed in to this register", label)
	}
	roles, err := r.rolesOf(tx, tenant, sub)
	if err != nil {
		return err
	}
	affs, err := r.affiliationsIn(tx, tenant, sub)
	if err != nil {
		return err
	}
	if len(roles) == 0 && len(affs) == 0 {
		return fmt.Errorf("%s names a holder who is not a member of this register", label)
	}
	return nil
}

// namedHolding says whether the record itself named whoever holds it.
func (r *Register) namedHolding(tx *store.Tx, tenant, class, key string) (bool, error) {
	row, err := tx.QueryOne("SELECT since FROM `appointment_named` WHERE tenant = " + store.Lit(tenant) +
		" AND class = " + store.Lit(class) + " AND natural_key = " + store.Lit(key))
	return row != nil, err
}
