// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/pack"
	"github.com/Privasys/container-app-register/internal/store"
)

// Affiliation says a person belongs to an organisation, and whether they
// administer it there: invite colleagues and name other administrators.
type Affiliation struct {
	Sub          string `json:"sub"`
	Organisation string `json:"organisation"`
	Admin        bool   `json:"admin"`
	Since        int64  `json:"since"`
}

func decodeAffiliation(row store.Row) Affiliation {
	return Affiliation{Sub: row.Str("sub"), Organisation: row.Str("organisation"), Admin: row.Bool("admin"), Since: row.Int("since")}
}

func (r *Register) affiliationsIn(tx *store.Tx, tenant, sub string) ([]Affiliation, error) {
	rows, err := tx.Query("SELECT * FROM `affiliations` WHERE tenant = " + store.Lit(tenant) + " AND sub = " + store.Lit(sub))
	if err != nil {
		return nil, err
	}
	out := make([]Affiliation, 0, len(rows))
	for _, row := range rows {
		out = append(out, decodeAffiliation(row))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Organisation < out[j].Organisation })
	return out, nil
}

// Affiliations lists the organisations a person belongs to.
func (r *Register) Affiliations(tenant, sub string) ([]Affiliation, error) {
	var out []Affiliation
	err := r.st.Do(func(tx *store.Tx) error {
		var err error
		out, err = r.affiliationsIn(tx, tenant, sub)
		return err
	})
	return out, err
}

func (r *Register) organisationsOf(tx *store.Tx, p *auth.Principal) ([]string, error) {
	affs, err := r.affiliationsIn(tx, p.Tenant, p.Sub)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(affs))
	for _, a := range affs {
		keys = append(keys, a.Organisation)
	}
	return keys, nil
}

func (r *Register) organisationClass() (*pack.Class, error) {
	if r.pk.Organisations == nil {
		return nil, fmt.Errorf("this register has no organisations")
	}
	return r.pk.Class(r.pk.Organisations.Class), nil
}

// organisationExists says whether an organisation record has this key.
func (r *Register) organisationExists(tx *store.Tx, tenant, key string) (bool, error) {
	class, err := r.organisationClass()
	if err != nil {
		return false, err
	}
	row, err := tx.QueryOne("SELECT id FROM `objects` WHERE tenant = " + store.Lit(tenant) +
		" AND class = " + store.Lit(class.Name) + " AND natural_key = " + store.Lit(key))
	return row != nil, err
}

// OrganisationName is an organisation's legal name, or its key when the
// record has none that can be read.
func (r *Register) OrganisationName(tenant, key string) string {
	name := key
	_ = r.st.Do(func(tx *store.Tx) error {
		class, err := r.organisationClass()
		if err != nil {
			return err
		}
		row, err := tx.QueryOne("SELECT id FROM `objects` WHERE tenant = " + store.Lit(tenant) +
			" AND class = " + store.Lit(class.Name) + " AND natural_key = " + store.Lit(key))
		if err != nil || row == nil {
			return err
		}
		head, err := r.headVersion(tx, class, row.Str("id"))
		if err != nil {
			return err
		}
		if n, ok := unwrap(head.Payload["legal_name"]).(string); ok && n != "" {
			name = n
		}
		return nil
	})
	return name
}

// isOrganisationAdmin says whether the person administers the organisation.
func (r *Register) isOrganisationAdmin(tx *store.Tx, tenant, sub, organisation string) (bool, error) {
	row, err := tx.QueryOne("SELECT admin FROM `affiliations` WHERE tenant = " + store.Lit(tenant) +
		" AND sub = " + store.Lit(sub) + " AND organisation = " + store.Lit(organisation))
	if err != nil || row == nil {
		return false, err
	}
	return row.Bool("admin"), nil
}

func (r *Register) affiliatesIn(tx *store.Tx, tenant, organisation string) ([]Affiliation, error) {
	rows, err := tx.Query("SELECT * FROM `affiliations` WHERE tenant = " + store.Lit(tenant) +
		" AND organisation = " + store.Lit(organisation))
	if err != nil {
		return nil, err
	}
	out := make([]Affiliation, 0, len(rows))
	for _, row := range rows {
		out = append(out, decodeAffiliation(row))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Since < out[j].Since })
	return out, nil
}

// OrganisationMember is a person of an organisation, with the roles they
// hold in the register.
type OrganisationMember struct {
	Affiliation
	Roles []string `json:"roles"`
}

// OrganisationMembers lists the people of an organisation, for its own
// administrators and for whoever manages the register's members.
func (r *Register) OrganisationMembers(p *auth.Principal, organisation string) ([]OrganisationMember, error) {
	var out []OrganisationMember
	err := r.st.Do(func(tx *store.Tx) error {
		if err := r.mayAdminister(tx, p, organisation); err != nil {
			return err
		}
		affs, err := r.affiliatesIn(tx, p.Tenant, organisation)
		if err != nil {
			return err
		}
		for _, a := range affs {
			rows, err := tx.Query("SELECT role FROM `members` WHERE tenant = " + store.Lit(p.Tenant) + " AND sub = " + store.Lit(a.Sub))
			if err != nil {
				return err
			}
			m := OrganisationMember{Affiliation: a, Roles: []string{}}
			for _, row := range rows {
				m.Roles = append(m.Roles, row.Str("role"))
			}
			sort.Strings(m.Roles)
			out = append(out, m)
		}
		return nil
	})
	return out, err
}

func (r *Register) mayAdminister(tx *store.Tx, p *auth.Principal, organisation string) error {
	if p.Can(auth.PermMembers) {
		return nil
	}
	admin, err := r.isOrganisationAdmin(tx, p.Tenant, p.Sub, organisation)
	if err != nil {
		return err
	}
	if !admin {
		return fmt.Errorf("%s may not administer organisation %s", p.Acting, organisation)
	}
	return nil
}

// SetOrganisationAdmin makes a person of the organisation an administrator
// of it, or stops them being one. An organisation keeps at least one.
func (r *Register) SetOrganisationAdmin(p *auth.Principal, organisation, sub string, admin bool) (*model.Transaction, error) {
	var txn *model.Transaction
	err := r.st.Do(func(tx *store.Tx) error {
		if err := r.mayAdminister(tx, p, organisation); err != nil {
			return err
		}
		affs, err := r.affiliatesIn(tx, p.Tenant, organisation)
		if err != nil {
			return err
		}
		var target *Affiliation
		admins := 0
		for i := range affs {
			if affs[i].Admin {
				admins++
			}
			if affs[i].Sub == sub {
				target = &affs[i]
			}
		}
		if target == nil {
			return fmt.Errorf("no such person in organisation %s", organisation)
		}
		if target.Admin == admin {
			return nil
		}
		if !admin && admins <= 1 {
			return fmt.Errorf("organisation %s would be left without an administrator: name another one first", organisation)
		}
		at := r.now()
		verb := "Make an administrator of"
		if !admin {
			verb = "Stop someone administering"
		}
		txn, err = r.commit(tx, model.Envelope{
			Kind: model.KindAffiliationAdmin, Tenant: p.Tenant, Author: principalAuthor(p), Timestamp: at,
			Message: clip(fmt.Sprintf("%s organisation %s", verb, organisation), model.MaxSummary),
		}, []model.WriteOp{{
			Table: "affiliations", Key: map[string]any{"tenant": p.Tenant, "sub": sub, "organisation": organisation},
			Values: map[string]any{"admin": admin},
		}})
		return err
	})
	return txn, err
}

// RecordOrganisation records an organisation that no source holds, from
// the details its first invitation gives: one outside the jurisdiction of
// the register's sources, for instance. Whoever manages members may.
func (r *Register) RecordOrganisation(p *auth.Principal, payload map[string]any) (string, *model.Transaction, error) {
	if !p.Can(auth.PermMembers) {
		return "", nil, fmt.Errorf("%s may not record organisations", p.Acting)
	}
	class, err := r.organisationClass()
	if err != nil {
		return "", nil, err
	}
	if err := class.Compiled().Validate(payload); err != nil {
		return "", nil, fmt.Errorf("the organisation does not match the %s schema: %w", class.Name, err)
	}
	key := fmt.Sprint(payload[class.NaturalKey])
	var (
		objectID string
		txn      *model.Transaction
	)
	err = r.st.Do(func(tx *store.Tx) error {
		at := r.now()
		var ops []model.WriteOp
		objectID, ops, err = r.createOps(tx, newWriteCtx(p.Tenant, at), class, payload, "")
		if err != nil {
			return err
		}
		txn, err = r.commit(tx, model.Envelope{
			Kind: model.KindOrganisationRecord, Tenant: p.Tenant, Author: principalAuthor(p), Timestamp: at,
			Message: clip("Record organisation "+key, model.MaxSummary),
		}, ops)
		return err
	})
	return objectID, txn, err
}

// unwrap reads a property's value whether it is stored plain or in a
// value envelope.
func unwrap(v any) any {
	if m, ok := v.(map[string]any); ok {
		if inner, ok := m["value"]; ok {
			return inner
		}
	}
	return v
}

// inScope says whether a record with this payload is within what the
// caller's acting role may see and do in its class.
func (r *Register) inScope(tx *store.Tx, p *auth.Principal, class *pack.Class, payload map[string]any) (bool, error) {
	scope := r.pk.ScopeFor(class.Name, p.Acting)
	if scope == nil {
		return true, nil
	}
	value := fmt.Sprint(unwrap(payload[scope.Property]))
	if scope.Via == "" {
		orgs, err := r.organisationsOf(tx, p)
		return slices.Contains(orgs, value), err
	}
	via := r.pk.Class(scope.Via)
	row, err := tx.QueryOne("SELECT id FROM `objects` WHERE tenant = " + store.Lit(p.Tenant) +
		" AND class = " + store.Lit(via.Name) + " AND natural_key = " + store.Lit(value))
	if err != nil || row == nil {
		return false, err
	}
	head, err := r.headVersion(tx, via, row.Str("id"))
	if err != nil {
		return false, err
	}
	return r.inScope(tx, p, via, head.Payload)
}

// checkScope refuses a record outside the caller's scope.
func (r *Register) checkScope(tx *store.Tx, p *auth.Principal, class *pack.Class, objectID string) error {
	if r.pk.ScopeFor(class.Name, p.Acting) == nil {
		return nil
	}
	head, err := r.headVersion(tx, class, objectID)
	if err != nil {
		return err
	}
	ok, err := r.inScope(tx, p, class, head.Payload)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%s may not read this %s: it is not one of their organisation's", p.Acting, strings.ReplaceAll(class.Name, "_", " "))
	}
	return nil
}

// scopeClause is the SQL condition that keeps a listing to the caller's
// scope, empty when the caller's role is not limited in the class.
func (r *Register) scopeClause(tx *store.Tx, p *auth.Principal, class *pack.Class) (string, error) {
	scope := r.pk.ScopeFor(class.Name, p.Acting)
	if scope == nil {
		return "", nil
	}
	var allowed []string
	if scope.Via == "" {
		orgs, err := r.organisationsOf(tx, p)
		if err != nil {
			return "", err
		}
		allowed = orgs
	} else {
		via := r.pk.Class(scope.Via)
		rows, err := tx.Query("SELECT id, natural_key FROM `objects` WHERE tenant = " + store.Lit(p.Tenant) +
			" AND class = " + store.Lit(via.Name))
		if err != nil {
			return "", err
		}
		for _, row := range rows {
			head, err := r.headVersion(tx, via, row.Str("id"))
			if err != nil {
				return "", err
			}
			ok, err := r.inScope(tx, p, via, head.Payload)
			if err != nil {
				return "", err
			}
			if ok {
				allowed = append(allowed, row.Str("natural_key"))
			}
		}
	}
	if len(allowed) == 0 {
		return "1 = 0", nil
	}
	lits := make([]string, len(allowed))
	for i, a := range allowed {
		lits[i] = store.Lit(a)
	}
	if scope.Property == class.NaturalKey {
		return "o.natural_key IN (" + strings.Join(lits, ", ") + ")", nil
	}
	return "q." + store.Ident(scope.Property) + " IN (" + strings.Join(lits, ", ") + ")", nil
}
