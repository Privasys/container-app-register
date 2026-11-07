// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register

import (
	"fmt"
	"slices"
	"sort"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/store"
)

// How a role is held, as the pack declares it for each role.
const (
	// HeldByPerson: granted to one named person (the default).
	HeldByPerson = "person"
	// HeldByOrganisation: held by an organisation; its members inherit it.
	HeldByOrganisation = "organisation"
	// HeldByEither: held by an organisation when granted with one, by the
	// person otherwise (an approval given to a firm or to an individual).
	HeldByEither = "either"
	// HeldByAppointment: given by an appointment the register records,
	// never by an invitation.
	HeldByAppointment = "appointment"
)

// roleKind says how a role is held in a grant, given whether the grant
// brings the person into an organisation.
func (r *Register) roleKind(role string, withOrganisation bool) (string, error) {
	spec := r.pk.Model().Role(role)
	if spec == nil {
		return "", fmt.Errorf("no such role %q", role)
	}
	switch spec.Held {
	case "", HeldByPerson:
		return HeldByPerson, nil
	case HeldByEither:
		if withOrganisation {
			return HeldByOrganisation, nil
		}
		return HeldByPerson, nil
	case HeldByOrganisation:
		if !withOrganisation {
			return "", fmt.Errorf("%s is held by an organisation: invite the person into one", role)
		}
		return HeldByOrganisation, nil
	case HeldByAppointment:
		return "", fmt.Errorf("%s is given by an appointment recorded in the register, not by an invitation", role)
	}
	return "", fmt.Errorf("role %s is held in an unknown way %q", role, spec.Held)
}

func (r *Register) organisationRolesIn(tx *store.Tx, tenant, organisation string) ([]string, error) {
	rows, err := tx.Query("SELECT role FROM `organisation_roles` WHERE tenant = " + store.Lit(tenant) +
		" AND organisation = " + store.Lit(organisation))
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.Str("role"))
	}
	sort.Strings(out)
	return out, nil
}

// rolesOf is every role a person holds: granted to them, and inherited
// from each organisation they belong to.
func (r *Register) rolesOf(tx *store.Tx, tenant, sub string) ([]string, error) {
	rows, err := tx.Query("SELECT role FROM `members` WHERE tenant = " + store.Lit(tenant) + " AND sub = " + store.Lit(sub))
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, row := range rows {
		set[row.Str("role")] = true
	}
	affs, err := r.affiliationsIn(tx, tenant, sub)
	if err != nil {
		return nil, err
	}
	for _, a := range affs {
		roles, err := r.organisationRolesIn(tx, tenant, a.Organisation)
		if err != nil {
			return nil, err
		}
		for _, role := range roles {
			set[role] = true
		}
	}
	out := make([]string, 0, len(set))
	for role := range set {
		out = append(out, role)
	}
	sort.Strings(out)
	return out, nil
}

// checkCompatible refuses a set of roles that one person may not hold
// together, wherever each comes from.
func (r *Register) checkCompatible(sub string, roles []string) error {
	for i, a := range roles {
		specA := r.pk.Model().Role(a)
		for _, b := range roles[i+1:] {
			specB := r.pk.Model().Role(b)
			if (specA != nil && slices.Contains(specA.IncompatibleWith, b)) || (specB != nil && slices.Contains(specB.IncompatibleWith, a)) {
				return fmt.Errorf("separation of duties: %s would hold %s and %s, which may not be held together", clip(sub, 24), a, b)
			}
		}
	}
	return nil
}

// OrganisationRoles lists the roles an organisation holds.
func (r *Register) OrganisationRoles(tenant, organisation string) ([]string, error) {
	var out []string
	err := r.st.Do(func(tx *store.Tx) error {
		var err error
		out, err = r.organisationRolesIn(tx, tenant, organisation)
		return err
	})
	return out, err
}

// WithdrawOrganisationRole takes a role from an organisation, and so from
// every one of its members at once. Whoever manages members may.
func (r *Register) WithdrawOrganisationRole(p *auth.Principal, organisation, role, reason string) (*model.Transaction, error) {
	if !p.Can(auth.PermMembers) {
		return nil, fmt.Errorf("%s may not manage members", p.Acting)
	}
	if reason == "" {
		return nil, fmt.Errorf("say why the role is withdrawn")
	}
	var txn *model.Transaction
	err := r.st.Do(func(tx *store.Tx) error {
		held, err := r.organisationRolesIn(tx, p.Tenant, organisation)
		if err != nil {
			return err
		}
		if !slices.Contains(held, role) {
			return fmt.Errorf("no such role %s held by organisation %s", role, organisation)
		}
		at := r.now()
		txn, err = r.commit(tx, model.Envelope{
			Kind: model.KindMemberRevoke, Tenant: p.Tenant, Author: principalAuthor(p), Timestamp: at,
			Message: composeMessage(clip(fmt.Sprintf("Withdraw %s from organisation %s", role, organisation), model.MaxSummary), reason),
		}, []model.WriteOp{{
			Table: "organisation_roles", Key: map[string]any{"tenant": p.Tenant, "organisation": organisation, "role": role}, Delete: true,
		}})
		return err
	})
	return txn, err
}

// RemoveFromOrganisation takes a person out of an organisation, ending
// every role they inherited from it. Its administrators and whoever
// manages members may; an organisation keeps at least one administrator.
func (r *Register) RemoveFromOrganisation(p *auth.Principal, organisation, sub, reason string) (*model.Transaction, error) {
	if reason == "" {
		return nil, fmt.Errorf("say why the person leaves the organisation")
	}
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
		if target.Admin && admins <= 1 && len(affs) > 1 {
			return fmt.Errorf("organisation %s would be left without an administrator: name another one first", organisation)
		}
		at := r.now()
		txn, err = r.commit(tx, model.Envelope{
			Kind: model.KindMemberRevoke, Tenant: p.Tenant, Author: principalAuthor(p), Timestamp: at,
			Message: composeMessage(clip(fmt.Sprintf("Remove %s from organisation %s", clip(sub, 16), organisation), model.MaxSummary), reason),
		}, []model.WriteOp{{
			Table: "affiliations", Key: map[string]any{"tenant": p.Tenant, "sub": sub, "organisation": organisation}, Delete: true,
		}})
		return err
	})
	return txn, err
}
