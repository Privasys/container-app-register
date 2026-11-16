// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register

import (
	"strings"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/store"
)

// Actors: who made a change, by name, for the roles cleared to see it.
//
// A transaction names its author by subject and role only: it is
// permanent, and a name in it could never be erased. A role the pack
// marks history_actors sees, beside each change in the histories and logs
// it may already read, the author's name and email from their sealed
// profile, and the organisation they acted for. When a person's profile
// is erased, their changes go back to naming a subject.

// Actor is the person behind one change.
type Actor struct {
	Sub              string `json:"sub"`
	Name             string `json:"name,omitempty"`
	Email            string `json:"email,omitempty"`
	Organisation     string `json:"organisation,omitempty"`
	OrganisationName string `json:"organisation_name,omitempty"`
}

// seesActors reports whether the caller's acting role is shown who acted.
func (r *Register) seesActors(p *auth.Principal) bool {
	spec := r.pk.Model().Role(p.Acting)
	return spec != nil && spec.HistoryActors
}

// actorsIn gives the actor of each transaction, by txid, to a caller who
// sees actors; nil otherwise. System changes have no actor.
func (r *Register) actorsIn(tx *store.Tx, p *auth.Principal, txns []*model.Transaction) (map[string]*Actor, error) {
	if !r.seesActors(p) {
		return nil, nil
	}
	out := map[string]*Actor{}
	profiles := map[string]Profile{}
	orgNames := map[string]string{}
	for _, t := range txns {
		if t == nil {
			continue
		}
		a := t.Envelope.Author
		if a.Sub == "" || a.Sub == policySub || strings.HasPrefix(a.Sub, "system:") {
			continue
		}
		prof, ok := profiles[a.Sub]
		if !ok {
			var err error
			if prof, err = r.profileIn(tx, a.Sub); err != nil {
				return nil, err
			}
			profiles[a.Sub] = prof
		}
		actor := &Actor{Sub: a.Sub}
		if !prof.Erased {
			actor.Name, actor.Email = prof.Name, prof.Email
		}
		org := a.Organisation
		if org == "" && r.pk.Organisations != nil {
			// A change made before organisations were recorded with it:
			// the person's organisation, if they belonged to it then.
			affs, err := r.affiliationsIn(tx, t.Envelope.Tenant, a.Sub)
			if err != nil {
				return nil, err
			}
			for _, af := range affs {
				if af.Since <= t.Envelope.Timestamp {
					org = af.Organisation
				}
			}
		}
		if org != "" {
			name, ok := orgNames[org]
			if !ok {
				name = r.organisationNameIn(tx, t.Envelope.Tenant, org)
				orgNames[org] = name
			}
			actor.Organisation, actor.OrganisationName = org, name
		}
		out[t.TxID] = actor
	}
	return out, nil
}

// Actors gives the actors of some transactions to a caller who sees
// them: the log's entries, for instance. Changes the register makes on
// its own (system authors, approvals under policy) have no actor.
func (r *Register) Actors(p *auth.Principal, txns []*model.Transaction) (map[string]*Actor, error) {
	var out map[string]*Actor
	err := r.st.Do(func(tx *store.Tx) error {
		var err error
		out, err = r.actorsIn(tx, p, txns)
		return err
	})
	return out, err
}
