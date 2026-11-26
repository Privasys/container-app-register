// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package pack

import (
	"encoding/json"
	"fmt"
)

// Organisations names the class whose records are the organisations people
// belong to: the legal entities they are invited from. A person belongs to
// one organisation at a time, and acts for it. A person's
// affiliations are recorded when they accept an invitation that names one,
// and scopes read them.
type Organisations struct {
	Class string `json:"class"`
}

// Scope limits what a role sees and does in one class to the records of
// the organisations the person belongs to. A role may have several scopes
// in a class; a record any of them admits is in scope. Roles a scope does not name are
// not limited by it; a role a scope names sees only what the scope admits,
// and nothing when the person belongs to no organisation.
//
// A record is in scope when Property holds the key of one of the person's
// organisations. With Via, Property holds the natural key of a record of
// another class, and that record must be in scope under the scopes of its
// own class: a vehicle, for instance, is in scope when its fleet is.
//
// With ViaProperty, the link runs the other way: a record of class Via
// whose ViaProperty equals this record's Property, and which is in scope
// under its own class's scopes, brings this record into scope. A vehicle
// is in scope for a repairer while a repair order in the repairer's scope
// names it. ViaCurrent counts only the Via records in their class's
// initial status, so ending the link record ends the access at once.
type Scope struct {
	Class       string   `json:"class"`
	Roles       []string `json:"roles"`
	Property    string   `json:"property"`
	Via         string   `json:"via,omitempty"`
	ViaProperty string   `json:"via_property,omitempty"`
	ViaCurrent  bool     `json:"via_current,omitempty"`
}

// ViaColumn is the query column of the Via class that holds ViaProperty.
func (s *Scope) ViaColumn(via *Class) string {
	for _, p := range via.Compiled().Projections() {
		if p.Property == s.ViaProperty && p.Member == "" {
			return p.Column
		}
	}
	return ""
}

func classProperties(c *Class) (map[string]json.RawMessage, error) {
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(c.Schema, &schema); err != nil {
		return nil, err
	}
	return schema.Properties, nil
}

func (p *Pack) validateScopes() error {
	if p.Organisations != nil {
		class := p.classByName[p.Organisations.Class]
		if class == nil {
			return fmt.Errorf("organisations: no class named %q", p.Organisations.Class)
		}
		if class.NaturalKey == "" {
			return fmt.Errorf("organisations: class %s needs a natural key, which is an organisation's key", class.Name)
		}
	}
	for i, s := range p.Scopes {
		// A role held by appointment is scoped by its appointments' keys;
		// any other role by its organisations.
		for _, role := range s.Roles {
			if spec := p.model.Role(role); spec != nil && spec.Held != HeldByAppointment && p.Organisations == nil {
				return fmt.Errorf("scope %d: scoping %s needs the organisations of the pack to be named", i, role)
			}
		}
		class := p.classByName[s.Class]
		if class == nil {
			return fmt.Errorf("scope %d: no class named %q", i, s.Class)
		}
		props, err := classProperties(class)
		if err != nil {
			return fmt.Errorf("scope %d: %w", i, err)
		}
		if _, ok := props[s.Property]; !ok {
			return fmt.Errorf("scope %d: class %s has no property %q", i, s.Class, s.Property)
		}
		if s.Via != "" {
			via := p.classByName[s.Via]
			if via == nil || via.NaturalKey == "" {
				return fmt.Errorf("scope %d: %q is not a class with a natural key", i, s.Via)
			}
			if via.Name == s.Class {
				return fmt.Errorf("scope %d: a class cannot be scoped through itself", i)
			}
			if s.ViaProperty != "" {
				if s.ViaColumn(via) == "" {
					return fmt.Errorf("scope %d: %s.%s is not a queryable property", i, via.Name, s.ViaProperty)
				}
				for _, f := range via.Compiled().PIIFields() {
					if f == s.ViaProperty {
						return fmt.Errorf("scope %d: %s.%s is personal data, which no scope compares", i, via.Name, s.ViaProperty)
					}
				}
			}
			if s.ViaCurrent && (len(via.Statuses) == 0 || via.Initial == "") {
				return fmt.Errorf("scope %d: via_current needs %s to have statuses", i, via.Name)
			}
		} else if s.ViaProperty != "" || s.ViaCurrent {
			return fmt.Errorf("scope %d: via_property and via_current need via", i)
		}
		if len(s.Roles) == 0 {
			return fmt.Errorf("scope %d: name the roles it limits", i)
		}
		for _, role := range s.Roles {
			if p.model.Role(role) == nil {
				return fmt.Errorf("scope %d: no role named %q", i, role)
			}
		}
	}
	return nil
}

// ScopesFor returns the scopes that limit a role in a class, none when it
// is not limited. With several, a record is in scope under any of them: a
// fleet manager sees its own firm's organisation and those of the fleets
// it manages.
func (p *Pack) ScopesFor(class, role string) []*Scope {
	var out []*Scope
	for _, s := range p.Scopes {
		if s.Class == class && contains(s.Roles, role) {
			out = append(out, s)
		}
	}
	return out
}
