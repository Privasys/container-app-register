// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package pack

import (
	"encoding/json"
	"fmt"
)

// Organisations names the class whose records are the organisations people
// belong to: the legal entities they are invited from. A person's
// affiliations are recorded when they accept an invitation that names one,
// and scopes read them.
type Organisations struct {
	Class string `json:"class"`
	// Single limits a person to one organisation: an invitation into a
	// second one is refused when it is accepted. A register whose rules for
	// people in several organisations are not settled yet starts here.
	Single bool `json:"single,omitempty"`
}

// Scope limits what a role sees and does in one class to the records of
// the organisations the person belongs to. Roles a scope does not name are
// not limited by it; a role a scope names sees only what the scope admits,
// and nothing when the person belongs to no organisation.
//
// A record is in scope when Property holds the key of one of the person's
// organisations. With Via, Property holds the natural key of a record of
// another class, and that record must be in scope under the scopes of its
// own class: a data asset, for instance, is in scope when its foundation is.
type Scope struct {
	Class    string   `json:"class"`
	Roles    []string `json:"roles"`
	Property string   `json:"property"`
	Via      string   `json:"via,omitempty"`
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
	if len(p.Scopes) > 0 && p.Organisations == nil {
		return fmt.Errorf("scopes need the organisations of the pack to be named")
	}
	for i, s := range p.Scopes {
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

// ScopeFor returns the scope that limits a role in a class, or nil.
func (p *Pack) ScopeFor(class, role string) *Scope {
	for _, s := range p.Scopes {
		if s.Class == class && contains(s.Roles, role) {
			return s
		}
	}
	return nil
}
