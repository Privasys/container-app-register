// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package pack

import (
	"fmt"
	"sort"
)

// Appointment makes the records of one class appointments: a record names
// a role, and the person bound to it holds that role while the record is
// current. A designated driver, for instance, is appointed to one fleet by
// a driver_appointment record; they drive for that fleet only, personally,
// and colleagues at their own firm inherit nothing.
//
// A record gives the fixed Role, or the role RoleProperty's value maps to
// in Roles. It is current while its status is the class's initial status
// and EndedBy, when named, holds no value. Keys name the properties whose
// values a scope compares against when the person acts under the role, in
// place of the keys of their organisations.
type Appointment struct {
	Class        string            `json:"class"`
	Role         string            `json:"role,omitempty"`
	RoleProperty string            `json:"role_property,omitempty"`
	Roles        map[string]string `json:"roles,omitempty"`
	Keys         []string          `json:"keys,omitempty"`
	EndedBy      string            `json:"ended_by,omitempty"`
}

// HeldByAppointment is how a role given by an appointment is declared.
const HeldByAppointment = "appointment"

func (p *Pack) validateAppointments() error {
	seen := map[string]bool{}
	for i, a := range p.Appointments {
		class := p.classByName[a.Class]
		if class == nil || class.NaturalKey == "" {
			return fmt.Errorf("appointment %d: %q is not a class with a natural key", i, a.Class)
		}
		if seen[a.Class] {
			return fmt.Errorf("appointment %d: class %s is already an appointment", i, a.Class)
		}
		seen[a.Class] = true
		props, err := classProperties(class)
		if err != nil {
			return fmt.Errorf("appointment %d: %w", i, err)
		}
		switch {
		case a.Role != "" && (a.RoleProperty != "" || len(a.Roles) > 0):
			return fmt.Errorf("appointment %d: name a role, or a role property with its roles, not both", i)
		case a.Role == "" && (a.RoleProperty == "" || len(a.Roles) == 0):
			return fmt.Errorf("appointment %d: name a role, or a role property with its roles", i)
		}
		if a.RoleProperty != "" {
			if _, ok := props[a.RoleProperty]; !ok {
				return fmt.Errorf("appointment %d: class %s has no property %q", i, a.Class, a.RoleProperty)
			}
		}
		for _, role := range a.GivenRoles() {
			spec := p.model.Role(role)
			if spec == nil {
				return fmt.Errorf("appointment %d: no role named %q", i, role)
			}
			if spec.Held != HeldByAppointment {
				return fmt.Errorf("appointment %d: role %s is not held by appointment", i, role)
			}
		}
		for _, k := range a.Keys {
			if _, ok := props[k]; !ok {
				return fmt.Errorf("appointment %d: class %s has no property %q", i, a.Class, k)
			}
		}
		if a.EndedBy != "" {
			if _, ok := props[a.EndedBy]; !ok {
				return fmt.Errorf("appointment %d: class %s has no property %q", i, a.Class, a.EndedBy)
			}
		}
	}
	return nil
}

// GivenRoles lists the roles an appointment class can give, in name order.
func (a *Appointment) GivenRoles() []string {
	if a.Role != "" {
		return []string{a.Role}
	}
	set := map[string]bool{}
	for _, role := range a.Roles {
		set[role] = true
	}
	out := make([]string, 0, len(set))
	for role := range set {
		out = append(out, role)
	}
	sort.Strings(out)
	return out
}

// RoleFor is the role a record with this payload gives, "" when none.
// read unwraps a property's value however the payload stores it.
func (a *Appointment) RoleFor(payload map[string]any, read func(any) any) string {
	if a.Role != "" {
		return a.Role
	}
	v, ok := read(payload[a.RoleProperty]).(string)
	if !ok {
		return ""
	}
	return a.Roles[v]
}

// Gives reports whether the class can give the role.
func (a *Appointment) Gives(role string) bool {
	for _, r := range a.GivenRoles() {
		if r == role {
			return true
		}
	}
	return false
}

// AppointmentOf returns the appointment declared for a class, or nil.
func (p *Pack) AppointmentOf(class string) *Appointment {
	for _, a := range p.Appointments {
		if a.Class == class {
			return a
		}
	}
	return nil
}

// AppointmentsGiving lists the appointment classes that can give a role.
func (p *Pack) AppointmentsGiving(role string) []*Appointment {
	var out []*Appointment
	for _, a := range p.Appointments {
		if a.Gives(role) {
			out = append(out, a)
		}
	}
	return out
}
