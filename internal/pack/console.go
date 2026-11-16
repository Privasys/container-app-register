// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package pack

import "fmt"

func (p *Pack) validateConsole() error {
	if p.ConsoleRoles == nil {
		return nil
	}
	for _, role := range *p.ConsoleRoles {
		if p.model.Role(role) == nil {
			return fmt.Errorf("console_roles: no role named %q", role)
		}
	}
	return nil
}

// ConsoleServed reports whether the register serves its console at all.
func (p *Pack) ConsoleServed() bool {
	return p.ConsoleRoles == nil || len(*p.ConsoleRoles) > 0
}

// ConsoleOpenTo reports whether a person holding these roles may use the
// console.
func (p *Pack) ConsoleOpenTo(roles []string) bool {
	if p.ConsoleRoles == nil {
		return true
	}
	for _, r := range roles {
		for _, c := range *p.ConsoleRoles {
			if r == c {
				return true
			}
		}
	}
	return false
}
