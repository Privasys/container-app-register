// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package pack

import "fmt"

// InvitationRule lets the holders of one role invite people, to another
// role, into the organisation of a record they are scoped to: the
// organisation whose key is that record's natural key. A registered agent,
// for instance, invites the council members of a foundation it acts for
// into the foundation's organisation, without administering it.
type InvitationRule struct {
	Inviter string `json:"inviter"`
	Role    string `json:"role"`
	Class   string `json:"class"`
}

func (p *Pack) validateInvitations() error {
	if len(p.Invitations) > 0 && p.Organisations == nil {
		return fmt.Errorf("invitations need the organisations of the pack to be named")
	}
	for i, rule := range p.Invitations {
		if p.model.Role(rule.Inviter) == nil {
			return fmt.Errorf("invitation rule %d: no role named %q", i, rule.Inviter)
		}
		if p.model.Role(rule.Role) == nil {
			return fmt.Errorf("invitation rule %d: no role named %q", i, rule.Role)
		}
		class := p.classByName[rule.Class]
		if class == nil || class.NaturalKey == "" {
			return fmt.Errorf("invitation rule %d: %q is not a class with a natural key", i, rule.Class)
		}
	}
	return nil
}

// InvitationRule returns the rule that lets inviter invite to role, or nil.
func (p *Pack) InvitationRule(inviter, role string) *InvitationRule {
	for _, rule := range p.Invitations {
		if rule.Inviter == inviter && rule.Role == role {
			return rule
		}
	}
	return nil
}
