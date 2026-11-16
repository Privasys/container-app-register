// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package pack

import "fmt"

// StepUp names the acts a person must approve, each time, on the wallet
// bound to them: a signed-in session says who is at the keyboard, an
// approval says that this person meant this act, now. The register
// refuses a named act until it carries an approval of exactly that act.
//
//	"step_up": {
//	  "workflows": ["register_vehicle", "transfer_keeper"],
//	  "decisions": ["approve", "reject", "return"],
//	  "grant_roles": ["registrar", "auditor"],
//	  "revoke_roles": ["registrar", "auditor"],
//	  "erasure": true
//	}
type StepUp struct {
	// Workflows whose decisions need an approval.
	Workflows []string `json:"workflows,omitempty"`
	// Decisions narrows which decisions on those workflows do: approve,
	// reject, return. Empty, all three.
	Decisions []string `json:"decisions,omitempty"`
	// Propose makes proposing into those workflows need one too.
	Propose bool `json:"propose,omitempty"`
	// GrantRoles are the roles whose grant needs an approval, directly or
	// through an invitation to them.
	GrantRoles []string `json:"grant_roles,omitempty"`
	// RevokeRoles are the roles whose removal needs one, directly or by
	// ending an appointment that confers them.
	RevokeRoles []string `json:"revoke_roles,omitempty"`
	// Erasure makes every erasure of personal data need one.
	Erasure bool `json:"erasure,omitempty"`
}

// Decisions a step-up can name.
const (
	StepUpApprove = "approve"
	StepUpReject  = "reject"
	StepUpReturn  = "return"
)

func (p *Pack) validateStepUp() error {
	s := p.StepUp
	if s == nil {
		return nil
	}
	for _, w := range s.Workflows {
		if p.Workflow(w) == nil {
			return fmt.Errorf("step_up: no workflow named %q", w)
		}
	}
	for _, d := range s.Decisions {
		if d != StepUpApprove && d != StepUpReject && d != StepUpReturn {
			return fmt.Errorf("step_up: decisions are approve, reject or return, not %q", d)
		}
	}
	if (len(s.Decisions) > 0 || s.Propose) && len(s.Workflows) == 0 {
		return fmt.Errorf("step_up: decisions and propose apply to the workflows named; name them")
	}
	for _, list := range [][]string{s.GrantRoles, s.RevokeRoles} {
		for _, role := range list {
			if p.model.Role(role) == nil {
				return fmt.Errorf("step_up: no role named %q", role)
			}
		}
	}
	return nil
}

// StepUpUsed reports whether any act needs an approval, which is when
// people need a wallet bound to them.
func (p *Pack) StepUpUsed() bool {
	s := p.StepUp
	return s != nil && (len(s.Workflows) > 0 || len(s.GrantRoles) > 0 || len(s.RevokeRoles) > 0 || s.Erasure)
}

// StepUpDecision reports whether a decision on a workflow needs one.
func (p *Pack) StepUpDecision(workflow, decision string) bool {
	s := p.StepUp
	if s == nil || !contains(s.Workflows, workflow) {
		return false
	}
	return len(s.Decisions) == 0 || contains(s.Decisions, decision)
}

// StepUpPropose reports whether proposing into a workflow needs one.
func (p *Pack) StepUpPropose(workflow string) bool {
	return p.StepUp != nil && p.StepUp.Propose && contains(p.StepUp.Workflows, workflow)
}

// StepUpGrant reports whether granting a role needs one.
func (p *Pack) StepUpGrant(role string) bool {
	return p.StepUp != nil && contains(p.StepUp.GrantRoles, role)
}

// StepUpRevoke reports whether taking a role away needs one.
func (p *Pack) StepUpRevoke(role string) bool {
	return p.StepUp != nil && contains(p.StepUp.RevokeRoles, role)
}

// StepUpErasure reports whether an erasure needs one.
func (p *Pack) StepUpErasure() bool { return p.StepUp != nil && p.StepUp.Erasure }
