// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package pack

import (
	"fmt"
	"regexp"
	"strings"
)

// Notification writes to people when a workflow event happens (a
// proposal is made, approved by a reviewer or under policy, rejected, or
// returned for more information) or a wallet is bound to a member or
// removed. The site's email template names what the message says; the
// pack names who receives it.
type Notification struct {
	// On is "<workflow>:<event>", or "wallet:bound" or "wallet:removed".
	On string `json:"on"`
	// To are the rules that choose recipients, resolved when the event
	// is committed.
	To []NotifyRule `json:"to"`
	// Template is the name of the site's email template, emails/<name>.html.
	Template string `json:"template"`
}

// NotifyRule chooses recipients: everyone holding a role whose scope
// admits the record, everyone in the proposer's organisation, the
// proposer, or the member a wallet event concerns. A rule sets exactly
// one of them.
type NotifyRule struct {
	Role                 string `json:"role,omitempty"`
	ProposerOrganisation bool   `json:"proposer_organisation,omitempty"`
	Proposer             bool   `json:"proposer,omitempty"`
	// Member is the member a wallet event concerns.
	Member bool `json:"member,omitempty"`
}

// The workflow events a notification can follow.
const (
	EventProposed = "proposed"
	EventApproved = "approved"
	EventRejected = "rejected"
	EventReturned = "returned"

	// WalletEvents prefixes the events of wallet bindings: "wallet:bound"
	// when a member binds a wallet, "wallet:removed" when one is removed.
	WalletEvents       = "wallet"
	EventWalletBound   = "bound"
	EventWalletRemoved = "removed"
)

var (
	notifyEvents   = []string{EventProposed, EventApproved, EventRejected, EventReturned}
	walletEvents   = []string{EventWalletBound, EventWalletRemoved}
	templateNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
)

// Event splits On into the workflow and the event.
func (n *Notification) Event() (workflow, event string) {
	workflow, event, _ = strings.Cut(n.On, ":")
	return workflow, event
}

func (p *Pack) validateNotifications() error {
	for i, n := range p.Notifications {
		wf, event := n.Event()
		wallet := wf == WalletEvents
		switch {
		case wallet:
			if !contains(walletEvents, event) {
				return fmt.Errorf("notification %d: %q is not a wallet event (%s)", i, event, strings.Join(walletEvents, ", "))
			}
		case p.workflowByName[wf] == nil:
			return fmt.Errorf("notification %d: no workflow named %q", i, wf)
		case !contains(notifyEvents, event):
			return fmt.Errorf("notification %d: %q is not an event (%s)", i, event, strings.Join(notifyEvents, ", "))
		}
		if !templateNameRe.MatchString(n.Template) {
			return fmt.Errorf("notification %d: template %q is not a plain name (lower case, digits, - and _)", i, n.Template)
		}
		if len(n.To) == 0 {
			return fmt.Errorf("notification %d: name who receives it", i)
		}
		for j, rule := range n.To {
			set := 0
			if rule.Role != "" {
				set++
				if p.model.Role(rule.Role) == nil {
					return fmt.Errorf("notification %d, recipient %d: no role named %q", i, j, rule.Role)
				}
			}
			if rule.ProposerOrganisation {
				set++
				if p.Organisations == nil {
					return fmt.Errorf("notification %d, recipient %d: the proposer's organisation needs the organisations of the pack to be named", i, j)
				}
			}
			if rule.Proposer {
				set++
			}
			if rule.Member {
				set++
			}
			if set != 1 {
				return fmt.Errorf("notification %d, recipient %d: set exactly one of role, proposer_organisation, proposer and member", i, j)
			}
			if wallet && (rule.Proposer || rule.ProposerOrganisation) {
				return fmt.Errorf("notification %d, recipient %d: a wallet event has no proposer; name the member or a role", i, j)
			}
			if !wallet && rule.Member {
				return fmt.Errorf("notification %d, recipient %d: member applies to wallet events", i, j)
			}
		}
	}
	return nil
}

// NotificationsOn lists the notifications that follow one workflow event.
func (p *Pack) NotificationsOn(workflow, event string) []*Notification {
	var out []*Notification
	for _, n := range p.Notifications {
		if w, e := n.Event(); w == workflow && e == event {
			out = append(out, n)
		}
	}
	return out
}

// NotificationTemplates lists the template names the pack uses.
func (p *Pack) NotificationTemplates() []string {
	var out []string
	for _, n := range p.Notifications {
		if !contains(out, n.Template) {
			out = append(out, n.Template)
		}
	}
	return out
}
