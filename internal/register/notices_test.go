// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register_test

import (
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Privasys/container-app-register/internal/pack"
	"github.com/Privasys/container-app-register/internal/register"
)

type sink struct {
	mu      sync.Mutex
	notices []register.Notice
}

func (s *sink) Deliver(n register.Notice) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notices = append(s.notices, n)
}

func (s *sink) take() []register.Notice {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.notices
	s.notices = nil
	return out
}

func emails(n register.Notice) []string {
	var out []string
	for _, r := range n.Recipients {
		out = append(out, r.Email)
	}
	return out
}

func TestNotificationsFollowWorkflowEvents(t *testing.T) {
	h := newHarnessWith(t, t.TempDir(), carPackWithAppointments(t, func(doc map[string]any) {
		for _, w := range doc["workflows"].([]any) {
			if wf := w.(map[string]any); wf["name"] == "appoint_driver" {
				wf["auto_approve"] = false
			}
		}
		doc["notifications"] = []any{
			map[string]any{"on": "record_fleet:approved", "template": "fleet-recorded",
				"to": []any{map[string]any{"role": "fleet_manager"}}},
			map[string]any{"on": "appoint_driver:returned", "template": "returned",
				"to": []any{map[string]any{"proposer": true}}},
			map[string]any{"on": "appoint_driver:proposed", "template": "proposed",
				"to": []any{map[string]any{"role": "fleet_manager"}, map[string]any{"proposer": true}}},
		}
	}))
	out := &sink{}
	h.reg.SetNoticeSink(out)
	recordOrganisations(t, h, "ORG-NORTH", "ORG-SOUTH")
	join(t, h, "operator-1", "sub-north", register.InviteRequest{Role: "fleet_manager", Organisation: "ORG-NORTH"})
	join(t, h, "operator-1", "sub-south", register.InviteRequest{Role: "fleet_manager", Organisation: "ORG-SOUTH"})
	join(t, h, "operator-1", "sub-quiet", register.InviteRequest{Organisation: "ORG-NORTH"})
	for sub, email := range map[string]string{
		"sub-north": "north@example.org", "sub-south": "south@example.org",
		"registrar-1": "registrar@example.org",
	} {
		if _, err := h.reg.SeeIdentity(sub, email, strings.TrimPrefix(sub, "sub-")); err != nil {
			t.Fatal(err)
		}
	}
	out.take()

	// Auto-approved: proposed (nobody is named for it) then approved, to the
	// managers whose scope admits the fleet, and only them. A member of
	// the organisation with no address is skipped.
	record(t, h, "record_fleet", map[string]any{"fleet_number": "F-1", "operator": "ORG-NORTH"})
	got := out.take()
	if len(got) != 1 || got[0].Event != pack.EventApproved || got[0].Template != "fleet-recorded" ||
		got[0].Key != "F-1" || got[0].ClassTitle != "Fleet" || !slices.Equal(emails(got[0]), []string{"north@example.org"}) {
		t.Fatalf("approved: %+v", got)
	}

	// A proposal under review: the managers in scope, and the proposer.
	registrar := h.principal("registrar-1", "registrar")
	h.tick()
	prop, err := h.reg.Propose(registrar, "appoint_driver", register.ProposeRequest{Payload: map[string]any{"ref": "DA-1", "fleet_number": "F-1"}})
	if err != nil {
		t.Fatal(err)
	}
	got = out.take()
	if len(got) != 1 || got[0].Event != pack.EventProposed || got[0].Key != "DA-1" ||
		!slices.Equal(emails(got[0]), []string{"registrar@example.org", "north@example.org"}) {
		t.Fatalf("proposed: %+v", got)
	}

	// Returned, with the reviewer's reason, to the proposer.
	h.tick()
	if _, err := h.reg.Return(h.principal("registrar-2", "registrar"), prop.Task.ID, "Which depot?"); err != nil {
		t.Fatal(err)
	}
	got = out.take()
	if len(got) != 1 || got[0].Event != pack.EventReturned || got[0].Reason != "Which depot?" ||
		!slices.Equal(emails(got[0]), []string{"registrar@example.org"}) {
		t.Fatalf("returned: %+v", got)
	}

	// The history says how many people a notice reached, never who.
	txn, err := h.reg.RecordNotified(got[0], 1)
	if err != nil || !strings.HasPrefix(txn.Envelope.Message, "Notified 1 person: Appoint a driver returned, Driver appointment DA-1") ||
		strings.Contains(txn.Envelope.Message, "@") {
		t.Fatalf("recorded %v: %v", txn, err)
	}
}

func TestNotificationsAreValidatedAtLoad(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    map[string]any
		want string
	}{
		{"unknown workflow", map[string]any{"on": "nope:approved", "template": "t", "to": []any{map[string]any{"proposer": true}}}, `no workflow named "nope"`},
		{"unknown event", map[string]any{"on": "record_fleet:done", "template": "t", "to": []any{map[string]any{"proposer": true}}}, "is not an event"},
		{"template path", map[string]any{"on": "record_fleet:approved", "template": "../x", "to": []any{map[string]any{"proposer": true}}}, "not a plain name"},
		{"no recipient", map[string]any{"on": "record_fleet:approved", "template": "t"}, "name who receives it"},
		{"two in one rule", map[string]any{"on": "record_fleet:approved", "template": "t", "to": []any{map[string]any{"proposer": true, "role": "registrar"}}}, "exactly one"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := pack.Load(carPackWithAppointments(t, func(doc map[string]any) { doc["notifications"] = []any{tc.n} }))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}
