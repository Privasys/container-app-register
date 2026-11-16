// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register_test

import (
	"encoding/json"
	"testing"

	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/register"
)

// The car register with organisations, a registrar who sees who acted, and
// an auditor who reads the log and no record.
func carPackWithActors(t *testing.T) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(carPackWithOrganisations(t), &doc); err != nil {
		t.Fatal(err)
	}
	for _, r := range doc["roles"].([]any) {
		if role := r.(map[string]any); role["name"] == "registrar" {
			role["history_actors"] = true
		}
	}
	doc["roles"] = append(doc["roles"].([]any), map[string]any{
		"name": "auditor_log", "title": "Log auditor", "oidc_roles": []any{"register:auditor_log"},
		"permissions": []any{"explorer", "proofs", "checkpoints"},
	})
	out, _ := json.Marshal(doc)
	return out
}

// A role that sees actors is shown who made each change, by name, with the
// organisation they acted for, recorded with the change; other roles see
// a subject and a role only.
func TestAHistoryNamesWhoActed(t *testing.T) {
	h := newHarnessWith(t, t.TempDir(), carPackWithActors(t))
	recordOrganisations(t, h, "ORG-NORTH")
	join(t, h, "operator-1", "sub-north-1", register.InviteRequest{Role: "police", Organisation: "ORG-NORTH"})
	if _, err := h.reg.SeeIdentity("sub-north-1", "north@example.org", "Ada North"); err != nil {
		t.Fatal(err)
	}
	vehicle := h.vehicleByVIN("WVWZZZ1JZXW000001")
	h.tick()
	out, err := h.reg.Propose(h.principal("sub-north-1", "police"), "flag_stolen", register.ProposeRequest{
		ObjectID: vehicle, Payload: map[string]any{"report_reference": "PR-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := out.Transaction.Envelope.Author.Organisation; got != "ORG-NORTH" {
		t.Fatalf("the change records organisation %q", got)
	}

	registrar := h.principal("registrar-1", "registrar")
	actors, err := h.reg.Actors(registrar, []*model.Transaction{out.Transaction, out.Applied})
	if err != nil {
		t.Fatal(err)
	}
	found := actors[out.Transaction.TxID]
	if found == nil || found.Name != "Ada North" || found.Email != "north@example.org" ||
		found.Organisation != "ORG-NORTH" || found.OrganisationName == "" {
		t.Fatalf("actor %+v", found)
	}
	if a := actors[out.Applied.TxID]; a != nil {
		t.Fatalf("an approval under policy has an actor: %+v", a)
	}
	// The record's history shows the version and who wrote it: here the
	// policy, which is no person.
	history, err := h.reg.History(registrar, vehicle)
	if err != nil || len(history) == 0 {
		t.Fatal(err)
	}
	filed := false
	for _, e := range history {
		if e.Actor != nil {
			t.Fatalf("history entry with an actor %+v", e.Actor)
		}
		// The version the approval wrote names who filed what it approved.
		if e.ProposerActor != nil {
			if e.ProposerActor.Name != "Ada North" || e.ProposerActor.Organisation != "ORG-NORTH" {
				t.Fatalf("proposer %+v", e.ProposerActor)
			}
			filed = true
		}
	}
	if !filed {
		t.Fatal("the history does not say who filed the change")
	}
	clerkHistory, err := h.reg.History(h.principal("clerk-1", "clerk"), vehicle)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range clerkHistory {
		if e.ProposerActor != nil || e.Actor != nil {
			t.Fatalf("a role without actors saw who acted: %+v", e)
		}
	}
	if none, err := h.reg.Actors(h.principal("clerk-1", "clerk"), []*model.Transaction{out.Transaction}); err != nil || none != nil {
		t.Fatalf("a role without actors saw %+v %v", none, err)
	}
	detail, err := h.reg.Transaction(h.principal("registrar-1", "registrar"), out.Transaction.TxID)
	if err != nil || detail.Actor == nil || detail.Actor.Name != "Ada North" {
		t.Fatalf("transaction detail actor %+v %v", detail, err)
	}
}

// The log serves what a change wrote only to a reader of what it wrote: an
// auditor who reads no record sees each write's table, key and a summary.
func TestTheLogShowsWritesOnlyToTheirReaders(t *testing.T) {
	h := newHarnessWith(t, t.TempDir(), carPackWithActors(t))
	vehicle := h.vehicleByVIN("WVWZZZ1JZXW000001")
	h.tick()
	out, err := h.reg.Propose(h.principal("police-1", "police"), "flag_stolen", register.ProposeRequest{
		ObjectID: vehicle, Payload: map[string]any{"report_reference": "PR-2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	txid := out.Applied.TxID
	auditor, err := h.reg.Transaction(h.principal("auditor-1", "auditor_log"), txid)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range auditor.WriteSet {
		if op.Values != nil {
			t.Fatalf("the auditor read the values of %s", op.Table)
		}
		if op.Summary == nil || op.Summary.Digest == "" || op.Table == "" || len(op.Key) == 0 {
			t.Fatalf("summary missing for %+v", op)
		}
	}
	registrar, err := h.reg.Transaction(h.principal("registrar-1", "registrar"), txid)
	if err != nil {
		t.Fatal(err)
	}
	shown := false
	for _, op := range registrar.WriteSet {
		if op.Table == "objects" && op.Values != nil {
			shown = true
		}
	}
	if !shown {
		t.Fatal("a reader of the record did not see what was written to it")
	}
	log, err := h.reg.Log(h.principal("auditor-1", "auditor_log"), register.LogFilter{Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	for _, txn := range log {
		for _, op := range txn.WriteSet {
			if op.Values != nil {
				t.Fatalf("the log gave the auditor the values of %s", op.Table)
			}
		}
	}
}
