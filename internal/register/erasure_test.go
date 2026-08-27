// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Privasys/container-app-register/internal/canon"
	"github.com/Privasys/container-app-register/internal/register"
)

// Erasure has to be checked from outside the abstractions that create
// the data, because every defect found so far has been a second copy
// somewhere the erasure path did not know about. These tests take the
// ledger apart: they export every leaf and look for the name.

const canary = "CANARY, Distinctive"

// registerCanary puts a subject through the real workflow, which is
// where the personal data enters, and returns their record.
func registerCanary(t *testing.T, h *harness) string {
	t.Helper()
	registrar := h.principal("registrar-1", "registrar")
	h.tick()
	out, err := h.reg.Propose(registrar, "register_owner", register.ProposeRequest{
		Payload: map[string]any{
			"reference": "PTY-9999", "kind": "person", "country": "FR",
			"name": canary, "address": "9 rue Canari, 75009 Paris",
			"email": "canary@example.invalid", "date_of_birth": "1990-01-01",
		},
	})
	if err != nil {
		t.Fatalf("register an owner: %v", err)
	}
	if out.ObjectID == "" {
		t.Fatalf("the proposal produced no record: %+v", out.Task)
	}
	return out.ObjectID
}

// leaksIn reports the ledger leaves whose bytes contain a needle.
func leaksIn(t *testing.T, h *harness, needle string) []string {
	t.Helper()
	operator := h.principal("operator-1", "operator")
	var found []string
	after := ""
	for {
		chunk, err := h.reg.Export(operator, after, 500)
		if err != nil {
			t.Fatalf("export: %v", err)
		}
		for _, leaf := range chunk.Leaves {
			value, err := base64.StdEncoding.DecodeString(leaf.Value)
			if err != nil {
				t.Fatalf("leaf value: %v", err)
			}
			if bytes.Contains(value, []byte(needle)) {
				found = append(found, leaf.Path[:16])
			}
		}
		if chunk.Done {
			return found
		}
		after = chunk.Next
	}
}

// The control. Without it the tests below would pass on a register that
// wrote nothing at all, which is the classic way a leak test lies.
func TestTheLeakSearchFindsWhatIsActuallyThere(t *testing.T) {
	h := newHarness(t)
	registerCanary(t, h)
	if len(leaksIn(t, h, "PTY-9999")) == 0 {
		t.Fatal("the search cannot find a value that is in the clear by design; " +
			"every other test in this file is worthless")
	}
}

// Stronger than the erasure case, and worth stating separately: the
// personal data is never in the clear in the ledger at all. The
// proposal that carries it is sealed on the way in and the record it
// produces is sealed at rest, so there is no window — not between
// propose and approve, not before an erasure — in which a copy of the
// store yields a name.
func TestPersonalDataIsNeverInTheClear(t *testing.T) {
	h := newHarness(t)
	registerCanary(t, h)
	for _, needle := range []string{canary, "rue Canari", "canary@example.invalid"} {
		if leaks := leaksIn(t, h, needle); len(leaks) != 0 {
			t.Errorf("%q is in the clear in %d ledger leaves: %v", needle, len(leaks), leaks)
		}
	}
}

// And a proposal still under review, whose key is very much alive, is
// sealed at rest even though a reviewer can read it.
func TestAProposalUnderReviewIsSealedAtRest(t *testing.T) {
	h := newHarness(t)
	registrar := h.principal("registrar-1", "registrar")

	h.tick()
	_, err := h.reg.Propose(registrar, "register_owner", register.ProposeRequest{
		Payload: map[string]any{
			"reference": "PTY-6666", "kind": "person", "country": "FR",
			"name": "SPECIMEN, Underreview",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if leaks := leaksIn(t, h, "SPECIMEN, Underreview"); len(leaks) != 0 {
		t.Errorf("a proposal holds personal data in the clear in %d leaves: %v", len(leaks), leaks)
	}
}

func TestErasureLeavesNoPlaintextAnywhereInTheLedger(t *testing.T) {
	h := newHarness(t)
	owner := registerCanary(t, h)
	dpo := h.principal("dpo-1", "dpo")

	h.tick()
	if _, err := h.reg.Erase(dpo, register.ErasureRequest{
		ObjectID: owner, PolicyID: "P01", Reason: "Subject request.",
	}); err != nil {
		t.Fatalf("erase: %v", err)
	}

	// Every leaf, not every record: the proposal that created the record
	// and the write set of the transaction that carried it are leaves
	// too, and both used to hold the name in the clear.
	if leaks := leaksIn(t, h, canary); len(leaks) != 0 {
		t.Errorf("the name survives erasure in %d ledger leaves: %v", len(leaks), leaks)
	}
	for _, needle := range []string{"rue Canari", "canary@example.invalid", "1990-01-01"} {
		if leaks := leaksIn(t, h, needle); len(leaks) != 0 {
			t.Errorf("%q survives erasure in %d leaves: %v", needle, len(leaks), leaks)
		}
	}

	// The tombstone survives, because a record that vanished entirely
	// could not be shown to have been erased on purpose.
	if leaks := leaksIn(t, h, "PTY-9999"); len(leaks) == 0 {
		t.Error("the party reference should survive as a tombstone")
	}
}

// The commitment to a payload has to die with the key. An unkeyed
// digest of a name, an address and a date of birth is searchable, so
// keeping one past an erasure keeps the personal data in a form that
// only looks safe.
func TestTheRetainedHashCannotConfirmAGuess(t *testing.T) {
	h := newHarness(t)
	owner := registerCanary(t, h)
	registrar := h.principal("registrar-1", "registrar")

	view, err := h.reg.GetObject(registrar, owner)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	hash := view.Version.PayloadHash
	if !strings.HasPrefix(hash, "hmac-sha256:") {
		t.Fatalf("payload hash = %q, want a keyed commitment for a class carrying personal data", hash)
	}

	// The attack: hash a guessed identity and compare. It must not match,
	// because the commitment is keyed and the guesser has no key.
	guess := map[string]any{
		"reference": "PTY-9999", "kind": "person", "country": "FR",
		"name": canary, "address": "9 rue Canari, 75009 Paris",
		"email": "canary@example.invalid", "date_of_birth": "1990-01-01",
	}
	plaintext, err := canon.Marshal(guess)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(plaintext)
	if strings.Contains(hash, hex.EncodeToString(sum[:])) {
		t.Error("the retained commitment is an unkeyed digest of the payload: a guess confirms it")
	}
	if register.PlainHash(plaintext) == hash {
		t.Error("the retained commitment confirms a guessed identity")
	}
}

// A class with nothing personal in it keeps the plain digest, which is
// what makes a pruned version verifiable against a copy someone holds.
func TestClassesWithoutPersonalDataKeepAPlainDigest(t *testing.T) {
	h := newHarness(t)
	registrar := h.principal("registrar-1", "registrar")
	view, err := h.reg.GetObject(registrar, h.vehicleByVIN("WVWZZZ1JZXW000001"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(view.Version.PayloadHash, "sha256:") {
		t.Errorf("payload hash = %q, want a plain digest", view.Version.PayloadHash)
	}
}

// A proposal is readable while it is being reviewed and unreadable once
// it has been decided: the record is the truth from then on, and a
// second readable copy would sit outside the erasure that covers it.
func TestAProposalIsReadableUnderReviewAndSealedAfterwards(t *testing.T) {
	h := newHarness(t)
	clerk := h.principal("clerk-1", "clerk")
	registrar := h.principal("registrar-1", "registrar")

	h.tick()
	out, err := h.reg.Propose(clerk, "first_registration", register.ProposeRequest{
		Payload:  newVehicle("VF3CCHMZ3PT000055", "EE-555-EE"),
		Evidence: map[string]string{"proof_of_conformity": strings.Repeat("a", 64)},
	})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}

	// A vehicle carries no personal data, so nothing is sealed and the
	// reviewer sees the whole proposal.
	underReview, err := h.reg.Task(registrar, out.Task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if underReview.Payload["vin"] != "VF3CCHMZ3PT000055" {
		t.Errorf("a reviewer cannot see the proposal: %v", underReview.Payload)
	}

	// An owner proposal does carry personal data. Approving it destroys
	// the proposal's key.
	h.tick()
	owner, err := h.reg.Propose(registrar, "register_owner", register.ProposeRequest{
		Payload: map[string]any{
			"reference": "PTY-8888", "kind": "person", "country": "FR",
			"name": "SPECIMEN, Sealed", "address": "1 rue Test, 75001 Paris",
		},
	})
	if err != nil {
		t.Fatalf("register an owner: %v", err)
	}
	decided, err := h.reg.Task(registrar, owner.Task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := decided.Payload["name"]; present {
		t.Error("a decided proposal still serves the personal data it carried")
	}
	if !decided.Redacted {
		t.Error("the withheld half should be reported, not silently dropped")
	}
	if decided.Payload["reference"] != "PTY-8888" {
		t.Error("the non-personal half of a proposal should stay readable")
	}

	// And the record it produced holds the data, properly sealed.
	view, err := h.reg.GetObject(registrar, owner.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if view.Version.Payload["name"] != "SPECIMEN, Sealed" {
		t.Errorf("the record does not hold what the proposal proposed: %v", view.Version.Payload)
	}
}

// A proposal under review must not leak to a reader without clearance.
func TestAProposalUnderReviewRespectsClearance(t *testing.T) {
	h := newHarness(t)
	registrar := h.principal("registrar-1", "registrar")
	auditor := h.principal("auditor-1", "auditor")

	h.tick()
	out, err := h.reg.Propose(registrar, "register_owner", register.ProposeRequest{
		Payload: map[string]any{
			"reference": "PTY-7777", "kind": "person", "country": "FR",
			"name": "SPECIMEN, Private",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	seen, err := h.reg.Task(auditor, out.Task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := seen.Payload["name"]; present {
		t.Error("an uncleared reader saw a proposal's personal data")
	}
	if seen.Payload["reference"] != "PTY-7777" {
		t.Error("the non-personal half should still be readable")
	}
}
