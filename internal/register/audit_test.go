// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register_test

import (
	"strings"
	"testing"

	"github.com/Privasys/container-app-register/internal/checkpoint"
	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/register"
)

// The lineage chain is what turns proofs about individual facts into an
// audit. These tests are mostly about the negative case: a chain that
// accepts a rewritten history proves nothing at all.

func TestLineageHeadIsBoundToTheLiveRoot(t *testing.T) {
	h := newHarness(t)
	auditor := h.principal("auditor-1", "auditor")

	lineage, err := h.reg.Lineage(auditor)
	if err != nil {
		t.Fatalf("lineage: %v", err)
	}
	if !lineage.Enabled {
		t.Fatal("a register created now should maintain the lineage chain")
	}
	if len(lineage.Head) != 64 {
		t.Fatalf("head = %q", lineage.Head)
	}

	// The head is an ordinary leaf, so it comes with a proof that binds
	// it to the root. That is what stops the register asserting whatever
	// head happens to suit it.
	bundle := &model.EvidenceBundle{
		Present: true, Root: lineage.Root, Path: lineage.Path, Proof: lineage.Proof,
	}
	if err := checkpoint.VerifyBundleProof(bundle); err != nil {
		t.Errorf("the head is not bound to the live root: %v", err)
	}
}

func TestCheckpointsAnchorTheLineage(t *testing.T) {
	h := newHarness(t)
	h.tick()
	first, err := h.reg.IssueCheckpoint(register.ReasonManual)
	if err != nil {
		t.Fatal(err)
	}
	if first.Checkpoint.Head == "" {
		t.Fatal("a checkpoint should anchor the lineage, not just the state")
	}

	auditor := h.principal("auditor-1", "auditor")
	lineage, err := h.reg.Lineage(auditor)
	if err != nil {
		t.Fatal(err)
	}
	if first.Checkpoint.Head != lineage.Head {
		t.Errorf("the anchor head %s is not the live head %s",
			first.Checkpoint.Head, lineage.Head)
	}
}

// The whole point: an auditor holding two signed anchors and the public
// roots between them recomputes the chain themselves, with no
// commitment key and no trust in the register.
func TestAnAuditorVerifiesLineageWithoutTheRegister(t *testing.T) {
	h := newHarness(t)
	operator := h.principal("operator-1", "operator")
	registrar := h.principal("registrar-1", "registrar")

	h.tick()
	from, err := h.reg.IssueCheckpoint(register.ReasonManual)
	if err != nil {
		t.Fatal(err)
	}

	// Real work happens between the two anchors.
	h.tick()
	if _, err := h.reg.Propose(registrar, "register_lien", register.ProposeRequest{
		Payload: map[string]any{
			"vehicle_id": h.vehicleByVIN("WVWZZZ1JZXW000001"),
			"lender":     "Specimen Finance", "secured_on": "2026-02-02",
		},
	}); err != nil {
		t.Fatal(err)
	}
	h.tick()
	to, err := h.reg.IssueCheckpoint(register.ReasonManual)
	if err != nil {
		t.Fatal(err)
	}
	if to.Checkpoint.Version <= from.Checkpoint.Version {
		t.Fatal("the second anchor should be later")
	}

	roots, err := h.reg.Roots(operator, from.Checkpoint.Version, to.Checkpoint.Version)
	if err != nil {
		t.Fatalf("roots: %v", err)
	}
	if got, want := len(roots.Roots), int(to.Checkpoint.Version-from.Checkpoint.Version); got != want {
		t.Fatalf("got %d roots for %d versions", got, want)
	}

	if err := register.VerifyAnchors(&from.Checkpoint, &to.Checkpoint, roots.Roots); err != nil {
		t.Fatalf("the recorded roots do not lead from one anchor to the other: %v", err)
	}

	// A history that is not the one the later anchor commits to must be
	// refused. Substituting a single root is the cheapest rewrite there
	// is, and it has to fail.
	tampered := append([]string(nil), roots.Roots...)
	tampered[len(tampered)/2] = strings.Repeat("0", 64)
	if err := register.VerifyAnchors(&from.Checkpoint, &to.Checkpoint, tampered); err == nil {
		t.Error("a substituted root was accepted; the lineage check proves nothing")
	}

	// Dropping a version must fail too: a shortened history is a
	// rewritten one.
	if err := register.VerifyAnchors(&from.Checkpoint, &to.Checkpoint, roots.Roots[1:]); err == nil {
		t.Error("a shortened root sequence was accepted")
	}

	// And reordering, which preserves the multiset but not the lineage.
	if len(roots.Roots) > 2 {
		swapped := append([]string(nil), roots.Roots...)
		swapped[0], swapped[1] = swapped[1], swapped[0]
		if err := register.VerifyAnchors(&from.Checkpoint, &to.Checkpoint, swapped); err == nil {
			t.Error("a reordered root sequence was accepted")
		}
	}
}

func TestRegisterCanVerifyItsOwnLineage(t *testing.T) {
	h := newHarness(t)
	operator := h.principal("operator-1", "operator")

	if err := h.reg.VerifyLineage(operator, 0, strings.Repeat("0", 64)); err != nil {
		t.Fatalf("lineage from genesis: %v", err)
	}

	h.tick()
	anchor, err := h.reg.IssueCheckpoint(register.ReasonManual)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.reg.VerifyLineage(operator, anchor.Checkpoint.Version, anchor.Checkpoint.Head); err != nil {
		t.Fatalf("lineage from the anchor: %v", err)
	}
	if err := h.reg.VerifyLineage(operator, anchor.Checkpoint.Version, strings.Repeat("a", 64)); err == nil {
		t.Error("a fabricated anchor head verified")
	}
}

func TestTransitionsReportChangesWithoutServingContent(t *testing.T) {
	h := newHarness(t)
	auditor := h.principal("auditor-1", "auditor")
	operator := h.principal("operator-1", "operator")

	status, err := h.reg.Status()
	if err != nil {
		t.Fatal(err)
	}
	transition, err := h.reg.ChangesAt(auditor, status.LedgerVersion, false)
	if err != nil {
		t.Fatalf("changes: %v", err)
	}
	if len(transition.Changes) == 0 {
		t.Fatal("the last commit changed nothing")
	}
	for _, c := range transition.Changes {
		if len(c.Path) != 64 {
			t.Errorf("path = %q, want a 32-byte hash", c.Path)
		}
		if c.Value != "" {
			t.Error("a caller without clearance was served raw values")
		}
		if !c.Deleted && c.Digest == "" {
			t.Error("a put with no digest is not auditable")
		}
	}

	// Raw values need both the administrative permission and clearance
	// for personal data, because a ledger value is a row and rows carry
	// personal data.
	if _, err := h.reg.ChangesAt(auditor, status.LedgerVersion, true); err == nil {
		t.Error("an auditor without personal-data clearance was allowed raw values")
	}
	if _, err := h.reg.ChangesAt(operator, status.LedgerVersion, true); err == nil {
		t.Error("the operator role has no personal-data clearance and should be refused")
	}
}

func TestAuditVerifiesBeforeItCollects(t *testing.T) {
	h := newHarness(t)
	dpo := h.principal("dpo-1", "dpo")
	operator := h.principal("operator-1", "operator")

	// Closing an audit both attests and destroys, so it needs the
	// checkpoint permission and the retention one. The data protection
	// officer runs erasures but signs nothing; the auditor reads
	// everything but collects nothing. Neither can close on their own.
	h.tick()
	if _, err := h.reg.Audit(dpo, register.AuditRequest{}); err == nil {
		t.Error("the data protection officer signs no anchors and should not close an audit")
	}
	auditor := h.principal("auditor-1", "auditor")
	if _, err := h.reg.Audit(auditor, register.AuditRequest{}); err == nil {
		t.Error("the auditor collects no history and should not close an audit")
	}

	// A false anchor must stop the audit before anything is collected.
	h.tick()
	if _, err := h.reg.Audit(operator, register.AuditRequest{
		FromVersion: 1, FromHead: strings.Repeat("b", 64), Collect: true,
	}); err == nil {
		t.Fatal("an audit from a fabricated anchor was accepted")
	}

	h.tick()
	result, err := h.reg.Audit(operator, register.AuditRequest{Collect: true})
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !result.Verified || result.Anchor == nil {
		t.Fatalf("audit produced no verified anchor: %+v", result)
	}
	if !result.Collected {
		t.Error("the audit did not collect the history it vouched for")
	}
	if result.Anchor.Checkpoint.Head == "" {
		t.Error("the audit anchor carries no head")
	}
	if result.Transaction == nil || result.Transaction.Envelope.Kind != model.KindAudit {
		t.Error("closing an audit should itself be a transaction")
	}

	// The register still works, and the new anchor is a valid starting
	// point for the next audit.
	h.tick()
	if err := h.reg.VerifyLineage(operator,
		result.Anchor.Checkpoint.Version, result.Anchor.Checkpoint.Head); err != nil {
		t.Errorf("lineage from the new anchor: %v", err)
	}
}
