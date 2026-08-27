// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	ledger "github.com/Privasys/immutable-ledger/ledger"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/store"
)

// The audit surface.
//
// Proofs answer questions an auditor thinks to ask. They do not show
// that the auditor has been shown everything, and they say nothing
// about how the state got here. The ledger's lineage chain closes both
// gaps: every commit extends a hash chain over the root sequence, and
// the head is itself a leaf, so the live root commits to the entire
// lineage. Fabricating a different history that ends at the same head
// is a preimage attack.
//
// What makes this usable by a third party is that the link function is
// pure and the values are not secret. An auditor given two signed
// anchors and the roots between them recomputes the chain themselves,
// with no commitment key and no trust in the register. That is the
// difference between an audit and a demonstration.

// Lineage is the register's current position in its own history.
type Lineage struct {
	Enabled bool   `json:"enabled"`
	Head    string `json:"head,omitempty"`
	Version uint64 `json:"version"`
	Root    string `json:"root"`
	// Proof binds the head to the live root: it is the inclusion proof
	// for the reserved chain-head leaf, verifiable with no key.
	Path  string `json:"path,omitempty"`
	Proof string `json:"proof,omitempty"`
	// Anchor is the latest signed checkpoint, which carries the same
	// head and is what an auditor should keep.
	Anchor *model.SignedCheckpoint `json:"anchor,omitempty"`
}

// Lineage returns the chain head with the proof that binds it to the
// live root.
func (r *Register) Lineage(p *auth.Principal) (*Lineage, error) {
	if !p.Can(auth.PermCheckpoints) && !p.Can(auth.PermProofs) {
		return nil, fmt.Errorf("%s may not read the lineage", p.Acting)
	}
	out := &Lineage{}
	err := r.st.Do(func(tx *store.Tx) error {
		out.Enabled = tx.HistoryEnabled()
		if !out.Enabled {
			return nil
		}
		head, version, err := tx.HistoryHead()
		if err != nil {
			return err
		}
		out.Head, out.Version = head, version
		out.Root, _ = tx.Root()

		path, proof, err := tx.HistoryKeyProof()
		if err != nil {
			return err
		}
		out.Path = hex.EncodeToString(path[:])
		out.Proof = hex.EncodeToString(proof.Encode())
		return nil
	})
	if err != nil {
		return nil, err
	}
	out.Anchor = r.LatestCheckpoint()
	return out, nil
}

// RootRange is the recorded root sequence between two versions, which
// is what an auditor folds through the link function to recompute a
// lineage for themselves.
type RootRange struct {
	From  uint64   `json:"from_version"`
	To    uint64   `json:"to_version"`
	Roots []string `json:"roots"`
}

// MaxRootRange caps one request. Roots are 32 bytes each; a wider range
// is fetched in pages.
const MaxRootRange = 5000

// Roots returns the roots recorded for versions (from, to]. Roots and
// heads are not secret — they are hashes of state, not state — so this
// needs no more permission than reading a proof.
func (r *Register) Roots(p *auth.Principal, from, to uint64) (*RootRange, error) {
	if !p.Can(auth.PermProofs) && !p.Can(auth.PermCheckpoints) {
		return nil, fmt.Errorf("%s may not read the root sequence", p.Acting)
	}
	out := &RootRange{From: from, To: to}
	err := r.st.Do(func(tx *store.Tx) error {
		_, current := tx.Root()
		if to == 0 || to > current {
			to = current
			out.To = to
		}
		if from > to {
			return fmt.Errorf("from_version %d is after to_version %d", from, to)
		}
		if to-from > MaxRootRange {
			return fmt.Errorf("range of %d versions exceeds the %d this endpoint serves at once",
				to-from, MaxRootRange)
		}
		for v := from + 1; v <= to; v++ {
			root, err := tx.RootAt(v)
			if err != nil {
				return fmt.Errorf("version %d: %w (history before the last audit is pruned)", v, err)
			}
			out.Roots = append(out.Roots, root)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// VerifyLineage has the register check its own lineage from an anchor.
//
// This is the convenient answer, not the authoritative one: it is the
// register vouching for itself. The authoritative check is an auditor
// folding Roots through the link function against two signed anchors,
// which is what register-verify does.
func (r *Register) VerifyLineage(p *auth.Principal, fromVersion uint64, fromHead string) error {
	if !p.Can(auth.PermCheckpoints) {
		return fmt.Errorf("%s may not verify the lineage", p.Acting)
	}
	return r.st.Do(func(tx *store.Tx) error {
		return tx.VerifyHistory(fromVersion, fromHead)
	})
}

// Transition is what one commit changed, in the form an auditor can use
// without being handed the contents of the register.
type Transition struct {
	Version uint64   `json:"version"`
	Root    string   `json:"root"`
	Changes []Change `json:"changes"`
}

// Change is one leaf-level difference. Path is a keyed hash, so the
// logical key is not recoverable from it.
//
// Values are summarised rather than served by default. A ledger value
// is a raw row, and rows carry personal data; an auditor confirming
// that two independent copies of the register agree needs the digest,
// not the contents. Contents remain available through the record and
// proof surfaces, which are role-aware and redact.
type Change struct {
	Path    string `json:"path"`
	Deleted bool   `json:"deleted,omitempty"`
	Bytes   int    `json:"bytes,omitempty"`
	Digest  string `json:"digest,omitempty"`
	Value   string `json:"value,omitempty"`
}

// ChangesAt reports what the commit producing version changed. Contents
// are included only for a caller cleared to see personal data, and only
// when asked for.
func (r *Register) ChangesAt(p *auth.Principal, version uint64, withValues bool) (*Transition, error) {
	if !p.Can(auth.PermExplorer) && !p.Can(auth.PermProofs) {
		return nil, fmt.Errorf("%s may not read transitions", p.Acting)
	}
	if withValues && !(p.PII && p.Can(auth.PermAdmin)) {
		return nil, fmt.Errorf("%s may not read raw values: that needs both the administrative "+
			"permission and clearance for personal data", p.Acting)
	}
	out := &Transition{Version: version}
	err := r.st.Do(func(tx *store.Tx) error {
		changes, err := tx.ChangesAt(version)
		if err != nil {
			return err
		}
		out.Root, err = tx.RootAt(version)
		if err != nil {
			return err
		}
		for _, c := range changes {
			entry := Change{Path: hex.EncodeToString(c.Path[:]), Deleted: c.Deleted}
			if !c.Deleted {
				sum := sha256.Sum256(c.Value)
				entry.Bytes = len(c.Value)
				entry.Digest = hex.EncodeToString(sum[:])
				if withValues {
					entry.Value = hex.EncodeToString(c.Value)
				}
			}
			out.Changes = append(out.Changes, entry)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AuditRequest asks the register to close an audit period.
type AuditRequest struct {
	// FromVersion and FromHead are the previous audit's anchor. Zero and
	// empty audit from genesis.
	FromVersion uint64 `json:"from_version"`
	FromHead    string `json:"from_head,omitempty"`
	// Collect prunes the audited history once the anchor is signed.
	// Until this runs, superseded and erased content is still present in
	// the ledger's history: the audit cadence is the erasure latency.
	Collect bool   `json:"collect,omitempty"`
	Message string `json:"message,omitempty"`
}

// AuditResult reports a closed audit period.
type AuditResult struct {
	Verified       bool                    `json:"verified"`
	FromVersion    uint64                  `json:"from_version"`
	ToVersion      uint64                  `json:"to_version"`
	Anchor         *model.SignedCheckpoint `json:"anchor"`
	Collected      bool                    `json:"collected"`
	RecordsRemoved uint64                  `json:"records_removed,omitempty"`
	Transaction    *model.Transaction      `json:"transaction,omitempty"`
}

// Audit closes an audit period: verify the lineage from the previous
// anchor, sign a new one, and optionally prune everything the new
// signature now vouches for.
//
// The order matters and is not negotiable. Pruning first would destroy
// the root records the verification walks, so a register that pruned
// before verifying could never prove the lineage it was about to
// discard. Verification therefore gates the prune, and a failure leaves
// the history intact.
func (r *Register) Audit(p *auth.Principal, req AuditRequest) (*AuditResult, error) {
	if !p.Can(auth.PermCheckpoints) || !p.Can(auth.PermRetention) {
		return nil, fmt.Errorf("%s may not close an audit: it needs both the checkpoint "+
			"and the retention permissions", p.Acting)
	}
	result := &AuditResult{FromVersion: req.FromVersion}

	err := r.st.Do(func(tx *store.Tx) error {
		if !tx.HistoryEnabled() {
			return fmt.Errorf("this register has no lineage chain, so there is nothing to audit " +
				"against; the chain is fixed when a register is created")
		}
		if err := tx.VerifyHistory(req.FromVersion, req.FromHead); err != nil {
			return fmt.Errorf("lineage from version %d does not verify: %w", req.FromVersion, err)
		}
		result.Verified = true

		// The anchor is an ordinary checkpoint: it already carries the
		// root, the version and the head, which is exactly what the
		// next audit needs to verify from.
		anchor, err := r.issueCheckpoint(tx, ReasonAudit)
		if err != nil {
			return err
		}
		if anchor == nil {
			anchor = r.LatestCheckpoint()
		}
		if anchor == nil {
			return fmt.Errorf("the audit produced no anchor")
		}
		result.Anchor = anchor
		result.ToVersion = anchor.Checkpoint.Version

		at := r.now()
		summary := req.Message
		if summary == "" {
			summary = fmt.Sprintf("Close audit at version %d", result.ToVersion)
		}
		body := fmt.Sprintf(
			"Lineage verified from version %d to %d against the anchored head.\nRoot %s.\nHead %s.",
			req.FromVersion, result.ToVersion, anchor.Checkpoint.Root, anchor.Checkpoint.Head)
		if req.Collect {
			body += "\nAudited history collected: superseded and erased content before this " +
				"version is physically removed, and this anchor stands in for it."
		}
		env := model.Envelope{
			Kind: model.KindAudit, Tenant: p.Tenant, Author: principalAuthor(p), Timestamp: at,
			Message: composeMessage(clip(summary, model.MaxSummary), body),
		}
		txn, err := r.commit(tx, env, nil)
		if err != nil {
			return err
		}
		result.Transaction = txn

		if req.Collect {
			stats, err := tx.Ledger().Prune(result.ToVersion)
			if err != nil {
				return fmt.Errorf("collect audited history: %w", err)
			}
			result.Collected = true
			result.RecordsRemoved = uint64(stats.RecordsDeleted + stats.RootRecordsDeleted)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if r.notify != nil && result.Anchor != nil {
		r.notify.CheckpointIssued(result.Anchor)
	}
	return result, nil
}

// VerifyAnchors is the offline check an auditor performs, exposed here
// so the register, the verifier and the tests share one implementation.
//
// It takes two signed anchors and the roots recorded between them, and
// recomputes the chain. It needs no commitment key and no store: the
// link function is pure, and roots and heads are not secret. This is
// the check that makes an auditor independent.
func VerifyAnchors(from, to *model.Checkpoint, roots []string) error {
	if from.Head == "" || to.Head == "" {
		return fmt.Errorf("lineage: an anchor without a head cannot be chained; " +
			"this register predates the lineage chain")
	}
	if to.Version < from.Version {
		return fmt.Errorf("lineage: the later anchor is at version %d, before %d",
			to.Version, from.Version)
	}
	if got := len(roots); uint64(got) != to.Version-from.Version {
		return fmt.Errorf("lineage: %d roots supplied for %d versions",
			got, to.Version-from.Version)
	}
	head, err := store.ParseHash(from.Head)
	if err != nil {
		return fmt.Errorf("lineage: anchor head: %w", err)
	}
	prevRoot, err := store.ParseHash(from.Root)
	if err != nil {
		return fmt.Errorf("lineage: anchor root: %w", err)
	}
	for i, encoded := range roots {
		version := from.Version + uint64(i) + 1
		head = ledger.HistoryLink(head, prevRoot, version)
		prevRoot, err = store.ParseHash(encoded)
		if err != nil {
			return fmt.Errorf("lineage: root at version %d: %w", version, err)
		}
	}
	want, err := store.ParseHash(to.Head)
	if err != nil {
		return fmt.Errorf("lineage: later anchor head: %w", err)
	}
	if head != want {
		return fmt.Errorf("lineage: the roots from version %d do not lead to the head anchored "+
			"at version %d; the recorded history is not the one that anchor commits to",
			from.Version, to.Version)
	}
	if prevRoot, err = store.ParseHash(to.Root); err != nil {
		return err
	}
	if last := roots; len(last) > 0 {
		final, err := store.ParseHash(last[len(last)-1])
		if err != nil {
			return err
		}
		if final != prevRoot {
			return fmt.Errorf("lineage: the last root in the range is not the root the later " +
				"anchor names")
		}
	}
	return nil
}
