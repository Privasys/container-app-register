// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register

import (
	"fmt"
	"strings"
	"time"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/pack"
	"github.com/Privasys/container-app-register/internal/store"
)

// Deletion in a tamper-evident register.
//
// The claim worth making is not that nothing can be deleted. It is that
// nothing can be *covertly* altered or deleted. Both routes out of this
// file are explicit, signed, policy-gated transactions, and both leave
// the register able to prove what it once held and that it removed it
// on purpose:
//
//   - Retention pruning removes the content of record versions that
//     have passed their policy's window. The versions keep their place
//     in the history; a read of one returns "pruned per policy Pxx",
//     which is a different statement from "no such version".
//   - Erasure destroys a data subject's encryption key. The records
//     stay, their commitments stay, their history stays; what is gone
//     is the ability of anyone, including the register, to read the
//     personal data inside them, in live storage and in every backup at
//     once.

// PruneRequest asks for a retention prune.
type PruneRequest struct {
	// PolicyID names the retention policy being applied.
	PolicyID string `json:"policy_id"`
	// ObjectID narrows the prune to one record. Empty means every
	// record of the policy's class.
	ObjectID string `json:"object_id,omitempty"`
	// Message is the commit message; the policy and horizon are
	// appended to the body.
	Message string `json:"message,omitempty"`
	// DryRun reports what would be pruned and changes nothing.
	DryRun bool `json:"dry_run,omitempty"`
	// CollectHistory also prunes the ledger's own historical versions
	// below the horizon, so the pruned content stops being reachable
	// through a historical read as well as through the current state.
	CollectHistory bool `json:"collect_history,omitempty"`
}

// PruneResult reports what a prune did.
type PruneResult struct {
	PolicyID       string             `json:"policy_id"`
	Horizon        int64              `json:"horizon"`
	Versions       int                `json:"versions"`
	Objects        int                `json:"objects"`
	DryRun         bool               `json:"dry_run"`
	Transaction    *model.Transaction `json:"transaction,omitempty"`
	LedgerVersions uint64             `json:"ledger_versions_collected,omitempty"`
}

// Prune applies a retention policy. Content only ever leaves the
// register through this path: there is no out-of-band delete.
func (r *Register) Prune(p *auth.Principal, req PruneRequest) (*PruneResult, error) {
	if !p.Can(auth.PermRetention) {
		return nil, fmt.Errorf("%s may not run retention", p.Acting)
	}
	policy := r.pk.Policy(req.PolicyID)
	if policy == nil {
		return nil, fmt.Errorf("no retention policy %q", req.PolicyID)
	}
	class := r.pk.Class(policy.Class)
	if class == nil {
		return nil, fmt.Errorf("policy %s targets class %q, which this pack no longer declares",
			policy.ID, policy.Class)
	}

	result := &PruneResult{PolicyID: policy.ID, DryRun: req.DryRun}
	err := r.st.Do(func(tx *store.Tx) error {
		at := r.now()
		horizon := at - int64(policy.WindowDays)*24*3600
		result.Horizon = horizon

		clauses := []string{
			"o.class = " + store.Lit(class.Name),
			"o.tenant = " + store.Lit(p.Tenant),
			"v.created_at < " + store.Lit(horizon),
			"v.pruned = FALSE",
			// The head version of a live record is what the register
			// currently asserts. Retention removes history, not the
			// present: a record whose current version has aged out is
			// pruned by ending the record, not by emptying it.
			"v.version < o.head_version",
		}
		if req.ObjectID != "" {
			clauses = append(clauses, "o.id = "+store.Lit(req.ObjectID))
		}
		if policy.Scope == pack.ScopePII {
			clauses = append(clauses, "v.enc_scope <> "+store.Lit(""))
		}
		rows, err := tx.Query("SELECT v.object_id, v.version FROM `record_versions` AS v " +
			"JOIN `objects` AS o ON o.id = v.object_id WHERE " + strings.Join(clauses, " AND ") +
			" ORDER BY v.object_id, v.version LIMIT 5000")
		if err != nil {
			return err
		}
		objects := map[string]bool{}
		var ops []model.WriteOp
		for i, row := range rows {
			objectID, version := row.Str("object_id"), row.Uint("version")
			objects[objectID] = true
			ops = append(ops,
				model.WriteOp{
					Table: "record_versions",
					Key:   map[string]any{"object_id": objectID, "version": version},
					Values: map[string]any{
						"payload": model.Binary(nil), "pruned": true, "prune_policy": policy.ID,
					},
				},
				model.WriteOp{
					Table: "prune_marks",
					Key:   map[string]any{"txid": model.TxIDPlaceholder, "idx": uint64(i)},
					Values: map[string]any{
						"object_id": objectID, "from_version": version, "to_version": version,
						"policy_id": policy.ID, "reason": "retention", "created_at": at,
					},
				},
			)
		}
		result.Versions, result.Objects = len(rows), len(objects)
		if req.DryRun || len(rows) == 0 {
			return nil
		}

		summary := req.Message
		if summary == "" {
			summary = fmt.Sprintf("Prune %d %s versions per policy %s", len(rows), class.Name, policy.ID)
		}
		env := model.Envelope{
			Kind: model.KindRetentionPrune, Tenant: p.Tenant, Class: class.Name,
			Author: principalAuthor(p), Timestamp: at,
			Message: composeMessage(clip(summary, model.MaxSummary), fmt.Sprintf(
				"Policy %s (%s) keeps %s versions of %s for %d days.\nHorizon %s: everything committed before it is removed.",
				policy.ID, policy.Title, policy.Scope, class.Name, policy.WindowDays,
				time.Unix(horizon, 0).UTC().Format(time.RFC3339))),
		}
		if req.ObjectID != "" {
			env.ObjectIDs = []string{req.ObjectID}
		}
		txn, err := r.commit(tx, env, ops)
		if err != nil {
			return err
		}
		result.Transaction = txn

		if req.CollectHistory {
			// Removing the content from the current state is not enough
			// on its own: the ledger keeps every superseded version, so
			// the horizon has to be applied to the history too.
			stats, err := tx.Ledger().Prune(txn.VersionBefore)
			if err != nil {
				return fmt.Errorf("register: collect ledger history: %w", err)
			}
			result.LedgerVersions = uint64(stats.RecordsDeleted + stats.RootRecordsDeleted)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ErasureRequest asks for a data subject's personal data to be
// destroyed.
type ErasureRequest struct {
	// ObjectID is the data subject's record.
	ObjectID string `json:"object_id"`
	// PolicyID names the retention policy that permits the erasure.
	PolicyID string `json:"policy_id"`
	// Reason is recorded in the commit body: who asked, and under what.
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

// ErasureResult reports an erasure.
type ErasureResult struct {
	ObjectID    string             `json:"object_id"`
	Scope       string             `json:"scope"`
	Versions    int                `json:"versions_affected"`
	Transaction *model.Transaction `json:"transaction"`
}

// Erase destroys the data-encryption key of one data subject and marks
// the record erased.
//
// What survives is deliberate: the record still exists, its versions
// still exist, every commitment still verifies, and the history of what
// the register asserted about that subject is still auditable. What is
// gone is the plaintext, everywhere, at once, including in backups
// taken before the request.
func (r *Register) Erase(p *auth.Principal, req ErasureRequest) (*ErasureResult, error) {
	if !p.Can(auth.PermErasure) {
		return nil, fmt.Errorf("%s may not carry out erasures", p.Acting)
	}
	policy := r.pk.Policy(req.PolicyID)
	if policy == nil {
		return nil, fmt.Errorf("no retention policy %q", req.PolicyID)
	}
	if !policy.Erasure {
		return nil, fmt.Errorf("policy %s does not permit erasure", policy.ID)
	}

	result := &ErasureResult{ObjectID: req.ObjectID, Scope: ""}
	err := r.st.Do(func(tx *store.Tx) error {
		row, err := r.objectRow(tx, p.Tenant, req.ObjectID)
		if err != nil {
			return err
		}
		class := r.pk.Class(row.Str("class"))
		if class == nil {
			return fmt.Errorf("this register no longer declares class %q", row.Str("class"))
		}
		if class.Name != policy.Class {
			return fmt.Errorf("policy %s covers %s records, and %s is a %s",
				policy.ID, policy.Class, req.ObjectID, class.Name)
		}
		if class.Encryption != pack.EncSubject {
			return fmt.Errorf("%s records do not have a key per subject, so erasing one "+
				"would erase every record sharing its key", class.Name)
		}
		if row.Bool("erased") {
			return fmt.Errorf("%s has already been erased", req.ObjectID)
		}
		scope := r.dekScope(p.Tenant, class, req.ObjectID)
		result.Scope = scope

		key, err := tx.QueryOne("SELECT destroyed_at FROM `dek_keys` WHERE scope = " + store.Lit(scope))
		if err != nil {
			return err
		}
		if key == nil {
			return fmt.Errorf("%s has no personal data to erase", req.ObjectID)
		}
		affected, err := tx.Count("SELECT COUNT(*) FROM `record_versions` WHERE enc_scope = " + store.Lit(scope))
		if err != nil {
			return err
		}
		result.Versions = int(affected)

		at := r.now()
		ops := []model.WriteOp{
			{
				Table: "dek_keys",
				Key:   map[string]any{"scope": scope},
				Values: map[string]any{
					// Both wraps go: the operational one the register
					// uses, and the recovery one the customer holds.
					// Leaving either would make the erasure a promise
					// rather than a fact.
					"op_wrap": model.Binary(nil), "rec_wrap": model.Binary(nil), "destroyed_at": at,
				},
			},
			{
				Table:  "objects",
				Key:    map[string]any{"id": req.ObjectID},
				Values: map[string]any{"erased": true, "updated_at": at, "updated_tx": model.TxIDPlaceholder},
			},
			{
				Table: "prune_marks",
				Key:   map[string]any{"txid": model.TxIDPlaceholder, "idx": uint64(0)},
				Values: map[string]any{
					"object_id": req.ObjectID, "from_version": uint64(1),
					"to_version": row.Uint("head_version"), "policy_id": policy.ID,
					"reason": "erasure", "created_at": at,
				},
			},
		}
		summary := req.Message
		if summary == "" {
			summary = fmt.Sprintf("Erase personal data of %s", req.ObjectID)
		}
		env := model.Envelope{
			Kind: model.KindErasure, Tenant: p.Tenant, Class: class.Name,
			ObjectIDs: []string{req.ObjectID}, Author: principalAuthor(p), Timestamp: at,
			Message: composeMessage(clip(summary, model.MaxSummary), composeMessage(req.Reason, fmt.Sprintf(
				"Key %s destroyed under policy %s (%s). %d record versions are affected; "+
					"their commitments and history are unchanged and still verify.",
				scope, policy.ID, policy.Title, affected))),
		}
		txn, err := r.commit(tx, env, ops)
		if err != nil {
			return err
		}
		result.Transaction = txn
		r.ring.Forget(scope)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// PruneHorizon reports, per policy, the moment before which content is
// eligible for removal, and how much is currently past it. It is the
// report an operator needs to answer "when will this be gone
// everywhere".
type PruneHorizon struct {
	PolicyID string `json:"policy_id"`
	Title    string `json:"title"`
	Class    string `json:"class"`
	Scope    string `json:"scope"`
	Days     int    `json:"window_days"`
	Horizon  int64  `json:"horizon"`
	Eligible int64  `json:"eligible_versions"`
	Pruned   int64  `json:"pruned_versions"`
}

// Horizons reports the retention position of every policy.
func (r *Register) Horizons(p *auth.Principal) ([]PruneHorizon, error) {
	if !p.Can(auth.PermRetention) && !p.Can(auth.PermExplorer) {
		return nil, fmt.Errorf("%s may not read the retention report", p.Acting)
	}
	out := make([]PruneHorizon, 0, len(r.pk.Retention))
	err := r.st.Do(func(tx *store.Tx) error {
		now := r.now()
		for _, policy := range r.pk.Retention {
			h := PruneHorizon{
				PolicyID: policy.ID, Title: policy.Title, Class: policy.Class,
				Scope: policy.Scope, Days: policy.WindowDays,
				Horizon: now - int64(policy.WindowDays)*24*3600,
			}
			eligible, err := tx.Count("SELECT COUNT(*) FROM `record_versions` AS v JOIN `objects` AS o " +
				"ON o.id = v.object_id WHERE o.class = " + store.Lit(policy.Class) +
				" AND v.created_at < " + store.Lit(h.Horizon) +
				" AND v.pruned = FALSE AND v.version < o.head_version")
			if err != nil {
				return err
			}
			pruned, err := tx.Count("SELECT COUNT(*) FROM `record_versions` WHERE prune_policy = " + store.Lit(policy.ID))
			if err != nil {
				return err
			}
			h.Eligible, h.Pruned = eligible, pruned
			out = append(out, h)
		}
		return nil
	})
	return out, err
}
