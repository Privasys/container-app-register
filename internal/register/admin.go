// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	ledger "github.com/Privasys/immutable-ledger/ledger"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/byok"
	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/store"
)

// -- customer key enrolment ------------------------------------------------

// EnrolKEK records a customer-held key-encryption key. From then on
// every new data-encryption key is wrapped to it as well as to the
// register's own operational wrapper, so the customer keeps a recovery
// path the operator cannot exercise for them.
//
// Keys already in existence are not re-wrapped: a key enrolled today
// cannot claim custody of something it was not present for, and saying
// so is more useful than a silent partial guarantee.
func (r *Register) EnrolKEK(p *auth.Principal, id, algo, publicKeyB64 string) (*model.Transaction, error) {
	if !p.Can(auth.PermKeys) {
		return nil, fmt.Errorf("%s may not enrol keys", p.Acting)
	}
	public, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return nil, fmt.Errorf("public key must be base64: %w", err)
	}
	kek, err := byok.ParseKEK(id, algo, public)
	if err != nil {
		return nil, err
	}

	var out *model.Transaction
	err = r.st.Do(func(tx *store.Tx) error {
		at := r.now()
		ops := []model.WriteOp{{
			Table: "keks",
			Key:   map[string]any{"id": kek.ID},
			Values: map[string]any{
				"tenant": p.Tenant, "algo": kek.Algorithm, "public_key": model.Binary(kek.PublicKey),
				"enrolled_at": at, "active": true, "txid": model.TxIDPlaceholder,
			},
		}}
		previous, err := tx.Query("SELECT id FROM `keks` WHERE tenant = " + store.Lit(p.Tenant) +
			" AND active = TRUE AND id <> " + store.Lit(kek.ID))
		if err != nil {
			return err
		}
		for _, row := range previous {
			ops = append(ops, model.WriteOp{
				Table:  "keks",
				Key:    map[string]any{"id": row.Str("id")},
				Values: map[string]any{"active": false},
			})
		}
		env := model.Envelope{
			Kind: model.KindKeyEnrol, Tenant: p.Tenant, Author: principalAuthor(p), Timestamp: at,
			Message: fmt.Sprintf("Enrol customer key %s", kek.ID) + "\n\n" +
				fmt.Sprintf("Algorithm %s. Data-encryption keys created from now on carry a recovery "+
					"wrap only the holder of this key can open.", kek.Algorithm),
		}
		txn, err := r.commit(tx, env, ops)
		out = txn
		return err
	})
	return out, err
}

// RecoveryWrap returns the customer's recovery wrap for one key scope,
// so a customer can take custody of the material they are entitled to
// without the register ever holding their private key.
func (r *Register) RecoveryWrap(p *auth.Principal, scope string) (map[string]any, error) {
	if !p.Can(auth.PermKeys) {
		return nil, fmt.Errorf("%s may not read key material", p.Acting)
	}
	var out map[string]any
	err := r.st.Do(func(tx *store.Tx) error {
		row, err := tx.QueryOne("SELECT * FROM `dek_keys` WHERE scope = " + store.Lit(scope) +
			" AND tenant = " + store.Lit(p.Tenant))
		if err != nil {
			return err
		}
		if row == nil {
			return fmt.Errorf("no key for scope %q", scope)
		}
		if row.Int("destroyed_at") != 0 {
			return fmt.Errorf("the key for %s was destroyed on %d", scope, row.Int("destroyed_at"))
		}
		wrap := row.Bytes("rec_wrap")
		if len(wrap) == 0 {
			return fmt.Errorf("no recovery wrap for %s: no customer key was enrolled when it was created", scope)
		}
		out = map[string]any{
			"scope": scope, "kek_id": row.Str("kek_id"), "created_at": row.Int("created_at"),
			"recovery_wrap": base64.StdEncoding.EncodeToString(wrap),
		}
		return nil
	})
	return out, err
}

// -- subscribers -----------------------------------------------------------

// Webhook is a subscriber the register notifies.
type Webhook struct {
	ID      string   `json:"id"`
	Tenant  string   `json:"tenant"`
	URL     string   `json:"url"`
	Events  []string `json:"events,omitempty"`
	Active  bool     `json:"active"`
	Created int64    `json:"created_at"`
	// Secret is returned once, when the subscriber is registered. The
	// register keeps it to sign with and does not serve it again.
	Secret string `json:"secret,omitempty"`
}

// SetWebhook registers or replaces a subscriber.
//
// Registration is state, so it is a transaction like any other. The
// signing secret is not: it is generated here, returned once, and never
// appears in the write set or the log.
func (r *Register) SetWebhook(p *auth.Principal, hook Webhook) (*Webhook, *model.Transaction, error) {
	if !p.Can(auth.PermAdmin) {
		return nil, nil, fmt.Errorf("%s may not manage subscribers", p.Acting)
	}
	if hook.ID == "" || hook.URL == "" {
		return nil, nil, fmt.Errorf("a subscriber needs an id and a url")
	}
	if !strings.HasPrefix(hook.URL, "https://") {
		return nil, nil, fmt.Errorf("a subscriber url must be https")
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, nil, err
	}

	at := r.now()
	out := &Webhook{
		ID: hook.ID, Tenant: p.Tenant, URL: hook.URL, Events: hook.Events,
		Active: hook.Active, Created: at,
		Secret: base64.StdEncoding.EncodeToString(secret),
	}
	var txn *model.Transaction
	err := r.st.Do(func(tx *store.Tx) error {
		ops := []model.WriteOp{{
			Table: "webhooks",
			Key:   map[string]any{"id": hook.ID},
			Values: map[string]any{
				"tenant": p.Tenant, "url": hook.URL, "secret": model.Binary(secret),
				"events": strings.Join(hook.Events, ","), "active": hook.Active,
				"created_at": at, "txid": model.TxIDPlaceholder,
			},
		}}
		env := model.Envelope{
			Kind: model.KindWebhookSet, Tenant: p.Tenant, Author: principalAuthor(p),
			Timestamp: at,
			Message: composeMessage(clip(fmt.Sprintf("Register subscriber %s", hook.ID), model.MaxSummary),
				fmt.Sprintf("Notifications for %s go to %s.\nThe signing secret is generated "+
					"in the enclave and is not part of this record.",
					orDefault(strings.Join(hook.Events, ", "), "every event"), hook.URL)),
		}
		var err error
		txn, err = r.commit(tx, env, ops)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return out, txn, nil
}

// Webhooks lists the subscribers, without their secrets.
func (r *Register) Webhooks(p *auth.Principal) ([]Webhook, error) {
	if !p.Can(auth.PermAdmin) {
		return nil, fmt.Errorf("%s may not manage subscribers", p.Acting)
	}
	rows, err := r.st.Query("SELECT id, tenant, url, events, active, created_at FROM `webhooks` " +
		"WHERE tenant = " + store.Lit(p.Tenant))
	if err != nil {
		return nil, err
	}
	out := make([]Webhook, 0, len(rows))
	for _, row := range rows {
		hook := Webhook{
			ID: row.Str("id"), Tenant: row.Str("tenant"), URL: row.Str("url"),
			Active: row.Bool("active"), Created: row.Int("created_at"),
		}
		if events := row.Str("events"); events != "" {
			hook.Events = strings.Split(events, ",")
		}
		out = append(out, hook)
	}
	return out, nil
}

// -- export and standby ----------------------------------------------------

// ExportChunk is one page of a ledger export.
//
// The export unit is the ledger leaf rather than the volume snapshot:
// a leaf export is engine-portable, restores verifiably entry by entry,
// and produces a store whose root is the root it came from, which is
// exactly the property a standby needs to prove it is a copy and not an
// approximation.
type ExportChunk struct {
	Version uint64                  `json:"version"`
	Root    string                  `json:"root"`
	Leaves  []ExportLeaf            `json:"leaves"`
	Done    bool                    `json:"done"`
	Next    string                  `json:"next,omitempty"`
	Anchor  *model.SignedCheckpoint `json:"anchor,omitempty"`
}

// ExportLeaf is one exported entry. Paths are keyed hashes, so an
// export carries no logical keys and needs none: a restored tree is
// keyed by path exactly as the original was.
type ExportLeaf struct {
	Path  string `json:"path"`
	Value string `json:"value"`
}

// Export streams the ledger's leaves at the current version.
func (r *Register) Export(p *auth.Principal, after string, limit int) (*ExportChunk, error) {
	if !p.Can(auth.PermAdmin) {
		return nil, fmt.Errorf("%s may not export the register", p.Acting)
	}
	var startAfter *ledger.Hash
	if after != "" {
		raw, err := hex.DecodeString(after)
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("the resume position must be a 32-byte hex path")
		}
		var h ledger.Hash
		copy(h[:], raw)
		startAfter = &h
	}
	out := &ExportChunk{}
	err := r.st.Do(func(tx *store.Tx) error {
		root, version := tx.Root()
		out.Root, out.Version = root, version
		leaves, done, err := tx.Ledger().SnapshotLeaves(version, startAfter, clampLimit(limit))
		if err != nil {
			return err
		}
		out.Done = done
		for i := range leaves {
			out.Leaves = append(out.Leaves, ExportLeaf{
				Path:  hex.EncodeToString(leaves[i].Path[:]),
				Value: base64.StdEncoding.EncodeToString(leaves[i].Value),
			})
		}
		if n := len(leaves); n > 0 {
			out.Next = hex.EncodeToString(leaves[n-1].Path[:])
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out.Anchor = r.LatestCheckpoint()
	return out, nil
}

// Import applies an export chunk to a standby's store.
func (r *Register) Import(chunk *ExportChunk) error {
	return r.st.Do(func(tx *store.Tx) error {
		leaves := make([]ledger.Leaf, 0, len(chunk.Leaves))
		for _, l := range chunk.Leaves {
			raw, err := hex.DecodeString(l.Path)
			if err != nil || len(raw) != 32 {
				return fmt.Errorf("register: import: bad leaf path")
			}
			value, err := base64.StdEncoding.DecodeString(l.Value)
			if err != nil {
				return fmt.Errorf("register: import: bad leaf value: %w", err)
			}
			var leaf ledger.Leaf
			copy(leaf.Path[:], raw)
			leaf.Value = value
			leaves = append(leaves, leaf)
		}
		if len(leaves) > 0 {
			if _, _, err := tx.Ledger().RestoreLeaves(leaves); err != nil {
				return fmt.Errorf("register: import: %w", err)
			}
		}
		if !chunk.Done {
			return nil
		}
		if err := tx.Ledger().StampVersion(chunk.Version); err != nil {
			return fmt.Errorf("register: import: stamp version: %w", err)
		}
		root, _ := tx.Root()
		if root != chunk.Root {
			return fmt.Errorf("register: import: restored root %s does not match the source root %s",
				root, chunk.Root)
		}
		return nil
	})
}

// -- status ----------------------------------------------------------------

// Status is the register's health and evidence position, the report
// §9's observability asks for in one place.
type Status struct {
	Name        string `json:"name"`
	Pack        string `json:"pack"`
	PackVersion string `json:"pack_version"`
	Tenant      string `json:"tenant"`
	ImageDigest string `json:"image_digest,omitempty"`
	KeySource   string `json:"commitment_key_source"`
	Root        string `json:"root"`
	// HistoryChain reports whether this register maintains the lineage
	// chain. It is fixed when the store is created; a register without
	// one cannot be audited for lineage, only for state.
	HistoryChain    bool                    `json:"history_chain"`
	HistoryHead     string                  `json:"history_head,omitempty"`
	LedgerVersion   uint64                  `json:"ledger_version"`
	Transactions    int64                   `json:"transactions"`
	Objects         int64                   `json:"objects"`
	PendingTasks    int64                   `json:"pending_tasks"`
	PendingTxns     int64                   `json:"pending_transactions"`
	PrunedVersions  int64                   `json:"pruned_versions"`
	DestroyedKeys   int64                   `json:"destroyed_keys"`
	LastCheckpoint  *model.SignedCheckpoint `json:"last_checkpoint,omitempty"`
	CheckpointKeyID string                  `json:"checkpoint_key_id"`
	CheckpointKey   string                  `json:"checkpoint_public_key"`
}

// Status gathers the register's current position.
func (r *Register) Status() (*Status, error) {
	s := &Status{
		Name: r.opts.Name, Pack: r.pk.Name, PackVersion: r.pk.Version,
		Tenant: r.opts.Tenant, ImageDigest: r.opts.ImageDigest, KeySource: r.opts.KeySource,
	}
	s.CheckpointKeyID, s.CheckpointKey = r.VerificationKey()
	s.LastCheckpoint = r.LatestCheckpoint()
	err := r.st.Do(func(tx *store.Tx) error {
		s.Root, s.LedgerVersion = tx.Root()
		s.HistoryChain = tx.HistoryEnabled()
		s.HistoryHead, _, _ = tx.HistoryHead()
		counts := []struct {
			stmt string
			out  *int64
		}{
			{"SELECT COUNT(*) FROM `transactions`", &s.Transactions},
			{"SELECT COUNT(*) FROM `objects`", &s.Objects},
			{"SELECT COUNT(*) FROM `tasks` WHERE state IN ('awaiting_review','awaiting_counterparty','proposed')", &s.PendingTasks},
			{"SELECT COUNT(*) FROM `transactions` WHERE state = 'pending'", &s.PendingTxns},
			{"SELECT COUNT(*) FROM `record_versions` WHERE pruned = TRUE", &s.PrunedVersions},
			{"SELECT COUNT(*) FROM `dek_keys` WHERE destroyed_at <> 0", &s.DestroyedKeys},
		}
		for _, c := range counts {
			n, err := tx.Count(c.stmt)
			if err != nil {
				return err
			}
			*c.out = n
		}
		return nil
	})
	return s, err
}

// Tasks lists workflow proposals.
func (r *Register) Tasks(p *auth.Principal, state string, limit int) ([]*model.Task, error) {
	clauses := []string{"tenant = " + store.Lit(p.Tenant)}
	if state != "" {
		clauses = append(clauses, "state = "+store.Lit(state))
	}
	if !p.CanOn(auth.PermApprove, "*") && !p.Can(auth.PermExplorer) {
		// A caller who cannot decide proposals sees their own, and the
		// ones waiting on them as counterparty.
		clauses = append(clauses, "(proposer_sub = "+store.Lit(p.Sub)+
			" OR counterparty = "+store.Lit(p.Sub)+")")
	}
	rows, err := r.st.Query(fmt.Sprintf("SELECT * FROM `tasks` WHERE %s ORDER BY updated_at DESC LIMIT %d",
		joinAnd(clauses), clampLimit(limit)))
	if err != nil {
		return nil, err
	}
	out := make([]*model.Task, 0, len(rows))
	err = r.st.Do(func(tx *store.Tx) error {
		for _, row := range rows {
			task, err := decodeTask(row)
			if err != nil {
				return err
			}
			if err := r.openProposal(tx, p, task, row.Bytes("payload")); err != nil {
				return err
			}
			out = append(out, task)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Task returns one proposal.
func (r *Register) Task(p *auth.Principal, id string) (*model.Task, error) {
	var out *model.Task
	err := r.st.Do(func(tx *store.Tx) error {
		task, err := r.taskByIDAs(tx, p, id)
		if err != nil {
			return err
		}
		if task.Tenant != p.Tenant {
			return fmt.Errorf("no proposal %s", id)
		}
		wf := r.pk.Workflow(task.Workflow)
		if wf != nil {
			ctx := r.templateContext(tx, p, task.ID, task.ObjectID, task.Payload)
			blockers, reject, err := r.evaluateConditions(tx, wf, ctx)
			if err != nil {
				return err
			}
			task.Blockers = blockers
			if reject != "" {
				task.Blockers = append(task.Blockers, reject)
			}
		}
		out = task
		return nil
	})
	return out, err
}

func joinAnd(clauses []string) string {
	out := ""
	for i, c := range clauses {
		if i > 0 {
			out += " AND "
		}
		out += c
	}
	return out
}
