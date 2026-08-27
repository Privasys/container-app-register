// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package register is the generic register core: schema-driven records,
// a propose/review/decide workflow primitive, a decorated transaction
// log, retention and erasure, and the signed checkpoints a customer
// holds externally.
//
// # How a change lands
//
// Every state-changing operation is a transaction: a commit envelope
// saying who, when, why and about what, plus a write set of row-level
// effects. The pair is hashed into the transaction id, the transaction
// row is committed first with its write set attached, the write set is
// then applied, and a final commit marks the transaction applied. A
// crash between those points leaves a pending transaction, which the
// next start replays; applying a write set twice produces the same
// rows, so replay is not repair.
//
// The SQL layer commits one statement at a time, which is why a
// governance action is a short ordered sequence of commits rather than
// a single one. The write-ahead order is what makes the sequence safe:
// the ledger never contains an effect whose reason it does not already
// contain.
package register

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/byok"
	"github.com/Privasys/container-app-register/internal/canon"
	"github.com/Privasys/container-app-register/internal/keys"
	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/pack"
	"github.com/Privasys/container-app-register/internal/store"
)

// Options configure a register instance.
type Options struct {
	// Name identifies the register in checkpoints and evidence bundles.
	Name string
	// Tenant is the tenant a caller acts in when they do not name one.
	Tenant string
	// ImageDigest is the measurement of the running build, stamped into
	// every checkpoint.
	ImageDigest string
	// KeySource records how the commitment key was obtained.
	KeySource string
	// Now is the clock, overridable in tests.
	Now func() time.Time
}

// Notifier is told about committed transactions and issued
// checkpoints. The webhook dispatcher implements it; a nil notifier is
// fine.
type Notifier interface {
	TransactionCommitted(tx *model.Transaction)
	CheckpointIssued(sc *model.SignedCheckpoint)
}

// Register is one running register.
type Register struct {
	st   *store.Store
	pk   *pack.Pack
	mat  *keys.Material
	ring *byok.Keyring
	opts Options

	notify Notifier

	// mu guards the in-memory view of the last checkpoint. Ledger
	// serialisation is the store's job.
	mu       sync.RWMutex
	lastCkpt *model.SignedCheckpoint
}

// New brings a register up: it migrates the base tables, replays any
// transaction the last run left pending, then reconciles the store with
// the pack (schemas, query projections, retention policies, seed).
func New(st *store.Store, p *pack.Pack, mat *keys.Material, opts Options) (*Register, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Tenant == "" {
		opts.Tenant = p.Tenant
	}
	if opts.Tenant == "" {
		opts.Tenant = "default"
	}
	ring, err := byok.NewKeyring(mat.Master)
	if err != nil {
		return nil, err
	}
	r := &Register{st: st, pk: p, mat: mat, ring: ring, opts: opts}

	if err := st.Migrate(); err != nil {
		return nil, err
	}
	if err := r.replayPending(); err != nil {
		return nil, err
	}
	if err := r.reconcilePack(); err != nil {
		return nil, err
	}
	if err := r.loadLastCheckpoint(); err != nil {
		return nil, err
	}
	return r, nil
}

// SetNotifier attaches a notifier for committed transactions.
func (r *Register) SetNotifier(n Notifier) { r.notify = n }

// Pack returns the register's pack.
func (r *Register) Pack() *pack.Pack { return r.pk }

// Store returns the underlying store.
func (r *Register) Store() *store.Store { return r.st }

// Options returns the register's options.
func (r *Register) Options() Options { return r.opts }

// Keys returns the sealed key material.
func (r *Register) Keys() *keys.Material { return r.mat }

func (r *Register) now() int64 { return r.opts.Now().UTC().Unix() }

// -- transaction machinery -------------------------------------------------

// pkColumns names the primary-key columns of each table a write set may
// touch. A write set that names anything else is refused: the log
// describes changes to the register's own state, and nothing else.
var pkColumns = map[string][]string{
	"objects":         {"id"},
	"natural_keys":    {"tenant", "class", "natural_key"},
	"record_versions": {"object_id", "version"},
	"schemas":         {"id"},
	"policies":        {"id"},
	"tasks":           {"id"},
	"keks":            {"id"},
	"dek_keys":        {"scope"},
	"prune_marks":     {"txid", "idx"},
	"webhooks":        {"id"},
	"registry":        {"k"},
}

func keyColumnsFor(table string) ([]string, bool) {
	if cols, ok := pkColumns[table]; ok {
		return cols, true
	}
	if strings.HasPrefix(table, "q_") {
		return []string{"object_id"}, true
	}
	return nil, false
}

// commit runs one governance action: validate, write the transaction
// ahead of its effects, apply them, then mark it applied.
func (r *Register) commit(tx *store.Tx, env model.Envelope, ops []model.WriteOp) (*model.Transaction, error) {
	if err := env.Validate(); err != nil {
		return nil, err
	}
	for _, op := range ops {
		if _, ok := keyColumnsFor(op.Table); !ok {
			return nil, fmt.Errorf("register: write set touches unknown table %q", op.Table)
		}
		if len(op.Key) == 0 {
			return nil, fmt.Errorf("register: write set entry for %q has no key", op.Table)
		}
	}

	txid, err := transactionID(env, ops)
	if err != nil {
		return nil, err
	}
	if existing, err := r.transactionByID(tx, txid); err != nil {
		return nil, err
	} else if existing != nil {
		// The same envelope and the same effects at the same instant:
		// a retried request, not a second change.
		return existing, nil
	}

	rootBefore, versionBefore := tx.Root()
	// One SQL transaction, so the whole action is one ledger commit: the
	// transaction row, its effects and the mark that it was applied all
	// land together at versionBefore + 1. Nothing is half-applied, so
	// there is no partial state to recover from and exactly one link is
	// added to the lineage chain.
	if err := tx.Begin(); err != nil {
		return nil, fmt.Errorf("register: open transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	writeSet, err := canon.Marshal(ops)
	if err != nil {
		return nil, err
	}
	envelope, err := canon.Marshal(env)
	if err != nil {
		return nil, err
	}

	objectID := ""
	if len(env.ObjectIDs) > 0 {
		objectID = env.ObjectIDs[0]
	}
	if err := tx.Exec(store.Insert("transactions", map[string]any{
		"txid": txid, "tenant": env.Tenant, "kind": env.Kind,
		"class": env.Class, "object_id": objectID,
		"author_sub": env.Author.Sub, "author_display": env.Author.Display,
		"author_role": env.Author.Role, "summary": clip(env.Summary(), 255),
		"created_at": env.Timestamp, "state": model.TxApplied,
		"root_before":    rootBefore,
		"version_before": versionBefore, "version_after": versionBefore + 1,
		"envelope": envelope, "write_set": writeSet,
	})); err != nil {
		return nil, fmt.Errorf("register: record transaction: %w", err)
	}

	if err := r.apply(tx, txid, env, ops); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("register: commit transaction: %w", err)
	}
	committed = true

	// The action claimed it would produce versionBefore + 1. If the store
	// moved by anything else, the claim recorded in the row is wrong, and
	// a register that files an incorrect account of its own history is
	// worse than one that fails loudly.
	if _, actual := tx.Root(); actual != versionBefore+1 {
		return nil, fmt.Errorf("register: %s moved the ledger %d → %d; an action must be one commit",
			txid, versionBefore, actual)
	}

	out := &model.Transaction{
		TxID: txid, Envelope: env, WriteSet: ops, State: model.TxApplied,
		RootBefore:    rootBefore,
		VersionBefore: versionBefore, VersionAfter: versionBefore + 1,
	}
	if row, err := tx.QueryOne("SELECT seq FROM `transactions` WHERE txid = " + store.Lit(txid)); err == nil && row != nil {
		out.Seq = row.Uint("seq")
	}
	if r.notify != nil {
		r.notify.TransactionCommitted(out)
	}
	return out, nil
}

// transactionID hashes the envelope and the write set together. Two
// transactions with the same effects but different reasons have
// different identities, which is the point of carrying the reason in
// the first place.
func transactionID(env model.Envelope, ops []model.WriteOp) (string, error) {
	body, err := canon.Marshal(map[string]any{"envelope": env, "write_set": ops})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

// apply writes the effects of a transaction. It is idempotent: every
// op is an upsert or a delete keyed by primary key, so replaying a
// pending transaction converges on the same rows.
func (r *Register) apply(tx *store.Tx, txid string, env model.Envelope, ops []model.WriteOp) error {
	for i, op := range ops {
		if err := r.applyOne(tx, txid, op); err != nil {
			return fmt.Errorf("register: write set entry %d (%s): %w", i, op.Table, err)
		}
	}
	for i, ref := range env.Refs {
		if err := r.applyOne(tx, txid, model.WriteOp{
			Table:  "tx_refs",
			Key:    map[string]any{"txid": txid, "idx": uint64(i)},
			Values: map[string]any{"ref_type": ref.Type, "target": ref.Target},
		}); err != nil {
			return fmt.Errorf("register: reference %d: %w", i, err)
		}
	}
	return nil
}

func (r *Register) applyOne(tx *store.Tx, txid string, op model.WriteOp) error {
	keyCols, ok := keyColumnsFor(op.Table)
	if !ok && op.Table != "tx_refs" {
		return fmt.Errorf("unknown table")
	}
	if op.Table == "tx_refs" {
		keyCols = []string{"txid", "idx"}
	}
	key := make(map[string]any, len(op.Key))
	for k, v := range op.Key {
		key[k] = substitute(v, txid)
	}
	for _, col := range keyCols {
		if _, ok := key[col]; !ok {
			return fmt.Errorf("key column %q is missing", col)
		}
	}
	clauses := make([]string, 0, len(key))
	for _, col := range keyCols {
		clauses = append(clauses, store.Ident(col)+" = "+store.Lit(key[col]))
	}
	where := strings.Join(clauses, " AND ")

	if op.Delete {
		return tx.Exec("DELETE FROM " + store.Ident(op.Table) + " WHERE " + where)
	}

	values := make(map[string]any, len(op.Values))
	for k, v := range op.Values {
		values[k] = substitute(v, txid)
	}
	exists, err := tx.Count("SELECT COUNT(*) FROM " + store.Ident(op.Table) + " WHERE " + where)
	if err != nil {
		return err
	}
	if exists > 0 {
		if len(values) == 0 {
			return nil
		}
		return tx.Exec(store.Update(op.Table, values, where))
	}
	for col, v := range key {
		values[col] = v
	}
	return tx.Exec(store.Insert(op.Table, values))
}

// substitute replaces the transaction-id placeholder. JSON round-trips
// turn every integer into a float64, so the write set is normalised
// back to the types the SQL literal encoder accepts on the way in.
func substitute(v any, txid string) any {
	switch t := v.(type) {
	case string:
		if t == model.TxIDPlaceholder {
			return txid
		}
		return t
	case model.Binary:
		return []byte(t)
	case map[string]any:
		if decoded, ok := model.DecodeBinary(t); ok {
			return decoded
		}
		return t
	case float64:
		if t == float64(int64(t)) {
			return int64(t)
		}
		return t
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return i
		}
		f, _ := t.Float64()
		return f
	case int:
		return int64(t)
	}
	return v
}

// replayPending finishes any transaction left unapplied.
//
// A governance action is now one atomic commit, so this can no longer
// find anything: a crash either committed the whole action or none of
// it. It is kept because a store written by an earlier build, which
// wrote the transaction row ahead of its effects, can still contain a
// pending row, and finishing one is cheap and idempotent.
func (r *Register) replayPending() error {
	return r.st.Do(func(tx *store.Tx) error {
		rows, err := tx.Query("SELECT txid, envelope, write_set FROM `transactions` WHERE state = " +
			store.Lit(model.TxPending) + " ORDER BY seq")
		if err != nil {
			return err
		}
		for _, row := range rows {
			txid := row.Str("txid")
			var env model.Envelope
			if err := json.Unmarshal(row.Bytes("envelope"), &env); err != nil {
				return fmt.Errorf("register: replay %s: envelope: %w", txid, err)
			}
			var ops []model.WriteOp
			if err := json.Unmarshal(row.Bytes("write_set"), &ops); err != nil {
				return fmt.Errorf("register: replay %s: write set: %w", txid, err)
			}
			if err := r.apply(tx, txid, env, ops); err != nil {
				return fmt.Errorf("register: replay %s: %w", txid, err)
			}
			_, versionAfter := tx.Root()
			if err := tx.Exec(store.Update("transactions", map[string]any{
				"state": model.TxApplied, "version_after": versionAfter,
			}, "txid = "+store.Lit(txid))); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *Register) transactionByID(tx *store.Tx, txid string) (*model.Transaction, error) {
	row, err := tx.QueryOne("SELECT * FROM `transactions` WHERE txid = " + store.Lit(txid))
	if err != nil || row == nil {
		return nil, err
	}
	return decodeTransaction(row)
}

func decodeTransaction(row store.Row) (*model.Transaction, error) {
	out := &model.Transaction{
		Seq: row.Uint("seq"), TxID: row.Str("txid"), State: row.Str("state"),
		RootBefore:    row.Str("root_before"),
		VersionBefore: row.Uint("version_before"), VersionAfter: row.Uint("version_after"),
	}
	if raw := row.Bytes("envelope"); len(raw) > 0 {
		if err := json.Unmarshal(raw, &out.Envelope); err != nil {
			return nil, fmt.Errorf("register: transaction %s: envelope: %w", out.TxID, err)
		}
	}
	if raw := row.Bytes("write_set"); len(raw) > 0 {
		if err := json.Unmarshal(raw, &out.WriteSet); err != nil {
			return nil, fmt.Errorf("register: transaction %s: write set: %w", out.TxID, err)
		}
	}
	return out, nil
}

// -- identifiers -----------------------------------------------------------

var idAlphabet = base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz").WithPadding(base32.NoPadding)

// NewObjectID mints a persistent object identifier. The class prefix
// makes an id readable in a log line; the rest is 128 bits of
// randomness, so ids carry no ordering and leak no counts.
func NewObjectID(class string) (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("register: mint identifier: %w", err)
	}
	return class + "-" + idAlphabet.EncodeToString(buf[:]), nil
}

// NewTaskID mints a workflow task identifier.
func NewTaskID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("register: mint identifier: %w", err)
	}
	return "task-" + idAlphabet.EncodeToString(buf[:]), nil
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// systemAuthor is the author recorded for changes the register makes on
// its own behalf: bringing a pack's schemas into being, issuing a
// checkpoint. They are transactions like any other, and they say so.
func (r *Register) systemAuthor(reason string) model.Author {
	return model.Author{Sub: "system:" + r.opts.Name, Display: reason, Role: "system"}
}

// principalAuthor renders an authenticated caller as a commit author.
func principalAuthor(p *auth.Principal) model.Author {
	return model.Author{Sub: p.Sub, Display: p.Display, Role: p.Acting}
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
