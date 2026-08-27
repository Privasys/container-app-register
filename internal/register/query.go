// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/checkpoint"
	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/pack"
	"github.com/Privasys/container-app-register/internal/store"
)

// The read surface. Listing, filtering, counting and joining run
// through the SQL layer, where every row returned has been re-read and
// re-verified through the ledger on the way out; history and proofs
// come from the ledger directly.

// ListFilter constrains a record listing.
type ListFilter struct {
	Class  string
	Status string
	// Match constrains projected columns to exact values.
	Match map[string]string
	// Search is a prefix match over the class's natural key.
	Search string
	Order  string
	Desc   bool
	Limit  int
	Offset int
}

// ObjectSummary is a record's head, without its payload.
type ObjectSummary struct {
	model.Object
	Projection map[string]any `json:"projection,omitempty"`
}

// ListObjects returns the head of every record of a class matching the
// filter.
func (r *Register) ListObjects(p *auth.Principal, f ListFilter) ([]ObjectSummary, error) {
	class := r.pk.Class(f.Class)
	if class == nil {
		return nil, fmt.Errorf("no class named %q", f.Class)
	}
	if !p.CanOn(auth.PermRead, class.Name) {
		return nil, fmt.Errorf("%s may not read %s records", p.Acting, class.Name)
	}
	projections := map[string]bool{}
	for _, proj := range class.Compiled().Projections() {
		projections[proj.Column] = true
	}
	clauses := []string{"o.tenant = " + store.Lit(p.Tenant), "o.class = " + store.Lit(class.Name)}
	if f.Status != "" {
		clauses = append(clauses, "o.status = "+store.Lit(f.Status))
	}
	if f.Search != "" {
		clauses = append(clauses, "o.natural_key LIKE "+store.Lit(escapeLike(f.Search)+"%"))
	}
	for _, col := range sortedKeys(f.Match) {
		if !projections[col] {
			return nil, fmt.Errorf("%s is not a queryable property of %s", col, class.Name)
		}
		clauses = append(clauses, "q."+store.Ident(col)+" = "+store.Lit(f.Match[col]))
	}
	order := "o.updated_at"
	if f.Order != "" {
		switch {
		case f.Order == "natural_key" || f.Order == "status" || f.Order == "created_at" || f.Order == "updated_at":
			order = "o." + store.Ident(f.Order)
		case projections[f.Order]:
			order = "q." + store.Ident(f.Order)
		default:
			return nil, fmt.Errorf("%s is not a sortable property of %s", f.Order, class.Name)
		}
	}
	direction := "ASC"
	if f.Desc {
		direction = "DESC"
	}
	stmt := fmt.Sprintf(
		"SELECT o.*, q.* FROM `objects` AS o JOIN %s AS q ON q.object_id = o.id WHERE %s ORDER BY %s %s LIMIT %d OFFSET %d",
		store.Ident(class.QueryTable()), strings.Join(clauses, " AND "), order, direction,
		clampLimit(f.Limit), max(f.Offset, 0))

	rows, err := r.st.Query(stmt)
	if err != nil {
		return nil, err
	}
	out := make([]ObjectSummary, 0, len(rows))
	for _, row := range rows {
		summary := ObjectSummary{Object: decodeObject(row), Projection: map[string]any{}}
		for col := range projections {
			if v, ok := row[col]; ok {
				summary.Projection[col] = v
			}
		}
		out = append(out, summary)
	}
	return out, nil
}

func decodeObject(row store.Row) model.Object {
	return model.Object{
		ID: row.Str("id"), Tenant: row.Str("tenant"), Class: row.Str("class"),
		NaturalKey: row.Str("natural_key"), HeadVersion: row.Uint("head_version"),
		Status: row.Str("status"), CreatedAt: row.Int("created_at"), UpdatedAt: row.Int("updated_at"),
		CreatedTx: row.Str("created_tx"), UpdatedTx: row.Str("updated_tx"), Erased: row.Bool("erased"),
	}
}

// RecordView is a record's head with its payload, as one caller may see
// it.
type RecordView struct {
	Object  model.Object         `json:"object"`
	Version *model.RecordVersion `json:"version"`
}

// GetObject returns a record's head.
func (r *Register) GetObject(p *auth.Principal, objectID string) (*RecordView, error) {
	var out *RecordView
	err := r.st.Do(func(tx *store.Tx) error {
		row, err := r.objectRow(tx, p.Tenant, objectID)
		if err != nil {
			return err
		}
		obj := decodeObject(row)
		class := r.pk.Class(obj.Class)
		if class == nil {
			return fmt.Errorf("this register no longer declares class %q", obj.Class)
		}
		if !p.CanOn(auth.PermRead, class.Name) {
			return fmt.Errorf("%s may not read %s records", p.Acting, class.Name)
		}
		version, err := r.versionAt(tx, p, class, objectID, obj.HeadVersion)
		if err != nil {
			return err
		}
		out = &RecordView{Object: obj, Version: version}
		return nil
	})
	return out, err
}

// GetVersion returns one historical version of a record.
func (r *Register) GetVersion(p *auth.Principal, objectID string, version uint64) (*RecordView, error) {
	var out *RecordView
	err := r.st.Do(func(tx *store.Tx) error {
		row, err := r.objectRow(tx, p.Tenant, objectID)
		if err != nil {
			return err
		}
		obj := decodeObject(row)
		class := r.pk.Class(obj.Class)
		if class == nil || !p.CanOn(auth.PermRead, obj.Class) {
			return fmt.Errorf("%s may not read %s records", p.Acting, obj.Class)
		}
		v, err := r.versionAt(tx, p, class, objectID, version)
		if err != nil {
			return err
		}
		out = &RecordView{Object: obj, Version: v}
		return nil
	})
	return out, err
}

func (r *Register) versionAt(tx *store.Tx, p *auth.Principal, class *pack.Class, objectID string, version uint64) (*model.RecordVersion, error) {
	row, err := tx.QueryOne("SELECT * FROM `record_versions` WHERE object_id = " + store.Lit(objectID) +
		" AND version = " + store.Lit(version))
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, fmt.Errorf("%s has no version %d", objectID, version)
	}
	if row.Bool("pruned") {
		return nil, &PruneError{ObjectID: objectID, Version: version, Policy: row.Str("prune_policy")}
	}
	return r.readVersion(tx, p, class, row)
}

// HistoryEntry pairs a record version with the transaction that wrote
// it, which is what makes the timeline readable: what changed, and why.
type HistoryEntry struct {
	Version     *model.RecordVersion `json:"version"`
	Transaction *model.Transaction   `json:"transaction,omitempty"`
	Diff        map[string][2]any    `json:"diff,omitempty"`
}

// History returns a record's whole timeline, newest first.
func (r *Register) History(p *auth.Principal, objectID string) ([]HistoryEntry, error) {
	var out []HistoryEntry
	err := r.st.Do(func(tx *store.Tx) error {
		row, err := r.objectRow(tx, p.Tenant, objectID)
		if err != nil {
			return err
		}
		class := r.pk.Class(row.Str("class"))
		if class == nil || !p.CanOn(auth.PermRead, row.Str("class")) {
			return fmt.Errorf("%s may not read %s records", p.Acting, row.Str("class"))
		}
		versions, err := tx.Query("SELECT * FROM `record_versions` WHERE object_id = " +
			store.Lit(objectID) + " ORDER BY version DESC")
		if err != nil {
			return err
		}
		var previous *model.RecordVersion
		entries := make([]HistoryEntry, 0, len(versions))
		for i := len(versions) - 1; i >= 0; i-- {
			v, err := r.readVersion(tx, p, class, versions[i])
			if err != nil {
				return err
			}
			entry := HistoryEntry{Version: v}
			if previous != nil {
				entry.Diff = diffPayloads(previous, v)
			}
			if txn, err := r.transactionByID(tx, v.TxID); err == nil && txn != nil {
				entry.Transaction = txn
			}
			entries = append(entries, entry)
			previous = v
		}
		for i := len(entries) - 1; i >= 0; i-- {
			out = append(out, entries[i])
		}
		return nil
	})
	return out, err
}

// diffPayloads reports what one version changed against the previous
// one. Redacted and erased fields are compared as absent rather than as
// values, so a diff never leaks what a reader is not cleared to see.
func diffPayloads(before, after *model.RecordVersion) map[string][2]any {
	diff := map[string][2]any{}
	seen := map[string]bool{}
	for k, v := range after.Payload {
		seen[k] = true
		if old, ok := before.Payload[k]; !ok || fmt.Sprint(old) != fmt.Sprint(v) {
			diff[k] = [2]any{before.Payload[k], v}
		}
	}
	for k, v := range before.Payload {
		if !seen[k] {
			diff[k] = [2]any{v, nil}
		}
	}
	if before.Status != after.Status {
		diff["(status)"] = [2]any{before.Status, after.Status}
	}
	return diff
}

// -- the transaction log ---------------------------------------------------

// LogFilter constrains the git-log view.
type LogFilter struct {
	Tenant   string
	Class    string
	ObjectID string
	Author   string
	Role     string
	Kind     string
	RefType  string
	Target   string
	From     int64
	To       int64
	Limit    int
	Offset   int
}

// Log returns the transaction log, newest first.
func (r *Register) Log(p *auth.Principal, f LogFilter) ([]*model.Transaction, error) {
	if !p.Can(auth.PermExplorer) {
		return nil, fmt.Errorf("%s may not read the transaction log", p.Acting)
	}
	clauses := []string{"t.tenant = " + store.Lit(p.Tenant)}
	if f.Class != "" {
		clauses = append(clauses, "t.class = "+store.Lit(f.Class))
	}
	if f.ObjectID != "" {
		clauses = append(clauses, "t.object_id = "+store.Lit(f.ObjectID))
	}
	if f.Author != "" {
		clauses = append(clauses, "t.author_sub = "+store.Lit(f.Author))
	}
	if f.Role != "" {
		clauses = append(clauses, "t.author_role = "+store.Lit(f.Role))
	}
	if f.Kind != "" {
		clauses = append(clauses, "t.kind = "+store.Lit(f.Kind))
	}
	if f.From > 0 {
		clauses = append(clauses, "t.created_at >= "+store.Lit(f.From))
	}
	if f.To > 0 {
		clauses = append(clauses, "t.created_at <= "+store.Lit(f.To))
	}
	from := "`transactions` AS t"
	if f.RefType != "" || f.Target != "" {
		from += " JOIN `tx_refs` AS r ON r.txid = t.txid"
		if f.RefType != "" {
			clauses = append(clauses, "r.ref_type = "+store.Lit(f.RefType))
		}
		if f.Target != "" {
			clauses = append(clauses, "r.target = "+store.Lit(f.Target))
		}
	}
	stmt := fmt.Sprintf("SELECT t.* FROM %s WHERE %s ORDER BY t.seq DESC LIMIT %d OFFSET %d",
		from, strings.Join(clauses, " AND "), clampLimit(f.Limit), max(f.Offset, 0))
	rows, err := r.st.Query(stmt)
	if err != nil {
		return nil, err
	}
	out := make([]*model.Transaction, 0, len(rows))
	for _, row := range rows {
		txn, err := decodeTransaction(row)
		if err != nil {
			return nil, err
		}
		out = append(out, txn)
	}
	return out, nil
}

// TransactionDetail is one transaction with its typed references.
type TransactionDetail struct {
	*model.Transaction
	Refs []model.Ref `json:"refs"`
}

// Transaction returns one transaction in full.
func (r *Register) Transaction(p *auth.Principal, txid string) (*TransactionDetail, error) {
	if !p.Can(auth.PermExplorer) {
		return nil, fmt.Errorf("%s may not read the transaction log", p.Acting)
	}
	var out *TransactionDetail
	err := r.st.Do(func(tx *store.Tx) error {
		txn, err := r.transactionByID(tx, txid)
		if err != nil {
			return err
		}
		if txn == nil {
			return fmt.Errorf("no transaction %s", txid)
		}
		rows, err := tx.Query("SELECT ref_type, target FROM `tx_refs` WHERE txid = " + store.Lit(txid) + " ORDER BY idx")
		if err != nil {
			return err
		}
		detail := &TransactionDetail{Transaction: txn}
		for _, row := range rows {
			detail.Refs = append(detail.Refs, model.Ref{Type: row.Str("ref_type"), Target: row.Str("target")})
		}
		out = detail
		return nil
	})
	return out, err
}

// -- saved queries ---------------------------------------------------------

// RunQuery runs one of the pack's declared queries.
func (r *Register) RunQuery(p *auth.Principal, name string, params map[string]string) ([]store.Row, error) {
	q := r.pk.Query(name)
	if q == nil {
		return nil, fmt.Errorf("no query named %q", name)
	}
	if len(q.Roles) > 0 && !containsString(q.Roles, p.Acting) {
		return nil, fmt.Errorf("%s may not run the %s query", p.Acting, name)
	}
	if len(q.Roles) == 0 && !p.CanOn(auth.PermRead, "*") {
		return nil, fmt.Errorf("%s may not run queries", p.Acting)
	}
	ctx := &tmplContext{values: map[string]any{"tenant": p.Tenant}}
	for _, param := range q.Params {
		raw, ok := params[param.Name]
		if !ok || raw == "" {
			if param.Required {
				return nil, fmt.Errorf("%s requires %s", name, orDefault(param.Title, param.Name))
			}
			raw = param.Default
		}
		value, err := coerceParam(param, raw)
		if err != nil {
			return nil, err
		}
		ctx.set("param."+param.Name, value)
	}
	return r.st.Query(renderSQL(q.SQL, ctx))
}

func coerceParam(param pack.QueryParam, raw string) (any, error) {
	switch param.Type {
	case "integer":
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s must be a whole number", orDefault(param.Title, param.Name))
		}
		return n, nil
	case "number":
		f, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return nil, fmt.Errorf("%s must be a number", orDefault(param.Title, param.Name))
		}
		return f, nil
	default:
		return raw, nil
	}
}

// -- verified reads --------------------------------------------------------

// Evidence returns a row together with the proof that it is part of the
// register's authenticated state, signed, and anchored to the latest
// checkpoint. This is the artefact a court can be handed: it verifies
// with nothing but the bundle, the register's public key, and a
// checkpoint the holder already had.
func (r *Register) Evidence(p *auth.Principal, table string, pk []any, statement string) (*model.EvidenceBundle, error) {
	if !p.Can(auth.PermProofs) {
		return nil, fmt.Errorf("%s may not fetch proofs", p.Acting)
	}
	var out *model.EvidenceBundle
	err := r.st.Do(func(tx *store.Tx) error {
		// Anchor first. Issuing a checkpoint moves no version, so after
		// this the state the row is read at is exactly the state the
		// checkpoint attests, and the bundle can be verified end to end
		// without asking the register for anything else.
		anchor, err := r.anchorCurrentState(tx)
		if err != nil {
			return err
		}
		verified, err := tx.SQL().VerifiedGet(table, pk...)
		if err != nil {
			return err
		}
		path, proof, err := tx.Prove(verified.Key)
		if err != nil {
			return err
		}
		root, version := tx.Root()
		bundle := &model.EvidenceBundle{
			Register: r.opts.Name, Statement: statement, Table: table, PrimaryKey: pk,
			Present:   verified.Row != nil,
			LedgerKey: hex.EncodeToString(verified.Key),
			Path:      hex.EncodeToString(path[:]),
			Proof:     hex.EncodeToString(proof.Encode()),
			Root:      root, Version: version, IssuedAt: r.now(),
		}
		if verified.Value != nil {
			bundle.LedgerValue = hex.EncodeToString(verified.Value)
		}
		if verified.Row != nil {
			bundle.Row = map[string]any{}
			for i, col := range tableColumns(table, len(verified.Row)) {
				bundle.Row[col] = verified.Row[i]
			}
		}
		bundle.Checkpoint = anchor
		if err := checkpoint.SignBundle(r.mat.Signer, r.mat.KeyID, bundle); err != nil {
			return err
		}
		out = bundle
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RecordEvidence proves one record version.
func (r *Register) RecordEvidence(p *auth.Principal, objectID string, version uint64) (*model.EvidenceBundle, error) {
	return r.Evidence(p, "record_versions", []any{objectID, version},
		fmt.Sprintf("version %d of record %s", version, objectID))
}

// NaturalKeyEvidence proves that a natural key is, or is not,
// registered. An absence proof is the answer to "this vehicle was never
// registered here", and it is a proof rather than a silence.
func (r *Register) NaturalKeyEvidence(p *auth.Principal, class, naturalKey string) (*model.EvidenceBundle, error) {
	c := r.pk.Class(class)
	if c == nil {
		return nil, fmt.Errorf("no class named %q", class)
	}
	if c.NaturalKey == "" {
		return nil, fmt.Errorf("%s records have no natural key", class)
	}
	return r.Evidence(p, "natural_keys", []any{p.Tenant, class, naturalKey},
		fmt.Sprintf("whether %s %q is registered", c.NaturalKey, naturalKey))
}

// tableColumns names the columns of the register's tables in schema
// order, for rendering a verified row. Rows come back from the SQL
// layer as positional values.
func tableColumns(table string, n int) []string {
	if cols, ok := verifiedColumns[table]; ok && len(cols) == n {
		return cols
	}
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("column_%d", i)
	}
	return out
}

var verifiedColumns = map[string][]string{
	"record_versions": {"object_id", "version", "txid", "schema_id", "created_at", "status",
		"payload_hash", "payload", "enc_scope", "pruned", "prune_policy"},
	"natural_keys": {"tenant", "class", "natural_key", "object_id", "updated_at"},
	"objects": {"id", "tenant", "class", "natural_key", "head_version", "status",
		"created_at", "updated_at", "created_tx", "updated_tx", "erased"},
}

func escapeLike(s string) string {
	r := strings.NewReplacer("%", "", "_", "")
	return r.Replace(s)
}

func clampLimit(n int) int {
	if n <= 0 {
		return 50
	}
	if n > 500 {
		return 500
	}
	return n
}
