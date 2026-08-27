// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/byok"
	"github.com/Privasys/container-app-register/internal/canon"
	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/pack"
	"github.com/Privasys/container-app-register/internal/store"
)

// storedPayload is the on-ledger shape of a record version: the fields
// anyone with read access may see, and the sealed remainder.
//
// The ledger entry commits to this shape and to the hash of the whole
// plaintext payload. Destroying the data-encryption key removes the
// ability to read Enc, and changes neither the entry nor the hash, so
// an erased record still verifies against every root that ever
// contained it.
type storedPayload struct {
	Clear map[string]any   `json:"clear"`
	Enc   *byok.Ciphertext `json:"enc,omitempty"`
}

// recordDraft is a validated record about to be written.
type recordDraft struct {
	class    *pack.Class
	objectID string
	version  uint64
	status   string
	payload  map[string]any
	schemaID string
}

// buildRecordOps validates a payload and produces the write set that
// records it: the immutable version, the object head, and the class's
// query projection.
func (r *Register) buildRecordOps(tx *store.Tx, w *writeCtx, d recordDraft) ([]model.WriteOp, error) {
	if err := d.class.Compiled().Validate(d.payload); err != nil {
		return nil, fmt.Errorf("record does not match schema %s: %w", d.schemaID, err)
	}
	if err := r.checkReferences(tx, w, d); err != nil {
		return nil, err
	}

	plaintext, err := canon.Marshal(d.payload)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(plaintext)
	payloadHash := hex.EncodeToString(sum[:])

	stored := storedPayload{Clear: map[string]any{}}
	pii := d.class.Compiled().PIIFields()
	piiSet := map[string]bool{}
	for _, f := range pii {
		piiSet[f] = true
	}
	for k, v := range d.payload {
		if !piiSet[k] {
			stored.Clear[k] = v
		}
	}

	var ops []model.WriteOp
	scope := ""
	if d.class.Encryption != pack.EncNone {
		sealedFields := map[string]any{}
		for _, f := range pii {
			if v, ok := d.payload[f]; ok {
				sealedFields[f] = v
			}
		}
		scope = r.dekScope(w.tenant, d.class, d.objectID)
		dek, keyOps, err := r.ensureDEK(tx, w, d.class, scope)
		if err != nil {
			return nil, err
		}
		ops = append(ops, keyOps...)
		clear, err := canon.Marshal(sealedFields)
		if err != nil {
			return nil, err
		}
		ct, err := byok.Encrypt(dek, scope, d.objectID, d.version, clear)
		if err != nil {
			return nil, err
		}
		stored.Enc = ct
	}

	body, err := canon.Marshal(stored)
	if err != nil {
		return nil, err
	}

	naturalKey := d.objectID
	if d.class.NaturalKey != "" {
		if v, ok := d.payload[d.class.NaturalKey]; ok {
			naturalKey = fmt.Sprint(v)
		}
	}
	if err := r.checkNaturalKey(tx, w.tenant, d.class, d.objectID, naturalKey); err != nil {
		return nil, err
	}

	ops = append(ops,
		model.WriteOp{
			Table: "record_versions",
			Key:   map[string]any{"object_id": d.objectID, "version": d.version},
			Values: map[string]any{
				"txid": model.TxIDPlaceholder, "schema_id": d.schemaID,
				"created_at": w.at, "status": d.status,
				"payload_hash": payloadHash, "payload": model.Binary(body),
				"enc_scope": scope, "pruned": false, "prune_policy": "",
			},
		},
		model.WriteOp{
			Table: "objects",
			Key:   map[string]any{"id": d.objectID},
			Values: map[string]any{
				"tenant": w.tenant, "class": d.class.Name, "natural_key": naturalKey,
				"head_version": d.version, "status": d.status,
				"updated_at": w.at, "updated_tx": model.TxIDPlaceholder,
				"created_at": w.at, "created_tx": model.TxIDPlaceholder,
				"erased": false,
			},
		},
	)
	// An update must not rewrite the object's creation stamps.
	if d.version > 1 {
		values := ops[len(ops)-1].Values
		delete(values, "created_at")
		delete(values, "created_tx")
	}

	if d.class.NaturalKey != "" {
		if previous, err := r.previousNaturalKey(tx, d.objectID); err != nil {
			return nil, err
		} else if previous != "" && previous != naturalKey {
			// A correction that changes the natural key retires the old
			// one, so an absence proof for it says what it should: this
			// key is not registered here now.
			ops = append(ops, model.WriteOp{
				Table:  "natural_keys",
				Key:    map[string]any{"tenant": w.tenant, "class": d.class.Name, "natural_key": previous},
				Delete: true,
			})
		}
		ops = append(ops, model.WriteOp{
			Table: "natural_keys",
			Key:   map[string]any{"tenant": w.tenant, "class": d.class.Name, "natural_key": naturalKey},
			Values: map[string]any{
				"object_id": d.objectID, "updated_at": w.at,
			},
		})
	}

	proj := r.projectionOps(d.class, w.tenant, d.objectID, d.status, w.at, stored.Clear)
	ops = append(ops, proj)
	return ops, nil
}

func (r *Register) previousNaturalKey(tx *store.Tx, objectID string) (string, error) {
	row, err := tx.QueryOne("SELECT natural_key FROM `objects` WHERE id = " + store.Lit(objectID))
	if err != nil || row == nil {
		return "", err
	}
	return row.Str("natural_key"), nil
}

// projectionOps builds the row that makes a class queryable. Only
// non-personal fields are projected: a query table is plaintext, so
// anything in it is readable by every query the register can run, and
// personal data belongs behind the data-encryption key instead.
func (r *Register) projectionOps(class *pack.Class, tenant, objectID, status string, at int64, clear map[string]any) model.WriteOp {
	values := map[string]any{"tenant": tenant, "status": status, "updated_at": at}
	for _, p := range class.Compiled().Projections() {
		values[p.Column] = projectValue(p.Type, clear[p.Property])
	}
	return model.WriteOp{
		Table:  class.QueryTable(),
		Key:    map[string]any{"object_id": objectID},
		Values: values,
	}
}

// projectValue coerces a JSON value into the column type the projection
// declared, filling in the zero value when a property is absent. The
// SQL layer has no column defaults, so every column is always written.
func projectValue(typ string, v any) any {
	switch typ {
	case "integer":
		switch n := v.(type) {
		case float64:
			return int64(n)
		case json.Number:
			i, _ := n.Int64()
			return i
		case string:
			i, _ := strconv.ParseInt(n, 10, 64)
			return i
		case nil:
			return int64(0)
		}
		return int64(0)
	case "number":
		switch n := v.(type) {
		case float64:
			return n
		case json.Number:
			f, _ := n.Float64()
			return f
		case nil:
			return float64(0)
		}
		return float64(0)
	case "boolean":
		b, _ := v.(bool)
		return b
	default:
		if v == nil {
			return ""
		}
		if s, ok := v.(string); ok {
			return clip(s, 191)
		}
		return clip(fmt.Sprint(v), 191)
	}
}

// checkNaturalKey enforces the uniqueness the SQL layer's unique index
// also enforces, so the caller gets an explanation rather than a
// constraint violation. Both are kept: the index is the guarantee, the
// check is the message.
func (r *Register) checkNaturalKey(tx *store.Tx, tenant string, class *pack.Class, objectID, naturalKey string) error {
	if class.NaturalKey == "" {
		return nil
	}
	row, err := tx.QueryOne("SELECT id FROM `objects` WHERE tenant = " + store.Lit(tenant) +
		" AND class = " + store.Lit(class.Name) + " AND natural_key = " + store.Lit(naturalKey))
	if err != nil {
		return err
	}
	if row != nil && row.Str("id") != objectID {
		return fmt.Errorf("%s %q is already registered as %s", class.NaturalKey, naturalKey, row.Str("id"))
	}
	return nil
}

// checkReferences enforces the referential rules the SQL layer has no
// foreign keys for. A reference must point at an existing object of the
// declared class, in the same tenant.
func (r *Register) checkReferences(tx *store.Tx, w *writeCtx, d recordDraft) error {
	refs := d.class.Compiled().References()
	for _, prop := range sortedKeys(refs) {
		v, ok := d.payload[prop]
		if !ok || v == nil || v == "" {
			continue
		}
		target := fmt.Sprint(v)
		class, pending := w.pending[target]
		if !pending {
			row, err := tx.QueryOne("SELECT class FROM `objects` WHERE id = " + store.Lit(target) +
				" AND tenant = " + store.Lit(w.tenant))
			if err != nil {
				return err
			}
			if row == nil {
				return fmt.Errorf("%s references %s %q, which is not registered", prop, refs[prop], target)
			}
			class = row.Str("class")
		}
		if class != refs[prop] {
			return fmt.Errorf("%s references %q, which is a %s and not a %s", prop, target, class, refs[prop])
		}
	}
	return nil
}

// -- data-encryption keys --------------------------------------------------

// dekScope names the key that protects a record's personal data. A
// subject scope gives one record one key, which is what turns erasing a
// person into deleting a single key rather than rewriting history.
func (r *Register) dekScope(tenant string, class *pack.Class, objectID string) string {
	switch class.Encryption {
	case pack.EncTenant:
		return tenant + "/tenant"
	case pack.EncClass:
		return tenant + "/class/" + class.Name
	case pack.EncSubject:
		return tenant + "/subject/" + objectID
	}
	return ""
}

// ensureDEK returns the data-encryption key for a scope, creating it
// (and the write ops that record it) when it does not exist yet.
func (r *Register) ensureDEK(tx *store.Tx, w *writeCtx, class *pack.Class, scope string) ([32]byte, []model.WriteOp, error) {
	var zero [32]byte
	tenant, at := w.tenant, w.at
	row, err := tx.QueryOne("SELECT * FROM `dek_keys` WHERE scope = " + store.Lit(scope))
	if err != nil {
		return zero, nil, err
	}
	if row != nil {
		if row.Int("destroyed_at") != 0 {
			return zero, nil, fmt.Errorf("the key for %s has been destroyed; this record cannot be rewritten", scope)
		}
		dek, err := r.ring.UnwrapOperational(scope, row.Bytes("op_wrap"))
		return dek, nil, err
	}

	dek, err := byok.NewDEK()
	if err != nil {
		return zero, nil, err
	}
	opWrap, err := r.ring.WrapOperational(scope, dek)
	if err != nil {
		return zero, nil, err
	}
	recWrap, kekID := []byte{}, ""
	if kek, err := r.activeKEK(tx, tenant); err != nil {
		return zero, nil, err
	} else if kek != nil {
		recWrap, err = kek.WrapRecovery(scope, dek)
		if err != nil {
			return zero, nil, err
		}
		kekID = kek.ID
	}

	subject := ""
	if class.Encryption == pack.EncSubject {
		subject = strings.TrimPrefix(scope, tenant+"/subject/")
	}
	op := model.WriteOp{
		Table: "dek_keys",
		Key:   map[string]any{"scope": scope},
		Values: map[string]any{
			"tenant": tenant, "kind": class.Encryption, "subject": subject,
			"op_wrap": model.Binary(opWrap), "rec_wrap": model.Binary(recWrap), "kek_id": kekID,
			"created_at": at, "destroyed_at": int64(0), "txid": model.TxIDPlaceholder,
		},
	}
	return dek, []model.WriteOp{op}, nil
}

func (r *Register) activeKEK(tx *store.Tx, tenant string) (*byok.KEK, error) {
	row, err := tx.QueryOne("SELECT * FROM `keks` WHERE tenant = " + store.Lit(tenant) +
		" AND active = TRUE ORDER BY enrolled_at DESC LIMIT 1")
	if err != nil || row == nil {
		return nil, err
	}
	return byok.ParseKEK(row.Str("id"), row.Str("algo"), row.Bytes("public_key"))
}

// -- reading ---------------------------------------------------------------

// readVersion materialises one record version for a caller, applying
// the three reasons a payload may not come back whole: it was pruned,
// its key was destroyed, or the caller is not cleared to see personal
// data.
func (r *Register) readVersion(tx *store.Tx, p *auth.Principal, class *pack.Class, row store.Row) (*model.RecordVersion, error) {
	out := &model.RecordVersion{
		ObjectID: row.Str("object_id"), Version: row.Uint("version"),
		TxID: row.Str("txid"), SchemaID: row.Str("schema_id"),
		CreatedAt: row.Int("created_at"), Status: row.Str("status"),
		PayloadHash: row.Str("payload_hash"), EncScope: row.Str("enc_scope"),
		Pruned: row.Bool("pruned"), PrunePolicy: row.Str("prune_policy"),
	}
	if out.Pruned {
		return out, nil
	}
	var stored storedPayload
	if err := json.Unmarshal(row.Bytes("payload"), &stored); err != nil {
		return nil, fmt.Errorf("register: record %s v%d: %w", out.ObjectID, out.Version, err)
	}
	out.Payload = map[string]any{}
	for k, v := range stored.Clear {
		out.Payload[k] = v
	}
	if stored.Enc == nil {
		return out, nil
	}

	piiFields := class.Compiled().PIIFields()
	if p != nil && !p.PII {
		out.Redacted = piiFields
		return out, nil
	}
	dekRow, err := tx.QueryOne("SELECT op_wrap, destroyed_at FROM `dek_keys` WHERE scope = " + store.Lit(out.EncScope))
	if err != nil {
		return nil, err
	}
	if dekRow == nil || dekRow.Int("destroyed_at") != 0 {
		out.Erased = true
		out.Redacted = piiFields
		return out, nil
	}
	dek, err := r.ring.UnwrapOperational(out.EncScope, dekRow.Bytes("op_wrap"))
	if err != nil {
		return nil, err
	}
	clear, err := byok.Decrypt(dek, stored.Enc, out.ObjectID, out.Version)
	if err != nil {
		return nil, fmt.Errorf("register: record %s v%d: %w", out.ObjectID, out.Version, err)
	}
	var fields map[string]any
	if err := json.Unmarshal(clear, &fields); err != nil {
		return nil, err
	}
	for k, v := range fields {
		out.Payload[k] = v
	}
	return out, nil
}

// PruneError explains a read that fell past a retention horizon. The
// distinction matters: a pruned version is a version the register once
// held and lawfully removed, and saying so is not the same as saying
// nothing was ever there.
type PruneError struct {
	ObjectID string
	Version  uint64
	Policy   string
}

func (e *PruneError) Error() string {
	return fmt.Sprintf("register: %s version %d was pruned per policy %s", e.ObjectID, e.Version, e.Policy)
}
