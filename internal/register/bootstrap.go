// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Privasys/container-app-register/internal/canon"
	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/pack"
	"github.com/Privasys/container-app-register/internal/store"
)

// reconcilePack brings the store in line with the loaded pack: query
// projections, schema versions, retention policies, and (once, on a
// fresh register) the pack's seed content.
//
// Schemas and policies land as ordinary transactions, so the rules a
// decision was taken under are in the same log as the decision. Query
// projections are catalogue structure rather than state: creating them
// advances the root without a transaction of its own, which happens at
// bootstrap and whenever a pack changes which properties are queryable.
// The schema transaction that follows records the fingerprint of the
// structure it produced, so the structural step is not invisible.
func (r *Register) reconcilePack() error {
	if err := r.ensureProjections(); err != nil {
		return err
	}
	if err := r.registerSchemas(); err != nil {
		return err
	}
	if err := r.registerPolicies(); err != nil {
		return err
	}
	return r.applySeed()
}

// -- query projections -----------------------------------------------------

func (r *Register) ensureProjections() error {
	return r.st.Do(func(tx *store.Tx) error {
		tables, err := tx.Tables()
		if err != nil {
			return err
		}
		for _, class := range r.pk.Classes {
			ddl, indexes := projectionDDL(class)
			want := fingerprintOf(class)
			have, err := r.registryValue(tx, "projection:"+class.Name)
			if err != nil {
				return err
			}
			if tables[class.QueryTable()] && have == want {
				continue
			}
			if tables[class.QueryTable()] {
				if err := tx.Exec("DROP TABLE " + store.Ident(class.QueryTable())); err != nil {
					return fmt.Errorf("register: replace projection for %s: %w", class.Name, err)
				}
			}
			if err := tx.Exec(ddl); err != nil {
				return fmt.Errorf("register: projection for %s: %w", class.Name, err)
			}
			for _, idx := range indexes {
				if err := tx.Exec(idx); err != nil {
					return fmt.Errorf("register: projection index for %s: %w", class.Name, err)
				}
			}
			if err := r.repopulateProjection(tx, class); err != nil {
				return err
			}
			// The fingerprint is recorded by the schema transaction that
			// follows, not here, so the marker has a transaction to
			// explain it.
		}
		return nil
	})
}

// projectionDDL renders the query table for a class.
func projectionDDL(class *pack.Class) (string, []string) {
	var b strings.Builder
	fmt.Fprintf(&b, "CREATE TABLE %s (\n", store.Ident(class.QueryTable()))
	b.WriteString("  object_id VARCHAR(96) PRIMARY KEY,\n")
	b.WriteString("  tenant VARCHAR(64) NOT NULL,\n")
	b.WriteString("  status VARCHAR(32) NOT NULL,\n")
	b.WriteString("  updated_at BIGINT NOT NULL")
	indexes := []string{
		fmt.Sprintf("CREATE INDEX %s ON %s (tenant, status)",
			store.Ident(class.QueryTable()+"_scope"), store.Ident(class.QueryTable())),
	}
	for _, p := range class.Compiled().Projections() {
		fmt.Fprintf(&b, ",\n  %s %s NOT NULL", store.Ident(p.Column), columnType(p.Type))
		switch {
		case p.Unique:
			indexes = append(indexes, fmt.Sprintf("CREATE UNIQUE INDEX %s ON %s (%s)",
				store.Ident(class.QueryTable()+"_"+p.Column), store.Ident(class.QueryTable()), store.Ident(p.Column)))
		case p.Indexed:
			indexes = append(indexes, fmt.Sprintf("CREATE INDEX %s ON %s (%s)",
				store.Ident(class.QueryTable()+"_"+p.Column), store.Ident(class.QueryTable()), store.Ident(p.Column)))
		}
	}
	b.WriteString("\n)")
	return b.String(), indexes
}

func columnType(jsonType string) string {
	switch jsonType {
	case "integer":
		return "BIGINT"
	case "number":
		return "DOUBLE"
	case "boolean":
		return "BOOLEAN"
	default:
		return "VARCHAR(191)"
	}
}

// repopulateProjection rebuilds a class's query table from the record
// versions it derives from. Only the clear half of a payload is
// projected, so no key is needed and an erased record projects exactly
// what it always did.
func (r *Register) repopulateProjection(tx *store.Tx, class *pack.Class) error {
	objects, err := tx.Query("SELECT id, tenant, status, head_version, updated_at FROM `objects` WHERE class = " +
		store.Lit(class.Name))
	if err != nil {
		return err
	}
	for _, obj := range objects {
		row, err := tx.QueryOne("SELECT payload, pruned FROM `record_versions` WHERE object_id = " +
			store.Lit(obj.Str("id")) + " AND version = " + store.Lit(obj.Uint("head_version")))
		if err != nil {
			return err
		}
		if row == nil || row.Bool("pruned") {
			continue
		}
		var stored storedPayload
		if err := json.Unmarshal(row.Bytes("payload"), &stored); err != nil {
			return fmt.Errorf("register: rebuild projection for %s: %w", obj.Str("id"), err)
		}
		op := r.projectionOps(class, obj.Str("tenant"), obj.Str("id"), obj.Str("status"), obj.Int("updated_at"), stored.Clear)
		if err := r.applyOne(tx, "", op); err != nil {
			return err
		}
	}
	return nil
}

func fingerprint(parts []string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:])
}

// -- schemas ---------------------------------------------------------------

// registerSchemas commits each class's schema as a ledger object. A
// schema that has not changed is left alone; a changed one is
// registered as the next version and the previous one is deactivated,
// so records validated under the old rules keep pointing at the rules
// they were validated under.
func (r *Register) registerSchemas() error {
	for _, class := range r.pk.Classes {
		if err := r.registerSchema(class); err != nil {
			return err
		}
	}
	return nil
}

func (r *Register) registerSchema(class *pack.Class) error {
	return r.st.Do(func(tx *store.Tx) error {
		doc, err := canon.Marshal(json.RawMessage(class.Schema))
		if err != nil {
			return err
		}
		current, err := tx.QueryOne("SELECT id, version, doc FROM `schemas` WHERE class = " +
			store.Lit(class.Name) + " AND active = TRUE ORDER BY version DESC LIMIT 1")
		if err != nil {
			return err
		}
		if current != nil && string(current.Bytes("doc")) == string(doc) {
			return nil
		}
		version := uint64(1)
		if current != nil {
			version = current.Uint("version") + 1
		}
		id := fmt.Sprintf("%s@%d", class.Name, version)
		at := r.now()

		ops := []model.WriteOp{
			{
				Table: "schemas",
				Key:   map[string]any{"id": id},
				Values: map[string]any{
					"class": class.Name, "version": version, "active": true,
					"doc": model.Binary(doc), "created_at": at, "txid": model.TxIDPlaceholder,
				},
			},
			// The query table was created just before this ran. Recording
			// its fingerprint here rather than out of band means the root
			// movement has a transaction that explains it.
			{
				Table:  "registry",
				Key:    map[string]any{"k": "projection:" + class.Name},
				Values: map[string]any{"v": model.Binary(fingerprintOf(class)), "updated_at": at},
			},
		}
		if current != nil {
			ops = append(ops, model.WriteOp{
				Table:  "schemas",
				Key:    map[string]any{"id": current.Str("id")},
				Values: map[string]any{"active": false},
			})
		}

		message := fmt.Sprintf("Register schema %s", id)
		body := fmt.Sprintf("Pack %s %s.\nQuery projection fingerprint %s.",
			r.pk.Name, r.pk.Version, fingerprintOf(class)[:16])
		env := model.Envelope{
			Kind: model.KindSchemaRegister, Tenant: r.opts.Tenant, Class: class.Name,
			SchemaID: id, Author: r.systemAuthor("pack " + r.pk.Name),
			Timestamp: at, Message: message + "\n\n" + body,
		}
		if current != nil {
			env.Refs = []model.Ref{{Type: model.RefSupersedes, Target: current.Str("id")}}
		}
		_, err = r.commit(tx, env, ops)
		return err
	})
}

// fingerprintOf identifies the query table a class's schema produces, so
// a change to which properties are queryable is visible in the log.
func fingerprintOf(class *pack.Class) string {
	ddl, indexes := projectionDDL(class)
	return fingerprint(append([]string{ddl}, indexes...))
}

// -- retention policies ----------------------------------------------------

func (r *Register) registerPolicies() error {
	for _, policy := range r.pk.Retention {
		if err := r.registerPolicy(policy); err != nil {
			return err
		}
	}
	return nil
}

func (r *Register) registerPolicy(policy *pack.RetentionPolicy) error {
	return r.st.Do(func(tx *store.Tx) error {
		doc, err := canon.Marshal(policy)
		if err != nil {
			return err
		}
		current, err := tx.QueryOne("SELECT version, doc FROM `policies` WHERE id = " + store.Lit(policy.ID))
		if err != nil {
			return err
		}
		if current != nil && string(current.Bytes("doc")) == string(doc) {
			return nil
		}
		version := uint64(1)
		if current != nil {
			version = current.Uint("version") + 1
		}
		at := r.now()
		ops := []model.WriteOp{{
			Table: "policies",
			Key:   map[string]any{"id": policy.ID},
			Values: map[string]any{
				"kind": "retention", "tenant": r.opts.Tenant, "class": policy.Class,
				"version": version, "active": true, "doc": model.Binary(doc),
				"created_at": at, "txid": model.TxIDPlaceholder,
			},
		}}
		env := model.Envelope{
			Kind: model.KindPolicySet, Tenant: r.opts.Tenant, Class: policy.Class,
			Author: r.systemAuthor("pack " + r.pk.Name), Timestamp: at,
			Message: fmt.Sprintf("Set retention policy %s v%d", policy.ID, version) + "\n\n" +
				fmt.Sprintf("%s: keep %s versions of %s for %d days.",
					policy.Title, policy.Scope, policy.Class, policy.WindowDays),
		}
		_, err = r.commit(tx, env, ops)
		return err
	})
}

// -- seed ------------------------------------------------------------------

// applySeed writes the pack's demo content, once, on a register that
// has never held any. Seeded records are ordinary transactions with an
// ordinary author: the log says plainly that they came from the pack.
func (r *Register) applySeed() error {
	if r.pk.Seed == nil || len(r.pk.Seed.Objects) == 0 {
		return nil
	}
	return r.st.Do(func(tx *store.Tx) error {
		marker := "seed:" + r.pk.Name + ":" + r.pk.Version
		done, err := r.registryValue(tx, marker)
		if err != nil || done != "" {
			return err
		}
		refs := map[string]string{}
		for i, seed := range r.pk.Seed.Objects {
			class := r.pk.Class(seed.Class)
			payload := resolveRefs(seed.Payload, refs)
			at := r.now()
			message := seed.Message
			if message == "" {
				message = fmt.Sprintf("Seed %s record %d", seed.Class, i+1)
			}
			var objectID string
			var ops []model.WriteOp
			objectID, ops, err = r.createOps(tx, newWriteCtx(r.opts.Tenant, at), class, payload, seed.Status)
			if err != nil {
				return fmt.Errorf("register: seed object %d: %w", i, err)
			}
			env := model.Envelope{
				Kind: model.KindRecordCreate, Tenant: r.opts.Tenant, Class: class.Name,
				ObjectIDs: []string{objectID}, Author: r.systemAuthor("pack seed"),
				Timestamp: at, Message: clip(message, model.MaxSummary),
			}
			if _, err := r.commit(tx, env, ops); err != nil {
				return fmt.Errorf("register: seed object %d: %w", i, err)
			}
			if seed.Ref != "" {
				refs[seed.Ref] = objectID
			}
		}
		// Record that the seed ran, as a transaction rather than a bare
		// marker: it moved the root, so something should say why.
		at := r.now()
		env := model.Envelope{
			Kind: model.KindPackSeed, Tenant: r.opts.Tenant,
			Author: r.systemAuthor("pack " + r.pk.Name), Timestamp: at,
			Message: composeMessage(
				clip(fmt.Sprintf("Seed pack %s %s", r.pk.Name, r.pk.Version), model.MaxSummary),
				fmt.Sprintf("%d demonstration records written once, on a register that held none.",
					len(r.pk.Seed.Objects))),
		}
		_, err = r.commit(tx, env, []model.WriteOp{{
			Table:  "registry",
			Key:    map[string]any{"k": marker},
			Values: map[string]any{"v": model.Binary(r.opts.Now().UTC().Format(time.RFC3339)), "updated_at": at},
		}})
		return err
	})
}

// resolveRefs substitutes "@name" references between seed objects with
// the identifier the earlier object was minted with.
func resolveRefs(payload map[string]any, refs map[string]string) map[string]any {
	out := make(map[string]any, len(payload))
	for k, v := range payload {
		if s, ok := v.(string); ok && strings.HasPrefix(s, "@") {
			if id, ok := refs[strings.TrimPrefix(s, "@")]; ok {
				out[k] = id
				continue
			}
		}
		out[k] = v
	}
	return out
}

// -- small registry --------------------------------------------------------

func (r *Register) registryValue(tx *store.Tx, key string) (string, error) {
	row, err := tx.QueryOne("SELECT v FROM `registry` WHERE k = " + store.Lit(key))
	if err != nil || row == nil {
		return "", err
	}
	return string(row.Bytes("v")), nil
}
