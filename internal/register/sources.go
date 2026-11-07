// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/canon"
	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/pack"
	"github.com/Privasys/container-app-register/internal/store"
)

// SourceRecord is a record as a source describes it, before or after it
// is brought in.
type SourceRecord struct {
	Source   string         `json:"source"`
	Key      string         `json:"key"`
	Status   string         `json:"status"`
	Payload  map[string]any `json:"payload"`
	ObjectID string         `json:"object_id,omitempty"`
	// Held says the register already holds this record, and Current that
	// what it holds is what the source says now.
	Held    bool `json:"held"`
	Current bool `json:"current"`
}

// MapSource turns a fetched document into a record of the source's class.
func MapSource(pk *pack.Pack, src *pack.Source, doc map[string]any) (map[string]any, string, error) {
	class := pk.Class(src.Class)
	var schema struct {
		Properties map[string]struct {
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(class.Schema, &schema); err != nil {
		return nil, "", err
	}
	payload := map[string]any{}
	for name, f := range src.Fields {
		value := f.Const
		if f.From != "" {
			value = pack.Lookup(doc, f.From)
		}
		if value == nil {
			continue
		}
		if f.Date {
			s, ok := value.(string)
			if !ok || len(s) < 10 {
				return nil, "", fmt.Errorf("%s: %s is not a date", src.Name, f.From)
			}
			value = s[:10]
		}
		if _, envelope := schema.Properties[name].Properties["value"]; envelope {
			wrapped := map[string]any{"value": value}
			for k, v := range src.Envelope {
				wrapped[k] = v
			}
			value = wrapped
		}
		payload[name] = value
	}
	status := class.Initial
	if src.Status != nil {
		status = src.Status.Default
		if code, ok := pack.Lookup(doc, src.Status.From).(string); ok {
			if mapped, ok := src.Status.Map[code]; ok {
				status = mapped
			}
		}
	}
	return payload, status, nil
}

// CanImport returns the source if the caller may bring records in from it.
func (r *Register) CanImport(p *auth.Principal, name string) (*pack.Source, error) {
	return r.source(p, name)
}

func (r *Register) source(p *auth.Principal, name string) (*pack.Source, error) {
	src := r.pk.Source(name)
	if src == nil {
		return nil, fmt.Errorf("no source named %q", name)
	}
	if p == nil || !slices.Contains(src.ImportRoles, p.Acting) {
		return nil, fmt.Errorf("%s may not bring records in from %s", actingOf(p), src.Name)
	}
	return src, nil
}

func actingOf(p *auth.Principal) string {
	if p == nil {
		return "nobody"
	}
	return p.Acting
}

// DescribeSource says what bringing a fetched document in would record,
// and whether the register already holds it as the source says.
func (r *Register) DescribeSource(p *auth.Principal, name, key string, doc map[string]any) (*SourceRecord, error) {
	src, err := r.source(p, name)
	if err != nil {
		return nil, err
	}
	out := &SourceRecord{Source: src.Name, Key: key}
	err = r.st.Do(func(tx *store.Tx) error {
		return r.describeSource(tx, p.Tenant, src, key, doc, out)
	})
	return out, err
}

func (r *Register) describeSource(tx *store.Tx, tenant string, src *pack.Source, key string, doc map[string]any, out *SourceRecord) error {
	payload, status, err := MapSource(r.pk, src, doc)
	if err != nil {
		return err
	}
	class := r.pk.Class(src.Class)
	if got := fmt.Sprint(payload[class.NaturalKey]); got != key {
		return fmt.Errorf("%s answered for %q when asked for %q", src.Name, got, key)
	}
	out.Payload, out.Status = payload, status
	row, err := tx.QueryOne("SELECT id, status FROM `objects` WHERE tenant = " + store.Lit(tenant) +
		" AND class = " + store.Lit(class.Name) + " AND natural_key = " + store.Lit(key))
	if err != nil || row == nil {
		return err
	}
	out.Held, out.ObjectID = true, row.Str("id")
	head, err := r.headVersion(tx, class, out.ObjectID)
	if err != nil {
		return err
	}
	held, err1 := canon.Marshal(head.Payload)
	fetched, err2 := canon.Marshal(payload)
	if err1 != nil || err2 != nil {
		return fmt.Errorf("%s: could not compare with the record held", src.Name)
	}
	out.Current = bytes.Equal(held, fetched) && row.Str("status") == status
	return nil
}

// ImportFromSource records what a source says about one record: a new
// record if the register does not hold it, a new version if the source
// has changed it, nothing if the register is already current. It is the
// register's own act on the source's authority, so it needs no approval;
// the person who asked is named in the message, by role.
func (r *Register) ImportFromSource(p *auth.Principal, name, key string, doc map[string]any) (*SourceRecord, *model.Transaction, error) {
	src, err := r.source(p, name)
	if err != nil {
		return nil, nil, err
	}
	out := &SourceRecord{Source: src.Name, Key: key}
	var txn *model.Transaction
	err = r.st.Do(func(tx *store.Tx) error {
		if err := r.describeSource(tx, p.Tenant, src, key, doc, out); err != nil {
			return err
		}
		if out.Current {
			return nil
		}
		class := r.pk.Class(src.Class)
		at := r.now()
		w := newWriteCtx(p.Tenant, at)
		var ops []model.WriteOp
		verb := "Bring in"
		if out.Held {
			verb = "Refresh"
			ops, err = r.updateOps(tx, w, class, out.ObjectID, out.Payload, out.Status)
		} else {
			out.ObjectID, ops, err = r.createOps(tx, w, class, out.Payload, out.Status)
		}
		if err != nil {
			return err
		}
		txn, err = r.commit(tx, model.Envelope{
			Kind: model.KindSourceImport, Tenant: p.Tenant, Timestamp: at,
			Author: r.systemAuthor(orDefault(src.Title, src.Name)),
			Message: composeMessage(
				clip(fmt.Sprintf("%s %s %s from %s", verb, strings.ReplaceAll(class.Name, "_", " "), key, orDefault(src.Title, src.Name)), model.MaxSummary),
				fmt.Sprintf("Recorded as %s says it, at the request of a %s.", orDefault(src.Title, src.Name), p.Acting)),
		}, ops)
		if err == nil {
			out.Held, out.Current = true, true
		}
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return out, txn, nil
}
