// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/canon"
	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/store"
)

// A write set as a reader may see it.
//
// A transaction's write set carries the rows it wrote. The log and the
// histories serve transactions to readers who may see that a change was
// made without being cleared to see what it wrote: an auditor checks the
// history of the register without reading its records. So each write is
// served whole only when the reader may read it: a row of a record (its
// object, its versions, its natural key, its projection) when they may
// read the record's class and the record is within their scope; any
// other row only to a role that both administers the register and is
// cleared for personal data. Other writes keep their table, key and
// whether they delete, and their values give way to a summary: the
// columns, the size and a digest.

// recordTable reports whether a table holds the rows of records, and
// how to find the record a row belongs to.
func recordTable(op model.WriteOp) (objectID string, ok bool) {
	switch {
	case op.Table == "objects":
		return fmt.Sprint(op.Key["id"]), true
	case op.Table == "record_versions":
		return fmt.Sprint(op.Key["object_id"]), true
	case op.Table == "natural_keys":
		return fmt.Sprint(op.Values["object_id"]), true
	case strings.HasPrefix(op.Table, "q_"):
		return fmt.Sprint(op.Key["object_id"]), true
	}
	return "", false
}

// servedWrites returns copies of the transactions with each write the
// caller may not read summarised. The originals are not touched.
func (r *Register) servedWrites(tx *store.Tx, p *auth.Principal, txns []*model.Transaction) ([]*model.Transaction, error) {
	everything := p.PII && p.Can(auth.PermAdmin)
	readable := map[string]bool{}
	mayRead := func(objectID string) (bool, error) {
		if ok, seen := readable[objectID]; seen {
			return ok, nil
		}
		ok := false
		row, err := tx.QueryOne("SELECT class FROM `objects` WHERE id = " + store.Lit(objectID) +
			" AND tenant = " + store.Lit(p.Tenant))
		if err != nil {
			return false, err
		}
		if row != nil {
			if class := r.pk.Class(row.Str("class")); class != nil && p.CanOn(auth.PermRead, class.Name) {
				ok = r.checkScope(tx, p, class, objectID) == nil
			}
		}
		readable[objectID] = ok
		return ok, nil
	}
	out := make([]*model.Transaction, len(txns))
	for i, t := range txns {
		if t == nil {
			continue
		}
		c := *t
		c.WriteSet = make([]model.WriteOp, len(t.WriteSet))
		for j, op := range t.WriteSet {
			c.WriteSet[j] = op
			if op.Values == nil || everything {
				continue
			}
			if id, ok := recordTable(op); ok && id != "" && id != "<nil>" {
				may, err := mayRead(id)
				if err != nil {
					return nil, err
				}
				if may {
					continue
				}
			}
			s, err := summarise(op.Values)
			if err != nil {
				return nil, err
			}
			c.WriteSet[j].Values, c.WriteSet[j].Summary = nil, s
		}
		out[i] = &c
	}
	return out, nil
}

func summarise(values map[string]any) (*model.ValueSummary, error) {
	raw, err := canon.Marshal(values)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	cols := make([]string, 0, len(values))
	for k := range values {
		cols = append(cols, k)
	}
	sort.Strings(cols)
	return &model.ValueSummary{Columns: cols, Bytes: len(raw), Digest: "sha256:" + hex.EncodeToString(sum[:])}, nil
}
