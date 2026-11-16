// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/Privasys/container-app-register/internal/pack"
	"github.com/Privasys/container-app-register/internal/store"
)

// The listing index: the order a page of a class is read in, and what a
// search for part of a value reads, held in memory inside the enclave.
//
// Every row SQL reads is a walk of the ledger, so a page of a large class
// must not read the class. Sorting it would, and so would a search for
// part of a value, which no B-tree index can serve. The register instead
// keeps, per class, each record's id, natural key, status and times, with
// its projected values in lower case. It is derived state, like the SQL
// indexes: built from the ledger on first use, a chunk at a time in
// natural-key order, and brought up to date before each use by reading
// only what changed since, through the query table's index on
// updated_at. A listing takes its candidates, in order, from here; SQL
// then reads just those records and applies every condition the listing
// has, so what is served is still read and verified through the ledger.

type textRow struct {
	id, key, status string
	// raw is the natural key as written: a prefix search and the order
	// read it; key is its lower case, which a text search reads.
	raw              string
	updated, created int64
	cols             map[string]string
}

type classText struct {
	mu    sync.Mutex
	built bool
	since int64 // read every change from this updated_at on
	rows  map[string]*textRow
}

type textIndex struct {
	mu      sync.Mutex
	classes map[string]*classText
}

func (r *Register) classText(tenant, class string) *classText {
	r.text.mu.Lock()
	defer r.text.mu.Unlock()
	if r.text.classes == nil {
		r.text.classes = map[string]*classText{}
	}
	k := tenant + "\x00" + class
	ct := r.text.classes[k]
	if ct == nil {
		ct = &classText{rows: map[string]*textRow{}}
		r.text.classes[k] = ct
	}
	return ct
}

// textChunk is how many records one read takes, so building the index
// never holds the store for long.
const textChunk = 1000

// readObjects reads the objects of one class by id.
func (r *Register) readObjects(ids []string) (map[string]store.Row, error) {
	out := map[string]store.Row{}
	if len(ids) == 0 {
		return out, nil
	}
	lits := make([]string, len(ids))
	for i, id := range ids {
		lits[i] = store.Lit(id)
	}
	rows, err := r.st.Query("SELECT id, natural_key, status, updated_at, created_at FROM `objects` WHERE id IN (" + strings.Join(lits, ", ") + ")")
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out[row.Str("id")] = row
	}
	return out, nil
}

// readProjections reads the query-table rows of some records.
func (r *Register) readProjections(class *pack.Class, ids []string) (map[string]store.Row, error) {
	out := map[string]store.Row{}
	if len(ids) == 0 {
		return out, nil
	}
	lits := make([]string, len(ids))
	for i, id := range ids {
		lits[i] = store.Lit(id)
	}
	rows, err := r.st.Query("SELECT * FROM " + store.Ident(class.QueryTable()) + " WHERE object_id IN (" + strings.Join(lits, ", ") + ")")
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out[row.Str("object_id")] = row
	}
	return out, nil
}

func (ct *classText) ingest(obj, q store.Row) int64 {
	tr := &textRow{
		id: obj.Str("id"), key: strings.ToLower(obj.Str("natural_key")), raw: obj.Str("natural_key"), status: obj.Str("status"),
		updated: obj.Int("updated_at"), created: obj.Int("created_at"), cols: map[string]string{},
	}
	for col, v := range q {
		if v == nil {
			continue
		}
		switch col {
		case "object_id", "tenant", "status", "updated_at":
			continue
		}
		tr.cols[col] = strings.ToLower(fmt.Sprint(v))
	}
	ct.rows[tr.id] = tr
	return tr.updated
}

// build reads the whole class, in natural-key order, a chunk at a time.
// Changes made while it reads are read again by the first refresh, which
// starts from the time the build started, or from the latest change it
// read when the clock is behind the records.
func (r *Register) buildText(ct *classText, tenant string, class *pack.Class) error {
	start := r.now() - 1
	after := ""
	for {
		var objs []store.Row
		if err := r.st.Do(func(tx *store.Tx) error {
			var err error
			objs, err = tx.Query(fmt.Sprintf(
				"SELECT id, natural_key, status, updated_at, created_at FROM `objects` "+
					"WHERE tenant = %s AND class = %s AND natural_key > %s ORDER BY tenant, class, natural_key LIMIT %d",
				store.Lit(tenant), store.Lit(class.Name), store.Lit(after), textChunk))
			return err
		}); err != nil {
			return err
		}
		ids := make([]string, len(objs))
		for i, o := range objs {
			ids[i] = o.Str("id")
		}
		qs, err := r.readProjections(class, ids)
		if err != nil {
			return err
		}
		for _, o := range objs {
			start = max(start, ct.ingest(o, qs[o.Str("id")]))
		}
		if len(objs) < textChunk {
			break
		}
		after = objs[len(objs)-1].Str("natural_key")
	}
	ct.built, ct.since = true, start
	return nil
}

// refreshText reads what changed in the class since the last read.
// Records are never deleted, and every change to a record or its
// projections moves its updated_at. The last second read is read again,
// which is harmless: a later commit can share it.
func (r *Register) refreshText(ct *classText, tenant string, class *pack.Class) error {
	if !ct.built {
		return r.buildText(ct, tenant, class)
	}
	qt := store.Ident(class.QueryTable())
	from := ct.since
	for {
		qs, err := r.st.Query(fmt.Sprintf("SELECT * FROM %s WHERE updated_at >= %d ORDER BY updated_at LIMIT %d", qt, from, textChunk))
		if err != nil {
			return err
		}
		if err := r.ingestChanged(ct, tenant, qs); err != nil {
			return err
		}
		last := from
		for _, q := range qs {
			last = max(last, q.Int("updated_at"))
		}
		if len(qs) < textChunk {
			ct.since = max(ct.since, last)
			return nil
		}
		if last > from {
			from = last
			continue
		}
		// A whole chunk changed in one second: read that second in full,
		// then go on from the next.
		qs, err = r.st.Query(fmt.Sprintf("SELECT * FROM %s WHERE updated_at = %d", qt, from))
		if err != nil {
			return err
		}
		if err := r.ingestChanged(ct, tenant, qs); err != nil {
			return err
		}
		from++
	}
}

func (r *Register) ingestChanged(ct *classText, tenant string, qs []store.Row) error {
	ids := make([]string, 0, len(qs))
	for _, q := range qs {
		if q.Str("tenant") == tenant {
			ids = append(ids, q.Str("object_id"))
		}
	}
	objs, err := r.readObjects(ids)
	if err != nil {
		return err
	}
	for _, q := range qs {
		if o, ok := objs[q.Str("object_id")]; ok && q.Str("tenant") == tenant {
			ct.ingest(o, q)
		}
	}
	return nil
}

// listCandidates lists, in the listing's order, the ids of the records of
// a class with the status asked (any when empty), whose natural key starts
// with search, and, when text is given, whose natural key starts with it
// or whose named columns contain it, case aside. ok is false for an order
// the index does not hold.
func (r *Register) listCandidates(tenant string, class *pack.Class, status, search, text string, cols []string, order string, desc bool) (ids []string, ok bool, err error) {
	var less func(a, b *textRow) bool
	switch order {
	case "", "updated_at":
		less = func(a, b *textRow) bool { return a.updated < b.updated }
	case "created_at":
		less = func(a, b *textRow) bool { return a.created < b.created }
	case "natural_key":
		less = func(a, b *textRow) bool { return a.raw < b.raw }
	case "status":
		less = func(a, b *textRow) bool { return a.status < b.status }
	default:
		return nil, false, nil
	}
	ct := r.classText(tenant, class.Name)
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if err := r.refreshText(ct, tenant, class); err != nil {
		return nil, false, err
	}
	text = strings.ToLower(text)
	var hits []*textRow
	for _, tr := range ct.rows {
		if status != "" && tr.status != status {
			continue
		}
		if search != "" && !strings.HasPrefix(tr.raw, search) {
			continue
		}
		if text != "" {
			match := strings.HasPrefix(tr.key, text)
			for _, c := range cols {
				if match {
					break
				}
				match = strings.Contains(tr.cols[c], text)
			}
			if !match {
				continue
			}
		}
		hits = append(hits, tr)
	}
	sort.Slice(hits, func(i, j int) bool {
		a, b := hits[i], hits[j]
		if desc {
			a, b = b, a
		}
		if less(a, b) {
			return true
		}
		if less(b, a) {
			return false
		}
		return a.id < b.id
	})
	ids = make([]string, len(hits))
	for i, h := range hits {
		ids[i] = h.id
	}
	return ids, true, nil
}

// warmListings builds the listing index of every class in the background,
// so the first listing after a start does not wait for it.
func (r *Register) warmListings() {
	go func() {
		for _, class := range r.pk.Classes {
			ct := r.classText(r.opts.Tenant, class.Name)
			ct.mu.Lock()
			err := r.refreshText(ct, r.opts.Tenant, class)
			ct.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
}
