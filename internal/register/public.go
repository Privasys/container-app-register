// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register

import (
	"fmt"
	"sort"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/jsonschema"
	"github.com/Privasys/container-app-register/internal/pack"
)

// The public reader: what anyone may see without signing in. A pack marks
// the public fields of a class with x-register.public; the reader shows
// those and nothing else, for the classes that have any. It reads through
// the same paths as a member does, under a principal the process builds
// for itself, so every row is re-verified through the ledger on the way out.

// PublicRecord is a record as the public sees it.
type PublicRecord struct {
	Class     string         `json:"class"`
	Key       string         `json:"key"`
	Status    string         `json:"status"`
	CreatedAt int64          `json:"created_at"`
	UpdatedAt int64          `json:"updated_at"`
	Fields    map[string]any `json:"fields"`
	History   []PublicChange `json:"history,omitempty"`
}

// PublicChange is one version of a record in the public history: when it
// was written and the status it left the record in. The transaction's
// message is not shown: it is written by people and may name them.
type PublicChange struct {
	Version uint64 `json:"version"`
	At      int64  `json:"at"`
	Status  string `json:"status"`
}

// PublicClass reports whether a class shows anything to the public.
func PublicClass(c *pack.Class) bool {
	if c == nil || c.Compiled() == nil {
		return false
	}
	for _, p := range c.Compiled().Properties {
		if p.Register != nil && p.Register.Public {
			return true
		}
	}
	return false
}

func (r *Register) publicPrincipal(class string) *auth.Principal {
	p := &auth.Principal{Sub: "public", Tenant: r.opts.Tenant, Roles: []string{"public"}, Acting: "public"}
	p.Grant(auth.PermRead + ":" + class)
	return p
}

func (r *Register) publicClass(name string) (*pack.Class, error) {
	c := r.pk.Class(name)
	if !PublicClass(c) {
		return nil, fmt.Errorf("no such public class: %s", name)
	}
	return c, nil
}

// PublicList lists the records of a public class. Match may name only
// public projected fields.
func (r *Register) PublicList(class, search string, match map[string]string, limit, offset int) ([]PublicRecord, error) {
	c, err := r.publicClass(class)
	if err != nil {
		return nil, err
	}
	public := map[string]bool{}
	var text []string
	for _, proj := range c.Compiled().Projections() {
		if s := c.Compiled().Properties[proj.Property]; s != nil && s.Register != nil && s.Register.Public {
			public[proj.Column] = true
			if proj.Type == "string" {
				text = append(text, proj.Column)
			}
		}
	}
	sort.Strings(text)
	for col := range match {
		if !public[col] {
			return nil, fmt.Errorf("%s is not a public field of %s", col, class)
		}
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := r.ListObjects(r.publicPrincipal(class), ListFilter{
		Class: class, Text: search, TextColumns: text, Match: match, Limit: limit, Offset: offset,
		Order: "updated_at", Desc: true,
	})
	if err != nil {
		return nil, err
	}
	out := make([]PublicRecord, 0, len(rows))
	for _, row := range rows {
		fields := map[string]any{}
		for col, v := range row.Projection {
			if public[col] {
				fields[col] = v
			}
		}
		out = append(out, PublicRecord{Class: class, Key: row.NaturalKey, Status: row.Status, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, Fields: fields})
	}
	return out, nil
}

// PublicGet returns one record of a public class by its natural key, with
// its public fields and the dates and statuses of its versions.
func (r *Register) PublicGet(class, key string) (*PublicRecord, error) {
	c, err := r.publicClass(class)
	if err != nil {
		return nil, err
	}
	p := r.publicPrincipal(class)
	rows, err := r.ListObjects(p, ListFilter{Class: class, Search: key, Limit: 5})
	if err != nil {
		return nil, err
	}
	id := ""
	for _, row := range rows {
		if row.NaturalKey == key {
			id = row.ID
		}
	}
	if id == "" {
		return nil, fmt.Errorf("no such %s: %s", class, key)
	}
	view, err := r.GetObject(p, id)
	if err != nil {
		return nil, err
	}
	out := &PublicRecord{
		Class: class, Key: key, Status: view.Object.Status,
		CreatedAt: view.Object.CreatedAt, UpdatedAt: view.Object.UpdatedAt,
		Fields: publicFields(c.Compiled(), view.Version.Payload),
	}
	history, err := r.History(p, id)
	if err != nil {
		return nil, err
	}
	for _, h := range history {
		out.History = append(out.History, PublicChange{Version: h.Version.Version, At: h.Version.CreatedAt, Status: h.Version.Status})
	}
	return out, nil
}

// publicFields keeps a payload's public fields. An envelope {value,
// status, …} keeps its value and its evidence status only; a group's
// entries keep their public members.
func publicFields(s *jsonschema.Schema, payload map[string]any) map[string]any {
	out := map[string]any{}
	for name, v := range payload {
		prop := s.Properties[name]
		if prop == nil || prop.Register == nil || !prop.Register.Public {
			continue
		}
		out[name] = publicValue(prop, v)
	}
	return out
}

func publicValue(prop *jsonschema.Schema, v any) any {
	switch x := v.(type) {
	case []any:
		items := make([]any, 0, len(x))
		for _, e := range x {
			items = append(items, publicValue(prop.Items, e))
		}
		return items
	case map[string]any:
		if prop == nil {
			return nil
		}
		if _, envelope := x["value"]; envelope && prop.Properties["status"] != nil {
			return map[string]any{"value": x["value"], "status": x["status"]}
		}
		// A group entry: its public members only, when the group marks any.
		marked := false
		for _, sub := range prop.Properties {
			if sub.Register != nil && sub.Register.Public {
				marked = true
			}
		}
		if !marked {
			return x
		}
		return publicFields(prop, x)
	default:
		return v
	}
}
