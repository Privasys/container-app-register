// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package pack

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Source is an external register this register takes records from and
// never writes to: a companies register, for instance, that is the master
// of the facts it holds. The register fetches a document from it by key,
// maps the document onto a record of one class, and records it as its own
// act, with no approval, because the source is the authority.
//
// Only the mapping lives in the pack. Where the source is, and whether it
// is the real one or a stand-in, is configuration, so the same pack runs
// against a mock in testing and against the source in production.
type Source struct {
	Name  string `json:"name"`
	Title string `json:"title,omitempty"`
	// Class is the class a fetched document becomes a record of.
	Class string `json:"class"`
	// Path is the location of one document at the source, with {key}
	// standing for the record's natural key.
	Path string `json:"path"`
	// ImportRoles may bring a record in from the source.
	ImportRoles []string `json:"import_roles"`
	// Fields maps each property of the record onto the document.
	Fields map[string]FieldMap `json:"fields"`
	// Envelope is merged into every property whose schema is a value
	// envelope (an object with a "value"), beside the value itself: the
	// verification status and value origin a source's facts carry.
	Envelope map[string]any `json:"envelope,omitempty"`
	// Status decides the record's lifecycle status from the document.
	Status *StatusMap `json:"status,omitempty"`
	// Show names members of the document that a lookup hands to the person
	// who asked, as the source gave them, without recording them: what they
	// need to act on, such as the people to invite, which the record does
	// not keep. Only someone who may bring the record in sees them.
	Show []string `json:"show,omitempty"`
}

// FieldMap says where one property comes from: a path into the document,
// or a constant. Date keeps the date part of an RFC 3339 timestamp.
type FieldMap struct {
	From  string `json:"from,omitempty"`
	Const any    `json:"const,omitempty"`
	Date  bool   `json:"date,omitempty"`
}

// StatusMap reads the record's status from one field of the document.
type StatusMap struct {
	From    string            `json:"from"`
	Map     map[string]string `json:"map"`
	Default string            `json:"default"`
}

// Lookup returns the value at a dotted path in a document, or nil.
func Lookup(doc map[string]any, path string) any {
	var cur any = doc
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[part]
	}
	return cur
}

// PathFor is the source location of the record with this key.
func (s *Source) PathFor(key string) string { return strings.ReplaceAll(s.Path, "{key}", key) }

func (p *Pack) validateSource(s *Source) error {
	if !nameRe.MatchString(s.Name) {
		return fmt.Errorf("source %q: name must match %s", s.Name, nameRe)
	}
	class := p.classByName[s.Class]
	if class == nil {
		return fmt.Errorf("source %s: no class named %q", s.Name, s.Class)
	}
	if class.NaturalKey == "" {
		return fmt.Errorf("source %s: class %s has no natural key to fetch by", s.Name, s.Class)
	}
	if !strings.HasPrefix(s.Path, "/") || !strings.Contains(s.Path, "{key}") {
		return fmt.Errorf("source %s: path must start with / and contain {key}", s.Name)
	}
	if len(s.ImportRoles) == 0 {
		return fmt.Errorf("source %s: name the roles that may import from it", s.Name)
	}
	for _, role := range s.ImportRoles {
		if p.model.Role(role) == nil {
			return fmt.Errorf("source %s: no role named %q", s.Name, role)
		}
	}
	var props struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(class.Schema, &props); err != nil {
		return fmt.Errorf("source %s: %w", s.Name, err)
	}
	if _, ok := s.Fields[class.NaturalKey]; !ok {
		return fmt.Errorf("source %s: the natural key %s must be mapped", s.Name, class.NaturalKey)
	}
	for name, f := range s.Fields {
		if _, ok := props.Properties[name]; !ok {
			return fmt.Errorf("source %s: class %s has no property %q", s.Name, s.Class, name)
		}
		if (f.From == "") == (f.Const == nil) {
			return fmt.Errorf("source %s: field %s needs exactly one of from and const", s.Name, name)
		}
	}
	if s.Status != nil {
		if s.Status.From == "" || !contains(class.Statuses, s.Status.Default) {
			return fmt.Errorf("source %s: the status map needs a field and a default status of %s", s.Name, s.Class)
		}
		for _, status := range s.Status.Map {
			if !contains(class.Statuses, status) {
				return fmt.Errorf("source %s: %q is not a status of %s", s.Name, status, s.Class)
			}
		}
	}
	return nil
}
