// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package jsonschema validates register payloads against the subset of
// JSON Schema the register uses.
//
// The subset is deliberate rather than incidental. Register schemas are
// ledger objects: once a schema is committed, every record validated
// against it must keep validating the same way forever, on any build.
// A large third-party validator with its own release cadence is a poor
// fit for that promise, so this is a small, dependency-free
// implementation of the keywords a record schema actually needs:
//
//	type, enum, const, required, properties, additionalProperties,
//	items, minItems, maxItems, uniqueItems,
//	minLength, maxLength, pattern, format,
//	minimum, maximum, exclusiveMinimum, exclusiveMaximum, multipleOf
//
// Anything else in a schema document is rejected at registration time,
// so a schema can never appear to constrain something it does not.
package jsonschema

import (
	"encoding/json"
	"fmt"
	"math"
	"net/mail"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Schema is one node of a validated schema document.
type Schema struct {
	Type                 string             `json:"type,omitempty"`
	Title                string             `json:"title,omitempty"`
	Description          string             `json:"description,omitempty"`
	Enum                 []any              `json:"enum,omitempty"`
	Const                any                `json:"const,omitempty"`
	Required             []string           `json:"required,omitempty"`
	Properties           map[string]*Schema `json:"properties,omitempty"`
	AdditionalProperties *bool              `json:"additionalProperties,omitempty"`
	Items                *Schema            `json:"items,omitempty"`
	MinItems             *int               `json:"minItems,omitempty"`
	MaxItems             *int               `json:"maxItems,omitempty"`
	UniqueItems          bool               `json:"uniqueItems,omitempty"`
	MinLength            *int               `json:"minLength,omitempty"`
	MaxLength            *int               `json:"maxLength,omitempty"`
	Pattern              string             `json:"pattern,omitempty"`
	Format               string             `json:"format,omitempty"`
	Minimum              *float64           `json:"minimum,omitempty"`
	Maximum              *float64           `json:"maximum,omitempty"`
	ExclusiveMinimum     *float64           `json:"exclusiveMinimum,omitempty"`
	ExclusiveMaximum     *float64           `json:"exclusiveMaximum,omitempty"`
	MultipleOf           *float64           `json:"multipleOf,omitempty"`

	// Register extension. Kept on the node so a field carries its own
	// handling rules (personal data, queryability) next to its shape.
	Register *FieldRules `json:"x-register,omitempty"`

	compiled *regexp.Regexp
}

// FieldRules is the `x-register` extension on a property.
type FieldRules struct {
	// PII marks a field as personal data: it is encrypted under the
	// record's data-encryption key and redacted for roles that are not
	// cleared to see it.
	PII bool `json:"pii,omitempty"`
	// Queryable projects the field into the class's query table so SQL
	// can filter, sort and count on it.
	Queryable bool `json:"queryable,omitempty"`
	// Indexed adds a secondary index on the projected column.
	Indexed bool `json:"indexed,omitempty"`
	// Unique adds a unique index on the projected column, and makes the
	// core check the constraint before proposing a change.
	Unique bool `json:"unique,omitempty"`
	// Column overrides the projected column name (default: the property
	// name).
	Column string `json:"column,omitempty"`
	// Reference names the class this field points at, so the core can
	// enforce the referential rule the SQL layer has no foreign keys
	// for.
	Reference string `json:"reference,omitempty"`
}

var knownKeywords = map[string]bool{
	"type": true, "title": true, "description": true, "enum": true, "const": true,
	"required": true, "properties": true, "additionalProperties": true,
	"items": true, "minItems": true, "maxItems": true, "uniqueItems": true,
	"minLength": true, "maxLength": true, "pattern": true, "format": true,
	"minimum": true, "maximum": true, "exclusiveMinimum": true,
	"exclusiveMaximum": true, "multipleOf": true, "x-register": true,
}

var knownTypes = map[string]bool{
	"object": true, "array": true, "string": true, "number": true,
	"integer": true, "boolean": true, "null": true,
}

var knownFormats = map[string]bool{
	"date": true, "date-time": true, "email": true, "uri": true, "sha256": true,
}

// Compile parses and checks a schema document, rejecting keywords the
// validator does not implement.
func Compile(doc []byte) (*Schema, error) {
	var s Schema
	if err := json.Unmarshal(doc, &s); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	var probe map[string]any
	if err := json.Unmarshal(doc, &probe); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	if err := checkKeywords(probe, ""); err != nil {
		return nil, err
	}
	if err := s.compile(""); err != nil {
		return nil, err
	}
	return &s, nil
}

func checkKeywords(node map[string]any, path string) error {
	for k, v := range node {
		if !knownKeywords[k] {
			return fmt.Errorf("schema: unsupported keyword %q at %s", k, pathOr(path))
		}
		switch k {
		case "properties":
			props, ok := v.(map[string]any)
			if !ok {
				return fmt.Errorf("schema: properties at %s must be an object", pathOr(path))
			}
			for name, sub := range props {
				child, ok := sub.(map[string]any)
				if !ok {
					return fmt.Errorf("schema: property %q at %s must be an object", name, pathOr(path))
				}
				if err := checkKeywords(child, path+"/"+name); err != nil {
					return err
				}
			}
		case "items":
			child, ok := v.(map[string]any)
			if !ok {
				return fmt.Errorf("schema: items at %s must be an object", pathOr(path))
			}
			if err := checkKeywords(child, path+"/items"); err != nil {
				return err
			}
		}
	}
	return nil
}

func pathOr(p string) string {
	if p == "" {
		return "the document root"
	}
	return p
}

func (s *Schema) compile(path string) error {
	if s.Type != "" && !knownTypes[s.Type] {
		return fmt.Errorf("schema: unsupported type %q at %s", s.Type, pathOr(path))
	}
	if s.Format != "" && !knownFormats[s.Format] {
		return fmt.Errorf("schema: unsupported format %q at %s", s.Format, pathOr(path))
	}
	if s.Pattern != "" {
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			return fmt.Errorf("schema: pattern at %s: %w", pathOr(path), err)
		}
		s.compiled = re
	}
	names := make([]string, 0, len(s.Properties))
	for name := range s.Properties {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := s.Properties[name].compile(path + "/" + name); err != nil {
			return err
		}
	}
	if s.Items != nil {
		if err := s.Items.compile(path + "/items"); err != nil {
			return err
		}
	}
	known := map[string]bool{}
	for _, name := range names {
		known[name] = true
	}
	for _, r := range s.Required {
		if len(s.Properties) > 0 && !known[r] {
			return fmt.Errorf("schema: required property %q at %s is not declared", r, pathOr(path))
		}
	}
	return nil
}

// Errors is the accumulated list of validation failures.
type Errors []string

func (e Errors) Error() string { return strings.Join(e, "; ") }

// Validate checks a decoded JSON value against the schema, reporting
// every failure rather than the first.
func (s *Schema) Validate(v any) error {
	var errs Errors
	s.validate(v, "", &errs)
	if len(errs) == 0 {
		return nil
	}
	return errs
}

func (s *Schema) validate(v any, path string, errs *Errors) {
	if s.Type != "" && !typeMatches(s.Type, v) {
		*errs = append(*errs, fmt.Sprintf("%s: expected %s, got %s", loc(path), s.Type, kindOf(v)))
		return
	}
	if len(s.Enum) > 0 && !containsValue(s.Enum, v) {
		*errs = append(*errs, fmt.Sprintf("%s: %v is not one of the permitted values", loc(path), v))
	}
	if s.Const != nil && !equalValue(s.Const, v) {
		*errs = append(*errs, fmt.Sprintf("%s: must be %v", loc(path), s.Const))
	}

	switch t := v.(type) {
	case string:
		s.validateString(t, path, errs)
	case float64:
		s.validateNumber(t, path, errs)
	case json.Number:
		f, err := t.Float64()
		if err != nil {
			*errs = append(*errs, fmt.Sprintf("%s: %q is not a number", loc(path), t.String()))
		} else {
			s.validateNumber(f, path, errs)
		}
	case []any:
		s.validateArray(t, path, errs)
	case map[string]any:
		s.validateObject(t, path, errs)
	}
}

func (s *Schema) validateString(t, path string, errs *Errors) {
	n := len([]rune(t))
	if s.MinLength != nil && n < *s.MinLength {
		*errs = append(*errs, fmt.Sprintf("%s: shorter than %d characters", loc(path), *s.MinLength))
	}
	if s.MaxLength != nil && n > *s.MaxLength {
		*errs = append(*errs, fmt.Sprintf("%s: longer than %d characters", loc(path), *s.MaxLength))
	}
	if s.compiled != nil && !s.compiled.MatchString(t) {
		*errs = append(*errs, fmt.Sprintf("%s: does not match %s", loc(path), s.Pattern))
	}
	if s.Format != "" && !formatOK(s.Format, t) {
		*errs = append(*errs, fmt.Sprintf("%s: not a valid %s", loc(path), s.Format))
	}
}

func (s *Schema) validateNumber(f float64, path string, errs *Errors) {
	if s.Type == "integer" && f != math.Trunc(f) {
		*errs = append(*errs, fmt.Sprintf("%s: expected an integer", loc(path)))
	}
	if s.Minimum != nil && f < *s.Minimum {
		*errs = append(*errs, fmt.Sprintf("%s: below the minimum %v", loc(path), *s.Minimum))
	}
	if s.Maximum != nil && f > *s.Maximum {
		*errs = append(*errs, fmt.Sprintf("%s: above the maximum %v", loc(path), *s.Maximum))
	}
	if s.ExclusiveMinimum != nil && f <= *s.ExclusiveMinimum {
		*errs = append(*errs, fmt.Sprintf("%s: must be greater than %v", loc(path), *s.ExclusiveMinimum))
	}
	if s.ExclusiveMaximum != nil && f >= *s.ExclusiveMaximum {
		*errs = append(*errs, fmt.Sprintf("%s: must be less than %v", loc(path), *s.ExclusiveMaximum))
	}
	if s.MultipleOf != nil && *s.MultipleOf > 0 {
		q := f / *s.MultipleOf
		if math.Abs(q-math.Round(q)) > 1e-9 {
			*errs = append(*errs, fmt.Sprintf("%s: not a multiple of %v", loc(path), *s.MultipleOf))
		}
	}
}

func (s *Schema) validateArray(t []any, path string, errs *Errors) {
	if s.MinItems != nil && len(t) < *s.MinItems {
		*errs = append(*errs, fmt.Sprintf("%s: fewer than %d items", loc(path), *s.MinItems))
	}
	if s.MaxItems != nil && len(t) > *s.MaxItems {
		*errs = append(*errs, fmt.Sprintf("%s: more than %d items", loc(path), *s.MaxItems))
	}
	if s.UniqueItems {
		seen := map[string]bool{}
		for _, e := range t {
			k := fmt.Sprintf("%T/%v", e, e)
			if seen[k] {
				*errs = append(*errs, fmt.Sprintf("%s: contains duplicate items", loc(path)))
				break
			}
			seen[k] = true
		}
	}
	if s.Items != nil {
		for i, e := range t {
			s.Items.validate(e, fmt.Sprintf("%s/%d", path, i), errs)
		}
	}
}

func (s *Schema) validateObject(t map[string]any, path string, errs *Errors) {
	for _, r := range s.Required {
		if _, ok := t[r]; !ok {
			*errs = append(*errs, fmt.Sprintf("%s: missing required property %q", loc(path), r))
		}
	}
	if s.AdditionalProperties != nil && !*s.AdditionalProperties && len(s.Properties) > 0 {
		extra := make([]string, 0)
		for name := range t {
			if _, ok := s.Properties[name]; !ok {
				extra = append(extra, name)
			}
		}
		sort.Strings(extra)
		for _, name := range extra {
			*errs = append(*errs, fmt.Sprintf("%s: unexpected property %q", loc(path), name))
		}
	}
	names := make([]string, 0, len(s.Properties))
	for name := range s.Properties {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if val, ok := t[name]; ok {
			s.Properties[name].validate(val, path+"/"+name, errs)
		}
	}
}

func loc(path string) string {
	if path == "" {
		return "payload"
	}
	return "payload" + path
}

func typeMatches(want string, v any) bool {
	switch want {
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "null":
		return v == nil
	case "number", "integer":
		switch n := v.(type) {
		case float64:
			return want == "number" || n == math.Trunc(n)
		case json.Number:
			f, err := n.Float64()
			return err == nil && (want == "number" || f == math.Trunc(f))
		}
		return false
	}
	return false
}

func kindOf(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case float64, json.Number:
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return fmt.Sprintf("%T", v)
}

func containsValue(list []any, v any) bool {
	for _, e := range list {
		if equalValue(e, v) {
			return true
		}
	}
	return false
}

func equalValue(a, b any) bool {
	an, aok := numeric(a)
	bn, bok := numeric(b)
	if aok && bok {
		return an == bn
	}
	return fmt.Sprintf("%T/%v", a, a) == fmt.Sprintf("%T/%v", b, b)
}

func numeric(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

func formatOK(format, s string) bool {
	switch format {
	case "date":
		_, err := time.Parse("2006-01-02", s)
		return err == nil
	case "date-time":
		_, err := time.Parse(time.RFC3339, s)
		return err == nil
	case "email":
		_, err := mail.ParseAddress(s)
		return err == nil
	case "uri":
		return strings.Contains(s, ":")
	case "sha256":
		return sha256Re.MatchString(s)
	}
	return true
}

// PIIFields lists the top-level properties marked as personal data.
func (s *Schema) PIIFields() []string {
	var out []string
	for name, p := range s.Properties {
		if p.Register != nil && p.Register.PII {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// Projection describes one column of a class's query table.
type Projection struct {
	Property string
	Column   string
	Type     string
	Indexed  bool
	Unique   bool
}

// Projections lists the properties that project into the class's query
// table, in a stable order so the generated DDL is deterministic.
func (s *Schema) Projections() []Projection {
	var out []Projection
	names := make([]string, 0, len(s.Properties))
	for name := range s.Properties {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		p := s.Properties[name]
		if p.Register == nil || !p.Register.Queryable {
			continue
		}
		col := p.Register.Column
		if col == "" {
			col = name
		}
		out = append(out, Projection{
			Property: name,
			Column:   col,
			Type:     p.Type,
			Indexed:  p.Register.Indexed || p.Register.Unique,
			Unique:   p.Register.Unique,
		})
	}
	return out
}

// References lists the properties that point at another class.
func (s *Schema) References() map[string]string {
	out := map[string]string{}
	for name, p := range s.Properties {
		if p.Register != nil && p.Register.Reference != "" {
			out[name] = p.Register.Reference
		}
	}
	return out
}
