// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package jsonschema

import (
	"encoding/json"
	"strings"
	"testing"
)

const vehicleSchema = `{
  "type": "object",
  "additionalProperties": false,
  "required": ["vin", "year"],
  "properties": {
    "vin": { "type": "string", "pattern": "^[A-HJ-NPR-Z0-9]{17}$",
             "x-register": { "queryable": true, "unique": true } },
    "year": { "type": "integer", "minimum": 1885, "maximum": 2100,
              "x-register": { "queryable": true, "indexed": true } },
    "fuel": { "type": "string", "enum": ["petrol", "electric"] },
    "owner": { "type": "string", "x-register": { "pii": true } },
    "first_registration": { "type": "string", "format": "date" },
    "tags": { "type": "array", "items": { "type": "string" }, "maxItems": 3, "uniqueItems": true }
  }
}`

func compile(t *testing.T, doc string) *Schema {
	t.Helper()
	s, err := Compile([]byte(doc))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return s
}

func decode(t *testing.T, doc string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(doc), &v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return v
}

func TestValidPayloadPasses(t *testing.T) {
	s := compile(t, vehicleSchema)
	payload := decode(t, `{"vin":"WVWZZZ1JZXW000001","year":2019,"fuel":"petrol",
	                       "first_registration":"2019-04-02","tags":["a","b"]}`)
	if err := s.Validate(payload); err != nil {
		t.Fatalf("expected the payload to validate: %v", err)
	}
}

func TestEveryFailureIsReported(t *testing.T) {
	s := compile(t, vehicleSchema)
	payload := decode(t, `{"vin":"nope","fuel":"steam","year":1700,"colour":"red","tags":["a","a"]}`)
	err := s.Validate(payload)
	if err == nil {
		t.Fatal("expected the payload to be refused")
	}
	text := err.Error()
	for _, want := range []string{
		"does not match", "not one of the permitted values", "below the minimum",
		"unexpected property", "duplicate items",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the report does not mention %q:\n%s", want, text)
		}
	}
}

func TestUnsupportedKeywordsAreRefusedAtCompileTime(t *testing.T) {
	// A schema is a ledger object: once committed, it must keep meaning
	// what it meant. A keyword the validator ignores would be a schema
	// that appears to constrain something and does not.
	_, err := Compile([]byte(`{"type":"object","oneOf":[{"type":"string"}]}`))
	if err == nil || !strings.Contains(err.Error(), "oneOf") {
		t.Fatalf("expected oneOf to be refused, got %v", err)
	}
	_, err = Compile([]byte(`{"type":"object","properties":{"x":{"type":"string","allOf":[]}}}`))
	if err == nil || !strings.Contains(err.Error(), "allOf") {
		t.Fatalf("expected a nested unsupported keyword to be refused, got %v", err)
	}
	_, err = Compile([]byte(`{"type":"tuple"}`))
	if err == nil || !strings.Contains(err.Error(), "tuple") {
		t.Fatalf("expected an unknown type to be refused, got %v", err)
	}
	_, err = Compile([]byte(`{"type":"object","required":["missing"],"properties":{"x":{"type":"string"}}}`))
	if err == nil {
		t.Fatal("expected a required property that is not declared to be refused")
	}
}

func TestRegisterAnnotations(t *testing.T) {
	s := compile(t, vehicleSchema)
	if got := s.PIIFields(); len(got) != 1 || got[0] != "owner" {
		t.Errorf("personal-data fields = %v", got)
	}
	projections := s.Projections()
	if len(projections) != 2 {
		t.Fatalf("expected 2 projected columns, got %v", projections)
	}
	if projections[0].Column != "vin" || !projections[0].Unique {
		t.Errorf("vin projection = %+v", projections[0])
	}
	if projections[1].Column != "year" || projections[1].Type != "integer" {
		t.Errorf("year projection = %+v", projections[1])
	}
}

func TestFormats(t *testing.T) {
	s := compile(t, `{"type":"object","properties":{
		"d":{"type":"string","format":"date"},
		"e":{"type":"string","format":"email"},
		"h":{"type":"string","format":"sha256"}}}`)
	if err := s.Validate(decode(t, `{"d":"2026-08-27","e":"a@b.example","h":"`+
		strings.Repeat("a", 64)+`"}`)); err != nil {
		t.Fatalf("valid formats refused: %v", err)
	}
	if err := s.Validate(decode(t, `{"d":"27/08/2026"}`)); err == nil {
		t.Error("expected a malformed date to be refused")
	}
	if err := s.Validate(decode(t, `{"h":"ABC"}`)); err == nil {
		t.Error("expected a malformed digest to be refused")
	}
}
