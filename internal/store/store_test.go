// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package store

import (
	"strings"
	"testing"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	var ck [32]byte
	for i := range ck {
		ck[i] = byte(i)
	}
	s, err := Open(t.TempDir(), ck)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return s
}

func TestMigrateIsIdempotent(t *testing.T) {
	s := openTest(t)
	if err := s.Migrate(); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	var tables map[string]bool
	if err := s.Do(func(tx *Tx) error {
		var err error
		tables, err = tx.Tables()
		return err
	}); err != nil {
		t.Fatalf("tables: %v", err)
	}
	for _, want := range []string{"transactions", "objects", "record_versions", "tasks", "natural_keys"} {
		if !tables[want] {
			t.Errorf("table %q missing (got %v)", want, tables)
		}
	}
}

func TestInsertAndReadBack(t *testing.T) {
	s := openTest(t)
	err := s.Do(func(tx *Tx) error {
		stmt := Insert("objects", map[string]any{
			"id": "vehicle-1", "tenant": "gov", "class": "vehicle",
			"natural_key":  "VIN'; DROP TABLE objects; --",
			"head_version": uint64(1), "status": "registered",
			"created_at": int64(1), "updated_at": int64(1),
			"created_tx": strings.Repeat("a", 64), "updated_tx": strings.Repeat("a", 64),
			"erased": false,
		})
		if err := tx.Exec(stmt); err != nil {
			return err
		}
		row, err := tx.QueryOne("SELECT * FROM `objects` WHERE id = " + Lit("vehicle-1"))
		if err != nil {
			return err
		}
		if got := row.Str("natural_key"); got != "VIN'; DROP TABLE objects; --" {
			t.Errorf("natural_key round-trip: %q", got)
		}
		if row.Bool("erased") {
			t.Error("erased should be false")
		}
		if row.Uint("head_version") != 1 {
			t.Errorf("head_version = %d", row.Uint("head_version"))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestBlobRoundTripAndAutoIncrement(t *testing.T) {
	s := openTest(t)
	blob := []byte{0x00, 0x27, 0x5c, 0x1a, 0xff, 0x0a}
	err := s.Do(func(tx *Tx) error {
		stmt := Insert("transactions", map[string]any{
			"txid": strings.Repeat("b", 64), "tenant": "gov", "kind": "record.create",
			"class": "vehicle", "object_id": "vehicle-1", "author_sub": "sub",
			"author_display": "A", "author_role": "registrar",
			"summary": "Registered vehicle", "created_at": int64(10), "state": "pending",
			"root_before": strings.Repeat("0", 64), "root_after": "",
			"version_before": uint64(3), "version_after": uint64(0),
			"envelope": blob, "write_set": []byte("[]"),
		})
		if err := tx.Exec(stmt); err != nil {
			return err
		}
		row, err := tx.QueryOne("SELECT seq, envelope FROM `transactions` WHERE txid = " + Lit(strings.Repeat("b", 64)))
		if err != nil {
			return err
		}
		if row.Uint("seq") != 1 {
			t.Errorf("auto-increment seq = %d, want 1", row.Uint("seq"))
		}
		if got := row.Bytes("envelope"); string(got) != string(blob) {
			t.Errorf("blob round-trip: %x", got)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestLitEscaping(t *testing.T) {
	cases := map[string]string{
		"plain":  "'plain'",
		"it's":   `'it\'s'`,
		"a\\b":   `'a\\b'`,
		"a\nb":   `'a\nb'`,
		"\x00":   `'\0'`,
		`"q"`:    `'\"q\"'`,
		"a\x1ab": `'a\Zb'`,
	}
	for in, want := range cases {
		if got := Lit(in); got != want {
			t.Errorf("Lit(%q) = %s, want %s", in, got, want)
		}
	}
	if got := Lit([]byte{0xde, 0xad}); got != "X'dead'" {
		t.Errorf("Lit(bytes) = %s", got)
	}
	if got := Lit(nil); got != "NULL" {
		t.Errorf("Lit(nil) = %s", got)
	}
}
