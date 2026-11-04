// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package store

import (
	"os"
	"path/filepath"
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
			"root_before":    strings.Repeat("0", 64),
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

// A class schema generated from a large field scheme runs to several
// hundred kilobytes; the payload columns must take it.
func TestLargePayloadsFit(t *testing.T) {
	s := openTest(t)
	big := []byte("[" + strings.Repeat(`{"k":"v"},`, 60000) + "{}]")
	if len(big) < 500_000 {
		t.Fatalf("fixture too small: %d", len(big))
	}
	err := s.Do(func(tx *Tx) error {
		if err := tx.Exec(Insert("transactions", map[string]any{
			"txid": strings.Repeat("c", 64), "tenant": "gov", "kind": "schema.create",
			"class": "data_asset", "object_id": "data_asset@1", "author_sub": "sub",
			"author_display": "A", "author_role": "operator",
			"summary": "Schema", "created_at": int64(10), "state": "applied",
			"root_before":    strings.Repeat("0", 64),
			"version_before": uint64(0), "version_after": uint64(1),
			"envelope": []byte("{}"), "write_set": big,
		})); err != nil {
			return err
		}
		row, err := tx.QueryOne("SELECT write_set FROM `transactions` WHERE txid = " + Lit(strings.Repeat("c", 64)))
		if err != nil {
			return err
		}
		if got := row.Bytes("write_set"); len(got) != len(big) {
			t.Errorf("write_set round-trip: %d bytes, want %d", len(got), len(big))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
}

// A directory written by the previous layout is refused with a message
// that says what to do, and a fresh directory is marked.
func TestOtherLayoutsAreRefused(t *testing.T) {
	var ck [32]byte
	dir := t.TempDir()
	s, err := Open(dir, ck)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if b, err := os.ReadFile(filepath.Join(dir, layoutFile)); err != nil || strings.TrimSpace(string(b)) != Layout {
		t.Fatalf("marker after first migrate: %q, %v", b, err)
	}

	// Layout 1 never wrote a marker: tables without one are refused.
	if err := os.Remove(filepath.Join(dir, layoutFile)); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir, ck)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Migrate()
	s.Close()
	if err == nil || !strings.Contains(err.Error(), "layout 1") {
		t.Fatalf("layout 1 directory: %v", err)
	}

	// A marker for a future layout is refused too.
	if err := os.WriteFile(filepath.Join(dir, layoutFile), []byte("9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir, ck)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Migrate()
	s.Close()
	if err == nil || !strings.Contains(err.Error(), "layout 9") {
		t.Fatalf("layout 9 directory: %v", err)
	}
}

// A directory from before profiles were sealed loses its clear names and
// addresses when it is opened, and keeps its memberships.
func TestMigrateRemovesClearProfiles(t *testing.T) {
	s := openTest(t)
	if err := s.Do(func(tx *Tx) error {
		if err := tx.Exec("CREATE TABLE `identities` (sub VARCHAR(256) PRIMARY KEY, email VARCHAR(254) NOT NULL, name VARCHAR(128) NOT NULL)"); err != nil {
			return err
		}
		if err := tx.Exec("INSERT INTO `identities` VALUES ('a', 'a@example.invalid', 'A Person')"); err != nil {
			return err
		}
		return tx.Exec("INSERT INTO `members` VALUES ('m', 't', 'a', 'operator', 'A Person', 'x', 1, 'tx')")
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := s.Do(func(tx *Tx) error {
		tables, err := tx.Tables()
		if err != nil {
			return err
		}
		if tables["identities"] {
			t.Error("the clear table survived")
		}
		row, err := tx.QueryOne("SELECT sub, display FROM `members` WHERE id = 'm'")
		if err != nil {
			return err
		}
		if row == nil || row.Str("sub") != "a" || row.Str("display") != "" {
			t.Errorf("member row %v, want the grant kept without the name", row)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
