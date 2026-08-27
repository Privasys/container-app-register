package store

import "testing"

func TestTransactionIsOneVersion(t *testing.T) {
	s := openTest(t)
	err := s.Do(func(tx *Tx) error {
		_, before := tx.Root()
		if err := tx.Exec("BEGIN"); err != nil {
			return err
		}
		for _, id := range []string{"a", "b", "c"} {
			if err := tx.Exec(Insert("objects", map[string]any{
				"id": id, "tenant": "gov", "class": "vehicle", "natural_key": id,
				"head_version": uint64(1), "status": "registered",
				"created_at": int64(1), "updated_at": int64(1),
				"created_tx": "x", "updated_tx": "x", "erased": false,
			})); err != nil {
				return err
			}
		}
		_, mid := tx.Root()
		if mid != before {
			t.Errorf("the store moved %d -> %d before COMMIT", before, mid)
		}
		if err := tx.Exec("COMMIT"); err != nil {
			return err
		}
		_, after := tx.Root()
		t.Logf("versions: before=%d during=%d after=%d", before, mid, after)
		if after != before+1 {
			t.Errorf("three statements produced %d versions, want 1", after-before)
		}
		n, err := tx.Count("SELECT COUNT(*) FROM `objects`")
		if err != nil {
			return err
		}
		if n != 3 {
			t.Errorf("rows = %d", n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRollbackLeavesNothing(t *testing.T) {
	s := openTest(t)
	err := s.Do(func(tx *Tx) error {
		_, before := tx.Root()
		if err := tx.Exec("BEGIN"); err != nil {
			return err
		}
		if err := tx.Exec(Insert("registry", map[string]any{
			"k": "probe", "v": []byte("x"), "updated_at": int64(1),
		})); err != nil {
			return err
		}
		if err := tx.Exec("ROLLBACK"); err != nil {
			return err
		}
		_, after := tx.Root()
		if after != before {
			t.Errorf("rollback moved the store %d -> %d", before, after)
		}
		n, err := tx.Count("SELECT COUNT(*) FROM `registry` WHERE k = 'probe'")
		if err != nil {
			return err
		}
		if n != 0 {
			t.Errorf("rolled-back row survived")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
