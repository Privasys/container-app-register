// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package drafts

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestADraftIsSavedByRevisionAndBelongsToItsOwner(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.Create("gov", "dealer-0001", "sub-ana", "register_vehicle", "Blue Golf", "1.0.0", map[string]any{"model": "Golf"})
	if err != nil || d.Revision != 1 {
		t.Fatalf("create: %+v %v", d, err)
	}

	// A colleague of the same owner carries on; a stale writer is refused.
	saved, err := s.Save("gov", "dealer-0001", "sub-rhys", d.ID, 1, "Blue Golf", map[string]any{"model": "Golf GTI"})
	if err != nil || saved.Revision != 2 || saved.UpdatedBy != "sub-rhys" {
		t.Fatalf("save: %+v %v", saved, err)
	}
	if _, err := s.Save("gov", "dealer-0001", "sub-ana", d.ID, 1, "x", nil); !errors.Is(err, ErrConflict) {
		t.Errorf("a stale save: %v", err)
	}

	// Another owner cannot see it, even with its id.
	if _, err := s.Get("gov", "dealer-0002", d.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("another firm read the draft: %v", err)
	}
	if list, _ := s.List("gov", "dealer-0002"); len(list) != 0 {
		t.Errorf("another firm lists %d drafts", len(list))
	}
	list, err := s.List("gov", "dealer-0001")
	if err != nil || len(list) != 1 || list[0].Payload != nil {
		t.Fatalf("list: %+v %v", list, err)
	}

	// Nothing identifying is written in a file name.
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if strings.Contains(path, "dealer-0001") || strings.Contains(path, "sub-") {
			t.Errorf("a path names its owner: %s", path)
		}
		return nil
	})

	if err := s.Delete("gov", "dealer-0001", d.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("gov", "dealer-0001", d.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("a deleted draft: %v", err)
	}
	if _, err := s.Get("gov", "dealer-0001", "../../etc/passwd"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a path as an id: %v", err)
	}
}
