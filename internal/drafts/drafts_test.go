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
	d, err := s.Create("iom", "900201C", "sub-ana", "provisional_registration", "Calf Bay readings", "1.0.0", map[string]any{"asset_name": "Calf"})
	if err != nil || d.Revision != 1 {
		t.Fatalf("create: %+v %v", d, err)
	}

	// A colleague of the same owner carries on; a stale writer is refused.
	saved, err := s.Save("iom", "900201C", "sub-rhys", d.ID, 1, "Calf Bay readings", map[string]any{"asset_name": "Calf Bay"})
	if err != nil || saved.Revision != 2 || saved.UpdatedBy != "sub-rhys" {
		t.Fatalf("save: %+v %v", saved, err)
	}
	if _, err := s.Save("iom", "900201C", "sub-ana", d.ID, 1, "x", nil); !errors.Is(err, ErrConflict) {
		t.Errorf("a stale save: %v", err)
	}

	// Another owner cannot see it, even with its id.
	if _, err := s.Get("iom", "900202C", d.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("another firm read the draft: %v", err)
	}
	if list, _ := s.List("iom", "900202C"); len(list) != 0 {
		t.Errorf("another firm lists %d drafts", len(list))
	}
	list, err := s.List("iom", "900201C")
	if err != nil || len(list) != 1 || list[0].Payload != nil {
		t.Fatalf("list: %+v %v", list, err)
	}

	// Nothing identifying is written in a file name.
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if strings.Contains(path, "900201C") || strings.Contains(path, "sub-") {
			t.Errorf("a path names its owner: %s", path)
		}
		return nil
	})

	if err := s.Delete("iom", "900201C", d.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("iom", "900201C", d.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("a deleted draft: %v", err)
	}
	if _, err := s.Get("iom", "900201C", "../../etc/passwd"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a path as an id: %v", err)
	}
}
