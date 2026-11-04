// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register_test

import "testing"

const (
	profileName  = "CANARY Profile"
	profileEmail = "canary.profile@example.invalid"
)

// A person's name and address are sealed from the moment they are first
// seen: no ledger leaf holds them, including the transaction that recorded
// them and the grant of a role to the person.
func TestAProfileIsNeverInTheClear(t *testing.T) {
	h := newHarness(t)
	h.tick()
	held, err := h.reg.SeeIdentity("sub-canary", profileEmail, profileName)
	if err != nil {
		t.Fatal(err)
	}
	if held.Name != profileName || held.Email != profileEmail || held.FirstSeen == 0 {
		t.Fatalf("held %+v", held)
	}
	operator := h.principal("operator-1", "operator")
	h.tick()
	if _, err := h.reg.GrantRole(operator, "sub-canary", "registrar", "", "Test grant."); err != nil {
		t.Fatalf("grant: %v", err)
	}
	// A name given with a grant goes into the sealed profile, not the grant.
	h.tick()
	if _, err := h.reg.GrantRole(operator, "sub-named", "registrar", "CANARY Given", "Test grant."); err != nil {
		t.Fatalf("grant with a name: %v", err)
	}
	if p, err := h.reg.Profile("sub-named"); err != nil || p.Name != "CANARY Given" {
		t.Fatalf("the name given with the grant: %+v %v", p, err)
	}
	for _, needle := range []string{profileName, profileEmail, "CANARY Given"} {
		if leaks := leaksIn(t, h, needle); len(leaks) != 0 {
			t.Errorf("%q is in the clear in %d ledger leaves: %v", needle, len(leaks), leaks)
		}
	}
	read, err := h.reg.Profile("sub-canary")
	if err != nil || read.Name != profileName || read.Email != profileEmail {
		t.Fatalf("read back %+v: %v", read, err)
	}
}

// A later sign-in that says nothing leaves the profile, one that changes a
// value updates it, and a person never seen has nothing.
func TestAProfileFollowsWhatSignInSays(t *testing.T) {
	h := newHarness(t)
	h.tick()
	if _, err := h.reg.SeeIdentity("sub-a", profileEmail, profileName); err != nil {
		t.Fatal(err)
	}
	h.tick()
	if p, err := h.reg.SeeIdentity("sub-a", "", ""); err != nil || p.Name != profileName || p.Email != profileEmail {
		t.Fatalf("after an empty sign-in: %+v %v", p, err)
	}
	h.tick()
	if p, err := h.reg.SeeIdentity("sub-a", "", "New Name"); err != nil || p.Name != "New Name" || p.Email != profileEmail {
		t.Fatalf("after a change: %+v %v", p, err)
	}
	if p, err := h.reg.Profile("sub-unknown"); err != nil || p.Name != "" || p.FirstSeen != 0 {
		t.Fatalf("unknown person: %+v %v", p, err)
	}
}

// Destroying the key makes the profile unreadable, leaves other people's
// alone, is refused without the permission, and is not undone by the person
// signing in again.
func TestErasingAProfileDestroysItsKey(t *testing.T) {
	h := newHarness(t)
	h.tick()
	if _, err := h.reg.SeeIdentity("sub-gone", profileEmail, profileName); err != nil {
		t.Fatal(err)
	}
	h.tick()
	if _, err := h.reg.SeeIdentity("sub-kept", "kept@example.invalid", "Kept Person"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.reg.EraseProfile(h.principal("registrar-1", "registrar"), "sub-gone", "Subject request."); err == nil {
		t.Fatal("a role without the erasure permission erased a profile")
	}
	dpo := h.principal("dpo-1", "dpo")
	h.tick()
	if _, err := h.reg.EraseProfile(dpo, "sub-gone", ""); err == nil {
		t.Fatal("an erasure without a reason was accepted")
	}
	if _, err := h.reg.EraseProfile(dpo, "sub-gone", "Subject request."); err != nil {
		t.Fatalf("erase: %v", err)
	}
	p, err := h.reg.Profile("sub-gone")
	if err != nil || !p.Erased || p.Name != "" || p.Email != "" {
		t.Fatalf("after erasure: %+v %v", p, err)
	}
	h.tick()
	if p, err := h.reg.SeeIdentity("sub-gone", profileEmail, profileName); err != nil || !p.Erased || p.Name != "" {
		t.Fatalf("a later sign-in brought the profile back: %+v %v", p, err)
	}
	if p, err := h.reg.Profile("sub-kept"); err != nil || p.Name != "Kept Person" {
		t.Fatalf("another person's profile: %+v %v", p, err)
	}
	h.tick()
	if _, err := h.reg.EraseProfile(dpo, "sub-gone", "Again."); err == nil {
		t.Fatal("erased twice")
	}
}
