// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register

import "github.com/Privasys/container-app-register/internal/store"

// Profile is what the identity provider said about a person when they
// signed in: the address it proved and the name the account carries.
// The identity provider keeps no profile, so these reach the register
// with the first request after a sign-in and with no later one; the
// register records them on first sight and reads them back afterwards.
type Profile struct {
	Sub       string `json:"sub"`
	Email     string `json:"email,omitempty"`
	Name      string `json:"name,omitempty"`
	FirstSeen int64  `json:"first_seen,omitempty"`
	UpdatedAt int64  `json:"updated_at,omitempty"`
}

// Profile is what the register holds for a subject; zero when it has
// never seen the person sign in with a profile.
func (r *Register) Profile(sub string) (Profile, error) {
	rows, err := r.st.Query("SELECT email, name, first_seen, updated_at FROM `identities` WHERE sub = " + store.Lit(sub))
	if err != nil || len(rows) == 0 {
		return Profile{Sub: sub}, err
	}
	row := rows[0]
	return Profile{Sub: sub, Email: row.Str("email"), Name: row.Str("name"),
		FirstSeen: row.Int("first_seen"), UpdatedAt: row.Int("updated_at")}, nil
}

// SeeIdentity records what a request asserts about a person, either
// value possibly empty, and returns the profile held afterwards. A value
// seen for the first time, or one that differs from what is held, is
// written; an absent one leaves what is held. A request that asserts
// nothing new costs a read, so a profile is written once per sign-in at
// most, and only when something about the person changed.
func (r *Register) SeeIdentity(sub, email, name string) (Profile, error) {
	held, err := r.Profile(sub)
	if err != nil {
		return held, err
	}
	email, name = truncateRunes(email, 254), truncateRunes(name, 128)
	changed := (email != "" && email != held.Email) || (name != "" && name != held.Name)
	if !changed {
		return held, nil
	}
	if email != "" {
		held.Email = email
	}
	if name != "" {
		held.Name = name
	}
	held.UpdatedAt = r.now()
	values := map[string]any{"email": held.Email, "name": held.Name, "updated_at": held.UpdatedAt}
	err = r.st.Do(func(tx *store.Tx) error {
		if held.FirstSeen == 0 {
			held.FirstSeen = held.UpdatedAt
			values["sub"], values["first_seen"] = sub, held.FirstSeen
			return tx.Exec(store.Insert("identities", values))
		}
		return tx.Exec(store.Update("identities", values, "sub = "+store.Lit(sub)))
	})
	return held, err
}

// truncateRunes keeps the first n characters of s, never cutting a
// character in two: a name is stored as it was written, or shorter.
func truncateRunes(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n])
}

// profileNames maps every subject with a recorded name to that name.
func (r *Register) profileNames() (map[string]string, error) {
	rows, err := r.st.Query("SELECT sub, name FROM `identities` WHERE name <> ''")
	if err != nil {
		return nil, err
	}
	names := make(map[string]string, len(rows))
	for _, row := range rows {
		names[row.Str("sub")] = row.Str("name")
	}
	return names, nil
}
