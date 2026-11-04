// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/byok"
	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/store"
)

// Profile is what the identity provider said about a person when they
// signed in: the address it proved and the name the account carries.
// The identity provider keeps no profile, so these reach the register
// with the first request after a sign-in and with no later one; the
// register records them on first sight and reads them back afterwards.
//
// A person's name and address are personal data, and everything the
// register persists is a ledger entry, so they are never written in the
// clear: they are sealed under a key that belongs to this person alone.
// Destroying that key makes them unreadable everywhere at once, including
// in backups and in the ledger's history, and nothing else is affected.
type Profile struct {
	Sub       string `json:"sub"`
	Email     string `json:"email,omitempty"`
	Name      string `json:"name,omitempty"`
	FirstSeen int64  `json:"first_seen,omitempty"`
	UpdatedAt int64  `json:"updated_at,omitempty"`
	// Erased says the person's key was destroyed. The profile stays
	// unreadable, and a later sign-in does not record it again.
	Erased bool `json:"erased,omitempty"`
}

// sealedProfile is the plaintext of a profile's sealed column.
type sealedProfile struct {
	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`
}

// profileID names a person in key scopes and associated data. A subject
// can be longer than a scope may be, so it is hashed.
func profileID(sub string) string {
	sum := sha256.Sum256([]byte(sub))
	return hex.EncodeToString(sum[:16])
}

// profileScope names the key that protects one person's profile.
func (r *Register) profileScope(sub string) string {
	return r.opts.Tenant + "/person/" + profileID(sub)
}

// openProfile reads a profile row given the key row of its scope.
func (r *Register) openProfile(row, key store.Row) (Profile, error) {
	sub := row.Str("sub")
	out := Profile{Sub: sub, FirstSeen: row.Int("first_seen"), UpdatedAt: row.Int("updated_at")}
	if key == nil || key.Int("destroyed_at") != 0 {
		out.Erased = true
		return out, nil
	}
	var ct byok.Ciphertext
	if err := json.Unmarshal(row.Bytes("sealed"), &ct); err != nil {
		return out, fmt.Errorf("register: profile: %w", err)
	}
	dek, err := r.ring.UnwrapOperational(ct.Scope, key.Bytes("op_wrap"))
	if err != nil {
		return out, err
	}
	plain, err := byok.Decrypt(dek, &ct, profileID(sub), 0)
	if err != nil {
		return out, err
	}
	var sealed sealedProfile
	if err := json.Unmarshal(plain, &sealed); err != nil {
		return out, fmt.Errorf("register: profile: %w", err)
	}
	out.Email, out.Name = sealed.Email, sealed.Name
	return out, nil
}

// profileIn reads a person's profile inside a transaction.
func (r *Register) profileIn(tx *store.Tx, sub string) (Profile, error) {
	row, err := tx.QueryOne("SELECT * FROM `profiles` WHERE sub = " + store.Lit(sub))
	if err != nil || row == nil {
		return Profile{Sub: sub}, err
	}
	key, err := tx.QueryOne("SELECT op_wrap, destroyed_at FROM `dek_keys` WHERE scope = " + store.Lit(row.Str("scope")))
	if err != nil {
		return Profile{Sub: sub}, err
	}
	return r.openProfile(row, key)
}

// Profile is what the register holds for a subject; zero when it has
// never seen the person sign in with a profile.
func (r *Register) Profile(sub string) (Profile, error) {
	out := Profile{Sub: sub}
	err := r.st.Do(func(tx *store.Tx) error {
		var err error
		out, err = r.profileIn(tx, sub)
		return err
	})
	return out, err
}

// SeeIdentity records what a request asserts about a person, either
// value possibly empty, and returns the profile held afterwards. A value
// seen for the first time, or one that differs from what is held, is
// written; an absent one leaves what is held. A request that asserts
// nothing new costs a read, so a profile is written once per sign-in at
// most, and only when something about the person changed.
func (r *Register) SeeIdentity(sub, email, name string) (Profile, error) {
	email, name = truncateRunes(email, 254), truncateRunes(name, 128)
	var held Profile
	err := r.st.Do(func(tx *store.Tx) error {
		var err error
		if held, err = r.profileIn(tx, sub); err != nil {
			return err
		}
		changed := (email != "" && email != held.Email) || (name != "" && name != held.Name)
		if !changed || held.Erased {
			return nil
		}
		if email != "" {
			held.Email = email
		}
		if name != "" {
			held.Name = name
		}
		at := r.now()
		held.UpdatedAt = at
		if held.FirstSeen == 0 {
			held.FirstSeen = at
		}
		w := newWriteCtx(r.opts.Tenant, at)
		scope := r.profileScope(sub)
		dek, ops, err := r.ensureDEK(tx, w, scope, "person", profileID(sub))
		if err != nil {
			return err
		}
		plain, err := json.Marshal(sealedProfile{Email: held.Email, Name: held.Name})
		if err != nil {
			return err
		}
		ct, err := byok.Encrypt(dek, scope, profileID(sub), 0, plain)
		if err != nil {
			return err
		}
		sealed, err := json.Marshal(ct)
		if err != nil {
			return err
		}
		ops = append(ops, model.WriteOp{
			Table: "profiles",
			Key:   map[string]any{"sub": sub},
			Values: map[string]any{
				"scope": scope, "sealed": model.Binary(sealed),
				"first_seen": held.FirstSeen, "updated_at": at,
			},
		})
		_, err = r.commit(tx, model.Envelope{
			Kind: model.KindProfileRecord, Tenant: r.opts.Tenant, Timestamp: at,
			Author:  r.systemAuthor("Sign-in"),
			Message: composeMessage("Record a person's profile", "Sealed under key "+scope+"."),
		}, ops)
		return err
	})
	return held, err
}

// EraseProfile destroys the key of one person's profile, so their name and
// address can no longer be read anywhere. The membership rows and the
// history of what they did stay, and name them only by their subject.
func (r *Register) EraseProfile(p *auth.Principal, sub, reason string) (*model.Transaction, error) {
	if !p.Can(auth.PermErasure) {
		return nil, fmt.Errorf("%s may not carry out erasures", p.Acting)
	}
	sub, reason = strings.TrimSpace(sub), strings.TrimSpace(reason)
	if sub == "" || reason == "" {
		return nil, fmt.Errorf("an erasure names the person and says why")
	}
	var txn *model.Transaction
	err := r.st.Do(func(tx *store.Tx) error {
		row, err := tx.QueryOne("SELECT scope FROM `profiles` WHERE sub = " + store.Lit(sub))
		if err != nil {
			return err
		}
		if row == nil {
			return fmt.Errorf("the register holds no profile for this person")
		}
		scope := row.Str("scope")
		key, err := tx.QueryOne("SELECT destroyed_at FROM `dek_keys` WHERE scope = " + store.Lit(scope))
		if err != nil {
			return err
		}
		if key == nil || key.Int("destroyed_at") != 0 {
			return fmt.Errorf("this person's profile has already been erased")
		}
		at := r.now()
		txn, err = r.commit(tx, model.Envelope{
			Kind: model.KindErasure, Tenant: p.Tenant, Author: principalAuthor(p), Timestamp: at,
			Message: composeMessage(clip("Erase a person's profile", model.MaxSummary),
				composeMessage(reason, "Key "+scope+" destroyed.")),
		}, []model.WriteOp{
			{
				Table: "dek_keys",
				Key:   map[string]any{"scope": scope},
				Values: map[string]any{
					// Both wraps go, as for a record's key: leaving either
					// would make the erasure a promise rather than a fact.
					"op_wrap": model.Binary(nil), "rec_wrap": model.Binary(nil), "destroyed_at": at,
				},
			},
			{
				Table:  "profiles",
				Key:    map[string]any{"sub": sub},
				Values: map[string]any{"sealed": model.Binary(nil), "updated_at": at},
			},
		})
		if err != nil {
			return err
		}
		r.ring.Forget(scope)
		return nil
	})
	return txn, err
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

// profileNames maps every subject with a readable recorded name to that name.
func (r *Register) profileNames() (map[string]string, error) {
	names := map[string]string{}
	err := r.st.Do(func(tx *store.Tx) error {
		rows, err := tx.Query("SELECT * FROM `profiles`")
		if err != nil {
			return err
		}
		for _, row := range rows {
			key, err := tx.QueryOne("SELECT op_wrap, destroyed_at FROM `dek_keys` WHERE scope = " + store.Lit(row.Str("scope")))
			if err != nil {
				return err
			}
			profile, err := r.openProfile(row, key)
			if err != nil {
				return err
			}
			if profile.Name != "" {
				names[profile.Sub] = profile.Name
			}
		}
		return nil
	})
	return names, err
}
