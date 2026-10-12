// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/store"
)

// Membership: who holds which role in this register.
//
// A person who signs in with their wallet reaches the register over a
// sealed session, and the subject the register sees for them is its
// own: no other service shares it, and the identity provider attaches
// no roles to it. So the register keeps its own answer to "who may do
// what", and keeps it the way it keeps everything else: a grant is a
// signed transaction with an author and a reason, and so is taking it
// away. Who made someone a registrar is a question the log answers.

// Member is one role held by one subject.
type Member struct {
	Sub       string `json:"sub"`
	Role      string `json:"role"`
	Display   string `json:"display,omitempty"`
	GrantedBy string `json:"granted_by"`
	GrantedAt int64  `json:"granted_at"`
	TxID      string `json:"txid,omitempty"`
}

// Invite is a single-use link that grants a role to whoever opens it.
type Invite struct {
	ID        string `json:"id"`
	Role      string `json:"role"`
	Label     string `json:"label,omitempty"`
	CreatedBy string `json:"created_by"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
	UsedBy    string `json:"used_by,omitempty"`
	UsedAt    int64  `json:"used_at,omitempty"`
	// Status is "open", "used", "expired" or "revoked".
	Status string `json:"status"`
}

// Invitation lifetimes.
const (
	DefaultInviteLifetime = 7 * 24 * time.Hour
	MaxInviteLifetime     = 30 * 24 * time.Hour
)

// ErrInvite is the one answer every unusable invitation gets. Telling a
// caller whether a link was wrong, spent or expired tells someone
// guessing links which guesses were close.
var ErrInvite = errors.New("this invitation is not valid: it may have been used, withdrawn, or have expired")

func memberID(tenant, sub, role string) string { return tenant + "|" + sub + "|" + role }

// GrantedRoles lists the roles this register granted to a subject. It
// takes no principal: it is how a principal comes to exist.
func (r *Register) GrantedRoles(tenant, sub string) ([]string, string, error) {
	rows, err := r.st.Query("SELECT role, display FROM `members` WHERE tenant = " + store.Lit(tenant) +
		" AND sub = " + store.Lit(sub))
	if err != nil {
		return nil, "", err
	}
	roles := make([]string, 0, len(rows))
	display := ""
	for _, row := range rows {
		roles = append(roles, row.Str("role"))
		if display == "" {
			display = row.Str("display")
		}
	}
	sort.Strings(roles)
	return roles, display, nil
}

// MembersRole names the role an unattended grant gives the first
// administrator: the first role, in name order, that may manage
// membership. A pack that declares none cannot be administered from
// inside, and says so.
func (r *Register) MembersRole() (string, error) {
	for _, spec := range r.pk.Model().Roles() {
		for _, perm := range spec.Permissions {
			if perm == auth.PermMembers {
				return spec.Name, nil
			}
		}
	}
	return "", fmt.Errorf("pack %s declares no role with the %q permission", r.pk.Name, auth.PermMembers)
}

// Members lists every grant.
func (r *Register) Members(p *auth.Principal) ([]Member, error) {
	if !p.Can(auth.PermMembers) {
		return nil, fmt.Errorf("%s may not manage members", p.Acting)
	}
	rows, err := r.st.Query("SELECT sub, role, display, granted_by, granted_at, txid FROM `members` " +
		"WHERE tenant = " + store.Lit(p.Tenant))
	if err != nil {
		return nil, err
	}
	out := make([]Member, 0, len(rows))
	for _, row := range rows {
		out = append(out, Member{
			Sub: row.Str("sub"), Role: row.Str("role"), Display: row.Str("display"),
			GrantedBy: row.Str("granted_by"), GrantedAt: row.Int("granted_at"), TxID: row.Str("txid"),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Sub != out[j].Sub {
			return out[i].Sub < out[j].Sub
		}
		return out[i].Role < out[j].Role
	})
	return out, nil
}

// GrantRole gives a subject a role.
func (r *Register) GrantRole(p *auth.Principal, sub, role, display, reason string) (*model.Transaction, error) {
	if !p.Can(auth.PermMembers) {
		return nil, fmt.Errorf("%s may not manage members", p.Acting)
	}
	sub, display = strings.TrimSpace(sub), strings.TrimSpace(display)
	if sub == "" || len(sub) > 256 {
		return nil, fmt.Errorf("a grant needs the subject it is for")
	}
	var txn *model.Transaction
	err := r.st.Do(func(tx *store.Tx) error {
		var err error
		txn, err = r.grant(tx, model.KindMemberGrant, principalAuthor(p), p.Tenant, sub, role, display, reason, nil)
		return err
	})
	return txn, err
}

// BootstrapMember grants a role on the deployer's behalf, at configure
// time. The author is the register itself and the message says why.
func (r *Register) BootstrapMember(sub, role string) (*model.Transaction, error) {
	var txn *model.Transaction
	err := r.st.Do(func(tx *store.Tx) error {
		var err error
		txn, err = r.grant(tx, model.KindMemberGrant, r.systemAuthor("configure"), r.opts.Tenant, strings.TrimSpace(sub), role, "",
			"Named by the deployer in the configure call.", nil)
		return err
	})
	return txn, err
}

// grant writes one membership row, with whatever else the same action
// changes (a redeemed invitation is spent in the same commit).
func (r *Register) grant(tx *store.Tx, kind string, author model.Author, tenant, sub, role, display, reason string,
	extra []model.WriteOp) (*model.Transaction, error) {
	spec := r.pk.Model().Role(role)
	if spec == nil {
		return nil, fmt.Errorf("no such role %q", role)
	}
	held, err := tx.Query("SELECT role, display FROM `members` WHERE tenant = " + store.Lit(tenant) +
		" AND sub = " + store.Lit(sub))
	if err != nil {
		return nil, err
	}
	for _, row := range held {
		other := row.Str("role")
		if other == role {
			return nil, fmt.Errorf("%s is already registered as %s", clip(sub, 24), role)
		}
		// Refused here rather than at the next sign-in: a grant that
		// breaches separation of duties would lock the person out of
		// both roles, and the log would show a grant that never worked.
		otherSpec := r.pk.Model().Role(other)
		if containsString(spec.IncompatibleWith, other) ||
			(otherSpec != nil && containsString(otherSpec.IncompatibleWith, role)) {
			return nil, fmt.Errorf("separation of duties: %s already holds %s, which may not be held with %s",
				clip(sub, 24), other, role)
		}
		if display == "" {
			display = row.Str("display")
		}
	}

	at := r.now()
	who := orDefault(display, clip(sub, 16))
	ops := append([]model.WriteOp{{
		Table: "members",
		Key:   map[string]any{"id": memberID(tenant, sub, role)},
		Values: map[string]any{
			"tenant": tenant, "sub": sub, "role": role, "display": display,
			"granted_by": author.Sub, "granted_at": at, "txid": model.TxIDPlaceholder,
		},
	}}, extra...)
	env := model.Envelope{
		Kind: kind, Tenant: tenant, Author: author, Timestamp: at,
		Message: composeMessage(clip(fmt.Sprintf("Grant %s to %s", role, who), model.MaxSummary),
			strings.TrimSpace(fmt.Sprintf("%s now holds the role %q (%s).\n%s",
				sub, role, orDefault(spec.Title, role), reason))),
	}
	return r.commit(tx, env, ops)
}

// RevokeRole takes a role away from a subject.
func (r *Register) RevokeRole(p *auth.Principal, sub, role, reason string) (*model.Transaction, error) {
	if !p.Can(auth.PermMembers) {
		return nil, fmt.Errorf("%s may not manage members", p.Acting)
	}
	var txn *model.Transaction
	err := r.st.Do(func(tx *store.Tx) error {
		row, err := tx.QueryOne("SELECT display FROM `members` WHERE id = " +
			store.Lit(memberID(p.Tenant, sub, role)))
		if err != nil {
			return err
		}
		if row == nil {
			return fmt.Errorf("no such member: %s does not hold %s", clip(sub, 24), role)
		}
		// A register nobody can administer cannot be put right from
		// inside, so the last grant of a role that manages membership
		// stays until someone else holds one.
		if spec := r.pk.Model().Role(role); spec != nil && containsString(spec.Permissions, auth.PermMembers) {
			others, err := r.otherAdministrators(tx, p.Tenant, sub)
			if err != nil {
				return err
			}
			if others == 0 {
				return fmt.Errorf("%s is the only member who may manage membership; grant that to someone else first",
					clip(sub, 24))
			}
		}
		at := r.now()
		env := model.Envelope{
			Kind: model.KindMemberRevoke, Tenant: p.Tenant, Author: principalAuthor(p), Timestamp: at,
			Message: composeMessage(
				clip(fmt.Sprintf("Revoke %s from %s", role, orDefault(row.Str("display"), clip(sub, 16))), model.MaxSummary),
				strings.TrimSpace(fmt.Sprintf("%s no longer holds the role %q.\n%s", sub, role, reason))),
		}
		txn, err = r.commit(tx, env, []model.WriteOp{{
			Table: "members", Key: map[string]any{"id": memberID(p.Tenant, sub, role)}, Delete: true,
		}})
		return err
	})
	return txn, err
}

func (r *Register) otherAdministrators(tx *store.Tx, tenant, except string) (int, error) {
	rows, err := tx.Query("SELECT sub, role FROM `members` WHERE tenant = " + store.Lit(tenant))
	if err != nil {
		return 0, err
	}
	seen := map[string]bool{}
	for _, row := range rows {
		spec := r.pk.Model().Role(row.Str("role"))
		if row.Str("sub") == except || spec == nil || !containsString(spec.Permissions, auth.PermMembers) {
			continue
		}
		seen[row.Str("sub")] = true
	}
	return len(seen), nil
}

// -- invitations -----------------------------------------------------------

// CreateInvite issues an invitation and returns its secret, once.
func (r *Register) CreateInvite(p *auth.Principal, role, label string, validFor time.Duration) (*Invite, string, error) {
	if !p.Can(auth.PermMembers) {
		return nil, "", fmt.Errorf("%s may not manage members", p.Acting)
	}
	var (
		inv    *Invite
		secret string
	)
	err := r.st.Do(func(tx *store.Tx) error {
		var err error
		inv, secret, err = r.createInvite(tx, principalAuthor(p), p.Tenant, role, label, validFor)
		return err
	})
	return inv, secret, err
}

// BootstrapInvite issues the first administrator's invitation at
// configure time, when there is nobody yet who could issue one.
func (r *Register) BootstrapInvite(role string, validFor time.Duration) (*Invite, string, error) {
	var (
		inv    *Invite
		secret string
	)
	err := r.st.Do(func(tx *store.Tx) error {
		var err error
		inv, secret, err = r.createInvite(tx, r.systemAuthor("configure"), r.opts.Tenant, role,
			"First administrator", validFor)
		return err
	})
	return inv, secret, err
}

func (r *Register) createInvite(tx *store.Tx, author model.Author, tenant, role, label string,
	validFor time.Duration) (*Invite, string, error) {
	spec := r.pk.Model().Role(role)
	if spec == nil {
		return nil, "", fmt.Errorf("no such role %q", role)
	}
	if validFor <= 0 {
		validFor = DefaultInviteLifetime
	}
	if validFor > MaxInviteLifetime {
		return nil, "", fmt.Errorf("an invitation is valid for at most %d days", int(MaxInviteLifetime.Hours()/24))
	}
	label = strings.TrimSpace(label)
	if len([]rune(label)) > 96 {
		return nil, "", fmt.Errorf("an invitation label is at most 96 characters")
	}
	rawID, rawSecret := make([]byte, 8), make([]byte, 32)
	if _, err := rand.Read(rawID); err != nil {
		return nil, "", err
	}
	if _, err := rand.Read(rawSecret); err != nil {
		return nil, "", err
	}
	secret := base64.RawURLEncoding.EncodeToString(rawSecret)
	hash := sha256.Sum256([]byte(secret))

	at := r.now()
	inv := &Invite{
		ID: hex.EncodeToString(rawID), Role: role, Label: label, CreatedBy: author.Sub,
		CreatedAt: at, ExpiresAt: at + int64(validFor.Seconds()), Status: "open",
	}
	env := model.Envelope{
		Kind: model.KindInviteCreate, Tenant: tenant, Author: author, Timestamp: at,
		Message: composeMessage(
			clip(fmt.Sprintf("Invite %s as %s", orDefault(label, "someone"), role), model.MaxSummary),
			fmt.Sprintf("Invitation %s grants the role %q (%s) to whoever opens it and signs in, once, "+
				"before %s.\nThe link's secret is not part of this record; only its hash is.",
				inv.ID, role, orDefault(spec.Title, role), time.Unix(inv.ExpiresAt, 0).UTC().Format(time.RFC3339))),
	}
	_, err := r.commit(tx, env, []model.WriteOp{{
		Table: "invites",
		Key:   map[string]any{"id": inv.ID},
		Values: map[string]any{
			"tenant": tenant, "role": role, "label": label, "secret_hash": model.Binary(hash[:]),
			"created_by": author.Sub, "created_at": at, "expires_at": inv.ExpiresAt,
			"used_by": "", "used_at": int64(0), "revoked": false, "txid": model.TxIDPlaceholder,
		},
	}})
	if err != nil {
		return nil, "", err
	}
	return inv, secret, nil
}

func (r *Register) decodeInvite(row store.Row) *Invite {
	inv := &Invite{
		ID: row.Str("id"), Role: row.Str("role"), Label: row.Str("label"),
		CreatedBy: row.Str("created_by"), CreatedAt: row.Int("created_at"), ExpiresAt: row.Int("expires_at"),
		UsedBy: row.Str("used_by"), UsedAt: row.Int("used_at"), Status: "open",
	}
	switch {
	case row.Bool("revoked"):
		inv.Status = "revoked"
	case inv.UsedBy != "":
		inv.Status = "used"
	case r.now() > inv.ExpiresAt:
		inv.Status = "expired"
	}
	return inv
}

// Invites lists invitations, newest first. Neither the secret nor its
// hash is served.
func (r *Register) Invites(p *auth.Principal) ([]*Invite, error) {
	if !p.Can(auth.PermMembers) {
		return nil, fmt.Errorf("%s may not manage members", p.Acting)
	}
	rows, err := r.st.Query("SELECT * FROM `invites` WHERE tenant = " + store.Lit(p.Tenant))
	if err != nil {
		return nil, err
	}
	out := make([]*Invite, 0, len(rows))
	for _, row := range rows {
		out = append(out, r.decodeInvite(row))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out, nil
}

// RevokeInvite withdraws an invitation nobody has used.
func (r *Register) RevokeInvite(p *auth.Principal, id string) (*model.Transaction, error) {
	if !p.Can(auth.PermMembers) {
		return nil, fmt.Errorf("%s may not manage members", p.Acting)
	}
	var txn *model.Transaction
	err := r.st.Do(func(tx *store.Tx) error {
		row, err := tx.QueryOne("SELECT * FROM `invites` WHERE id = " + store.Lit(id) +
			" AND tenant = " + store.Lit(p.Tenant))
		if err != nil {
			return err
		}
		if row == nil {
			return fmt.Errorf("no such invitation")
		}
		inv := r.decodeInvite(row)
		if inv.Status != "open" {
			return fmt.Errorf("invitation %s is not awaiting anyone: it is %s", id, inv.Status)
		}
		at := r.now()
		env := model.Envelope{
			Kind: model.KindInviteRevoke, Tenant: p.Tenant, Author: principalAuthor(p), Timestamp: at,
			Message: clip(fmt.Sprintf("Withdraw the invitation for %s", orDefault(inv.Label, inv.Role)), model.MaxSummary),
		}
		txn, err = r.commit(tx, env, []model.WriteOp{{
			Table: "invites", Key: map[string]any{"id": id}, Values: map[string]any{"revoked": true},
		}})
		return err
	})
	return txn, err
}

// openInvite finds a usable invitation and checks the secret against it.
func (r *Register) openInvite(tx *store.Tx, tenant, id, secret string) (*Invite, error) {
	row, err := tx.QueryOne("SELECT * FROM `invites` WHERE id = " + store.Lit(id) +
		" AND tenant = " + store.Lit(tenant))
	if err != nil {
		return nil, err
	}
	// The hash is compared even when there is no row, so a wrong id and
	// a wrong secret take the same time to refuse.
	want := make([]byte, sha256.Size)
	if row != nil {
		want = row.Bytes("secret_hash")
	}
	got := sha256.Sum256([]byte(secret))
	match := subtle.ConstantTimeCompare(got[:], want) == 1
	if row == nil || !match {
		return nil, ErrInvite
	}
	inv := r.decodeInvite(row)
	if inv.Status != "open" {
		return nil, ErrInvite
	}
	return inv, nil
}

// CheckInvite reports what an invitation would grant, without using it.
func (r *Register) CheckInvite(tenant, id, secret string) (*Invite, error) {
	var inv *Invite
	err := r.st.Do(func(tx *store.Tx) error {
		var err error
		inv, err = r.openInvite(tx, tenant, id, secret)
		return err
	})
	return inv, err
}

// RedeemInvite grants the invitation's role to the subject presenting
// it, and spends the invitation in the same commit. The author of the
// transaction is the person who redeemed: they hold no role yet, and
// the record says that too.
func (r *Register) RedeemInvite(tenant, sub, display, id, secret string) (*Invite, *model.Transaction, error) {
	sub = strings.TrimSpace(sub)
	if sub == "" || len(sub) > 256 {
		return nil, nil, fmt.Errorf("an invitation is redeemed by a signed-in person")
	}
	var (
		inv *Invite
		txn *model.Transaction
	)
	err := r.st.Do(func(tx *store.Tx) error {
		var err error
		if inv, err = r.openInvite(tx, tenant, id, secret); err != nil {
			return err
		}
		if display == "" {
			display = inv.Label
		}
		at := r.now()
		spend := model.WriteOp{
			Table: "invites", Key: map[string]any{"id": id},
			Values: map[string]any{"used_by": sub, "used_at": at},
		}
		txn, err = r.grant(tx, model.KindInviteRedeem, model.Author{Sub: sub, Display: display, Role: "invitee"}, tenant, sub,
			inv.Role, display, fmt.Sprintf("Invitation %s, issued by %s.", inv.ID, inv.CreatedBy),
			[]model.WriteOp{spend})
		if err == nil {
			inv.UsedBy, inv.UsedAt, inv.Status = sub, at, "used"
		}
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return inv, txn, nil
}

// Administered reports whether anybody holds a granted role that may
// manage membership.
func (r *Register) Administered() (bool, error) {
	n := 0
	err := r.st.Do(func(tx *store.Tx) error {
		var err error
		n, err = r.otherAdministrators(tx, r.opts.Tenant, "")
		return err
	})
	return n > 0, err
}
