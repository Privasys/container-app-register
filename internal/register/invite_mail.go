// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Privasys/container-app-register/internal/byok"
	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/store"
)

// RemindAfter is how long an invitation waits unanswered before the
// person is reminded of it.
const RemindAfter = 7 * 24 * time.Hour

// InviteRecipient is who an emailed invitation is for. Everything the
// register persists is a ledger entry, so this is sealed under a key of
// the invitation's own, together with the link's secret the reminder has
// to repeat. The key is destroyed as soon as the invitation is accepted,
// withdrawn or expired, and nothing of the address remains.
type InviteRecipient struct {
	Email        string `json:"email"`
	Name         string `json:"name,omitempty"`
	Organisation string `json:"organisation,omitempty"`
	Secret       string `json:"secret,omitempty"`
}

// InviteReminder is an invitation due its reminder.
type InviteReminder struct {
	Invite *Invite
	To     InviteRecipient
}

func inviteScope(tenant, id string) string { return tenant + "/invite/" + id }

// sealRecipient returns the writes that hold a recipient under a new key.
func (r *Register) sealRecipient(tx *store.Tx, tenant, id string, at int64, to InviteRecipient) ([]model.WriteOp, error) {
	scope := inviteScope(tenant, id)
	dek, ops, err := r.ensureDEK(tx, newWriteCtx(tenant, at), scope, "invite", id)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(to)
	if err != nil {
		return nil, err
	}
	ct, err := byok.Encrypt(dek, scope, id, 0, plain)
	if err != nil {
		return nil, err
	}
	sealed, err := json.Marshal(ct)
	if err != nil {
		return nil, err
	}
	return append(ops, model.WriteOp{
		Table: "invite_recipients",
		Key:   map[string]any{"id": id},
		Values: map[string]any{
			"tenant": tenant, "scope": scope, "sealed": model.Binary(sealed), "reminded_at": int64(0),
		},
	}), nil
}

// forgetRecipient returns the writes that destroy an invitation's
// recipient, and the scope to forget once they commit; nothing for an
// invitation that was issued as a bare link, or already forgotten.
func (r *Register) forgetRecipient(tx *store.Tx, id string, at int64) ([]model.WriteOp, string, error) {
	row, err := tx.QueryOne("SELECT scope FROM `invite_recipients` WHERE id = " + store.Lit(id))
	if err != nil || row == nil {
		return nil, "", err
	}
	scope := row.Str("scope")
	key, err := tx.QueryOne("SELECT destroyed_at FROM `dek_keys` WHERE scope = " + store.Lit(scope))
	if err != nil {
		return nil, "", err
	}
	if key == nil || key.Int("destroyed_at") != 0 {
		return nil, "", nil
	}
	return []model.WriteOp{
		{
			Table: "dek_keys",
			Key:   map[string]any{"scope": scope},
			Values: map[string]any{
				"op_wrap": model.Binary(nil), "rec_wrap": model.Binary(nil), "destroyed_at": at,
			},
		},
		{
			Table:  "invite_recipients",
			Key:    map[string]any{"id": id},
			Values: map[string]any{"sealed": model.Binary(nil)},
		},
	}, scope, nil
}

// openRecipient reads a sealed recipient row.
func (r *Register) openRecipient(tx *store.Tx, row store.Row) (InviteRecipient, bool, error) {
	var to InviteRecipient
	key, err := tx.QueryOne("SELECT op_wrap, destroyed_at FROM `dek_keys` WHERE scope = " + store.Lit(row.Str("scope")))
	if err != nil {
		return to, false, err
	}
	if key == nil || key.Int("destroyed_at") != 0 {
		return to, false, nil
	}
	var ct byok.Ciphertext
	if err := json.Unmarshal(row.Bytes("sealed"), &ct); err != nil {
		return to, false, fmt.Errorf("register: invitation: %w", err)
	}
	dek, err := r.ring.UnwrapOperational(ct.Scope, key.Bytes("op_wrap"))
	if err != nil {
		return to, false, err
	}
	plain, err := byok.Decrypt(dek, &ct, row.Str("id"), 0)
	if err != nil {
		return to, false, err
	}
	if err := json.Unmarshal(plain, &to); err != nil {
		return to, false, fmt.Errorf("register: invitation: %w", err)
	}
	return to, true, nil
}

// InviteReminders lists the open invitations due a reminder.
func (r *Register) InviteReminders() ([]InviteReminder, error) {
	var out []InviteReminder
	err := r.st.Do(func(tx *store.Tx) error {
		rows, err := tx.Query("SELECT * FROM `invite_recipients` WHERE reminded_at = 0")
		if err != nil {
			return err
		}
		for _, row := range rows {
			inviteRow, err := tx.QueryOne("SELECT * FROM `invites` WHERE id = " + store.Lit(row.Str("id")))
			if err != nil {
				return err
			}
			if inviteRow == nil {
				continue
			}
			inv := r.decodeInvite(inviteRow)
			if inv.Status != "open" || r.now() < inv.CreatedAt+int64(RemindAfter.Seconds()) {
				continue
			}
			to, readable, err := r.openRecipient(tx, row)
			if err != nil {
				return err
			}
			if readable {
				out = append(out, InviteReminder{Invite: inv, To: to})
			}
		}
		return nil
	})
	return out, err
}

// MarkReminded records that a reminder went out, so it goes out once.
func (r *Register) MarkReminded(id string) error {
	return r.st.Do(func(tx *store.Tx) error {
		at := r.now()
		_, err := r.commit(tx, model.Envelope{
			Kind: model.KindInviteRemind, Tenant: r.opts.Tenant, Author: r.systemAuthor("Reminders"), Timestamp: at,
			Message: clip("Remind the person invited by invitation "+id, model.MaxSummary),
		}, []model.WriteOp{{
			Table: "invite_recipients", Key: map[string]any{"id": id}, Values: map[string]any{"reminded_at": at},
		}})
		return err
	})
}

// ForgetExpiredRecipients destroys the recipient of every invitation
// that ran out unanswered, and says how many.
func (r *Register) ForgetExpiredRecipients() (int, error) {
	n := 0
	err := r.st.Do(func(tx *store.Tx) error {
		rows, err := tx.Query("SELECT id FROM `invite_recipients`")
		if err != nil {
			return err
		}
		for _, row := range rows {
			id := row.Str("id")
			inviteRow, err := tx.QueryOne("SELECT * FROM `invites` WHERE id = " + store.Lit(id))
			if err != nil {
				return err
			}
			if inviteRow == nil || r.decodeInvite(inviteRow).Status != "expired" {
				continue
			}
			at := r.now()
			ops, scope, err := r.forgetRecipient(tx, id, at)
			if err != nil {
				return err
			}
			if len(ops) == 0 {
				continue
			}
			if _, err := r.commit(tx, model.Envelope{
				Kind: model.KindInviteExpire, Tenant: r.opts.Tenant, Author: r.systemAuthor("Reminders"), Timestamp: at,
				Message: composeMessage(clip("Forget who invitation "+id+" was for", model.MaxSummary),
					"It expired unanswered. Key "+scope+" destroyed."),
			}, ops); err != nil {
				return err
			}
			r.ring.Forget(scope)
			n++
		}
		return nil
	})
	return n, err
}
