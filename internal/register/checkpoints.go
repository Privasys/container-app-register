// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"

	ledger "github.com/Privasys/immutable-ledger/ledger"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/checkpoint"
	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/store"
)

// Root checkpoints are the register's external anchor. Everything else
// here is verifiable from the inside; a checkpoint is what a customer
// holds on the outside, so a register rolled back to an earlier state
// cannot pass it off as the current one.
//
// # Why checkpoints are not ledger rows
//
// The obvious design is to store each checkpoint as a row like
// everything else, so the root attests the chain too. It cannot work: a
// checkpoint states the root at a version, and writing it would advance
// the version past the one it states. Every checkpoint would then
// attest a state the register had already left, and no evidence read
// afterwards could ever be anchored exactly.
//
// So checkpoints live beside the ledger rather than inside it, and the
// chain carries its own integrity instead: each one names the version
// and root of the one before it, and all of them are signed. A register
// that served two histories has to have signed both, which is precisely
// what the chain check looks for. Issuing a checkpoint moves no
// version, so a checkpoint always attests exactly the state that is
// current when it is taken.

// Checkpoint reasons.
const (
	ReasonScheduled = "scheduled"
	ReasonEvent     = "event"
	ReasonManual    = "manual"
	ReasonBootstrap = "bootstrap"
)

// checkpointPrefix is the backend keyspace checkpoints live in. It sits
// outside every prefix the ledger and its SQL layer use for their own
// records.
const checkpointPrefix = 'K'

func checkpointKey(version uint64) []byte {
	k := make([]byte, 0, 9)
	k = append(k, checkpointPrefix)
	return binary.BigEndian.AppendUint64(k, version)
}

// IssueCheckpoint signs the register's current state and records it.
// The signing key lives on the sealed volume, so only a build the app
// owner has approved can produce one, and the measurement of that build
// is stamped into the checkpoint so a reader can tell which.
func (r *Register) IssueCheckpoint(reason string) (*model.SignedCheckpoint, error) {
	var signed *model.SignedCheckpoint
	err := r.st.Do(func(tx *store.Tx) error {
		var err error
		signed, err = r.issueCheckpoint(tx, reason)
		return err
	})
	if err != nil {
		return nil, err
	}
	if signed == nil {
		return r.LatestCheckpoint(), nil
	}
	if r.notify != nil {
		r.notify.CheckpointIssued(signed)
	}
	return signed, nil
}

// issueCheckpoint is the body, callable from a caller that already
// holds the store.
func (r *Register) issueCheckpoint(tx *store.Tx, reason string) (*model.SignedCheckpoint, error) {
	root, version := tx.Root()
	previous := r.LatestCheckpoint()
	if previous != nil && previous.Checkpoint.Version == version {
		// The state has not moved. A checkpoint that repeats the
		// previous one is not more evidence.
		return nil, nil
	}

	summary, txSeq, err := r.checkpointSummary(tx)
	if err != nil {
		return nil, err
	}
	cp := model.Checkpoint{
		Register: r.opts.Name, Version: version, Root: root,
		IssuedAt: r.now(), Reason: reason, ImageDigest: r.opts.ImageDigest,
		TxSeq: txSeq, Summary: summary,
	}
	if previous != nil {
		cp.Previous = &model.CheckpointRef{
			Version: previous.Checkpoint.Version,
			Root:    previous.Checkpoint.Root,
		}
	}
	signed, err := checkpoint.Sign(r.mat.Signer, r.mat.KeyID, cp)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(signed)
	if err != nil {
		return nil, err
	}
	if err := tx.Ledger().Backend().WriteBatch([]ledger.BatchOp{
		{Key: checkpointKey(version), Value: body},
	}); err != nil {
		return nil, fmt.Errorf("register: record checkpoint: %w", err)
	}

	r.mu.Lock()
	r.lastCkpt = signed
	r.mu.Unlock()
	return signed, nil
}

// anchorCurrentState makes sure the state a caller is about to be given
// evidence about is one the register has publicly committed to. Because
// issuing a checkpoint moves no version, the anchor is exact, and
// because it is skipped when the state has not moved, the number of
// checkpoints follows the rate of change rather than the rate of
// requests.
func (r *Register) anchorCurrentState(tx *store.Tx) (*model.SignedCheckpoint, error) {
	if signed, err := r.issueCheckpoint(tx, ReasonEvent); err != nil {
		return nil, err
	} else if signed != nil {
		if r.notify != nil {
			r.notify.CheckpointIssued(signed)
		}
		return signed, nil
	}
	return r.LatestCheckpoint(), nil
}

func (r *Register) checkpointSummary(tx *store.Tx) (map[string]any, uint64, error) {
	counts := map[string]int64{}
	for name, stmt := range map[string]string{
		"transactions":    "SELECT COUNT(*) FROM `transactions`",
		"objects":         "SELECT COUNT(*) FROM `objects`",
		"pruned_versions": "SELECT COUNT(*) FROM `record_versions` WHERE pruned = TRUE",
		"destroyed_keys":  "SELECT COUNT(*) FROM `dek_keys` WHERE destroyed_at <> 0",
	} {
		n, err := tx.Count(stmt)
		if err != nil {
			return nil, 0, err
		}
		counts[name] = n
	}
	var seq uint64
	if row, err := tx.QueryOne("SELECT seq FROM `transactions` ORDER BY seq DESC LIMIT 1"); err == nil && row != nil {
		seq = row.Uint("seq")
	}
	return map[string]any{
		"pack":                r.pk.Name + " " + r.pk.Version,
		"transactions":        counts["transactions"],
		"objects":             counts["objects"],
		"pruned_versions":     counts["pruned_versions"],
		"destroyed_keys":      counts["destroyed_keys"],
		"commitment_key_from": r.opts.KeySource,
	}, seq, nil
}

// LatestCheckpoint returns the most recent signed checkpoint.
func (r *Register) LatestCheckpoint() *model.SignedCheckpoint {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.lastCkpt
}

func (r *Register) loadLastCheckpoint() error {
	return r.st.Do(func(tx *store.Tx) error {
		list, err := readCheckpoints(tx, 1, true)
		if err != nil || len(list) == 0 {
			return err
		}
		r.mu.Lock()
		r.lastCkpt = list[0]
		r.mu.Unlock()
		return nil
	})
}

// readCheckpoints scans the checkpoint keyspace. Versions are stored
// big-endian, so the scan is already in chain order.
func readCheckpoints(tx *store.Tx, limit int, newestFirst bool) ([]*model.SignedCheckpoint, error) {
	start := []byte{checkpointPrefix}
	end := []byte{checkpointPrefix + 1}
	var out []*model.SignedCheckpoint
	for {
		kvs, err := tx.Ledger().Backend().Scan(start, end, 256)
		if err != nil {
			return nil, fmt.Errorf("register: read checkpoints: %w", err)
		}
		if len(kvs) == 0 {
			break
		}
		for _, kv := range kvs {
			var sc model.SignedCheckpoint
			if err := json.Unmarshal(kv.Value, &sc); err != nil {
				return nil, fmt.Errorf("register: checkpoint record: %w", err)
			}
			out = append(out, &sc)
		}
		last := kvs[len(kvs)-1].Key
		start = append(append([]byte{}, last...), 0)
	}
	if newestFirst {
		for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Checkpoints returns the checkpoint chain, newest first.
func (r *Register) Checkpoints(p *auth.Principal, limit int) ([]*model.SignedCheckpoint, error) {
	if !p.Can(auth.PermCheckpoints) {
		return nil, fmt.Errorf("%s may not read checkpoints", p.Acting)
	}
	var out []*model.SignedCheckpoint
	err := r.st.Do(func(tx *store.Tx) error {
		var err error
		out, err = readCheckpoints(tx, clampLimit(limit), true)
		return err
	})
	return out, err
}

// VerificationKey is the public half of the checkpoint signing key,
// published so a customer can verify what the register signs without
// asking the register.
func (r *Register) VerificationKey() (keyID, publicKey string) {
	return r.mat.KeyID, base64.StdEncoding.EncodeToString(r.mat.PublicKey())
}
