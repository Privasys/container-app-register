// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package model holds the wire and storage types shared by the register
// core, the HTTP surface and the verifier.
//
// The central type is Envelope, the git-like commit message every
// state-changing transaction carries. The envelope and the write set
// are hashed together into the transaction id, and both are stored
// verbatim in the ledger, so the root commits to the reason for a
// change as well as the change itself.
package model

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Reference types linking one transaction to earlier work.
const (
	RefCorrects   = "corrects"
	RefSupersedes = "supersedes"
	RefApproves   = "approves"
	RefRelates    = "relates"
)

// Transaction kinds. The kind tells the explorer and the webhook
// consumers what happened without parsing the write set.
const (
	KindSchemaRegister = "schema.register"
	KindPolicySet      = "policy.set"
	KindRecordCreate   = "record.create"
	KindRecordUpdate   = "record.update"
	KindRecordStatus   = "record.status"
	KindRecordCorrect  = "record.correct"
	KindTaskPropose    = "workflow.propose"
	KindTaskAccept     = "workflow.accept"
	KindTaskApprove    = "workflow.approve"
	KindTaskReject     = "workflow.reject"
	KindTaskWithdraw   = "workflow.withdraw"
	KindRetentionPrune = "retention.prune"
	KindErasure        = "erasure.execute"
	KindKeyEnrol       = "key.enrol"
	KindKeyCreate      = "key.create"
	KindKeyDestroy     = "key.destroy"
	KindCheckpoint     = "checkpoint.issue"
	KindWebhookSet     = "webhook.set"
)

// Ref is a typed link from a transaction to an earlier transaction or
// to an object.
type Ref struct {
	Type   string `json:"type"`
	Target string `json:"target"`
}

// Author identifies who made a change and in which capacity. Sub is
// the OIDC subject; Role is the role the author was acting under, which
// is not necessarily the only role they hold.
type Author struct {
	Sub     string `json:"sub"`
	Display string `json:"display,omitempty"`
	Role    string `json:"role"`
}

// Envelope is the commit envelope hashed into every transaction.
type Envelope struct {
	Kind      string   `json:"kind"`
	Tenant    string   `json:"tenant"`
	Class     string   `json:"class,omitempty"`
	SchemaID  string   `json:"schema_id,omitempty"`
	ObjectIDs []string `json:"object_ids,omitempty"`
	Author    Author   `json:"author"`
	Timestamp int64    `json:"timestamp"`
	Message   string   `json:"message"`
	Refs      []Ref    `json:"refs,omitempty"`
}

// Summary returns the first line of the message.
func (e *Envelope) Summary() string {
	if i := strings.IndexByte(e.Message, '\n'); i >= 0 {
		return e.Message[:i]
	}
	return e.Message
}

// Body returns the message body (everything after the blank line that
// follows the summary), or "" when the message is a summary only.
func (e *Envelope) Body() string {
	i := strings.IndexByte(e.Message, '\n')
	if i < 0 {
		return ""
	}
	return strings.TrimLeft(e.Message[i+1:], "\n")
}

// MaxSummary is the git convention the API enforces on the first line.
const MaxSummary = 72

var refTypes = map[string]bool{
	RefCorrects: true, RefSupersedes: true, RefApproves: true, RefRelates: true,
}

// Validate rejects messageless and malformed envelopes. A register
// transaction without a reason is not accepted at any layer: the API
// refuses it, so the ledger never sees one.
func (e *Envelope) Validate() error {
	if e.Kind == "" {
		return errors.New("envelope: kind is required")
	}
	if e.Tenant == "" {
		return errors.New("envelope: tenant is required")
	}
	if e.Author.Sub == "" {
		return errors.New("envelope: author.sub is required")
	}
	if e.Author.Role == "" {
		return errors.New("envelope: author.role is required")
	}
	msg := strings.TrimRight(e.Message, "\n")
	if strings.TrimSpace(msg) == "" {
		return errors.New("envelope: message is required (a transaction must say why)")
	}
	summary := msg
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		summary = msg[:i]
		if msg[i+1] != '\n' && strings.TrimSpace(msg[i+1:]) != "" {
			return errors.New("envelope: message body must be separated from the summary by a blank line")
		}
	}
	if strings.TrimSpace(summary) == "" {
		return errors.New("envelope: message summary is empty")
	}
	if len([]rune(summary)) > MaxSummary {
		return fmt.Errorf("envelope: message summary is %d characters, the limit is %d",
			len([]rune(summary)), MaxSummary)
	}
	if strings.HasSuffix(strings.TrimSpace(summary), ".") {
		return errors.New("envelope: message summary must not end with a full stop")
	}
	for _, r := range e.Refs {
		if !refTypes[r.Type] {
			return fmt.Errorf("envelope: unknown ref type %q", r.Type)
		}
		if r.Target == "" {
			return fmt.Errorf("envelope: ref %q has no target", r.Type)
		}
	}
	e.Message = msg
	return nil
}

// WriteOp is one row-level effect of a transaction. A write set is an
// ordered list of them; applying the same list twice produces the same
// rows, which is what makes crash recovery a replay rather than a
// repair.
//
// String values equal to TxIDPlaceholder are replaced with the
// transaction id when the op is applied. The id is the hash of the
// envelope and the write set together, so a write set cannot contain
// the literal id without defining it in terms of itself.
type WriteOp struct {
	Table  string         `json:"table"`
	Key    map[string]any `json:"key"`
	Values map[string]any `json:"values,omitempty"`
	Delete bool           `json:"delete,omitempty"`
}

// TxIDPlaceholder stands in for the transaction id inside a write set.
const TxIDPlaceholder = "$txid"

// Binary is a byte column's value inside a write set.
//
// A write set is stored as JSON and replayed from it after a crash, and
// encoding/json turns a plain []byte into a bare base64 string, which
// is indistinguishable from text on the way back. Every payload,
// schema document, wrapped key and signature the register writes is a
// byte column, so the encoding is tagged: what goes in as bytes comes
// back as bytes, whatever route it took.
type Binary []byte

// MarshalJSON tags the value so the decoder can tell it from a string.
func (b Binary) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{binaryTag: base64.StdEncoding.EncodeToString(b)})
}

// binaryTag is the single member of a tagged byte value.
const binaryTag = "$bytes"

// DecodeBinary recognises a tagged byte value produced by Binary.
func DecodeBinary(v any) ([]byte, bool) {
	m, ok := v.(map[string]any)
	if !ok || len(m) != 1 {
		return nil, false
	}
	encoded, ok := m[binaryTag].(string)
	if !ok {
		return nil, false
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, false
	}
	return decoded, true
}

// Transaction is the full committed record: the envelope, the write
// set, and where the ledger stood before and after.
type Transaction struct {
	Seq           uint64    `json:"seq"`
	TxID          string    `json:"txid"`
	Envelope      Envelope  `json:"envelope"`
	WriteSet      []WriteOp `json:"write_set"`
	State         string    `json:"state"`
	RootBefore    string    `json:"root_before"`
	RootAfter     string    `json:"root_after,omitempty"`
	VersionBefore uint64    `json:"version_before"`
	VersionAfter  uint64    `json:"version_after,omitempty"`
}

// Transaction states.
const (
	TxPending = "pending"
	TxApplied = "applied"
)

// Object is the head record of one registered entity.
type Object struct {
	ID          string `json:"id"`
	Tenant      string `json:"tenant"`
	Class       string `json:"class"`
	NaturalKey  string `json:"natural_key,omitempty"`
	HeadVersion uint64 `json:"head_version"`
	Status      string `json:"status"`
	CreatedAt   int64  `json:"created_at"`
	UpdatedAt   int64  `json:"updated_at"`
	CreatedTx   string `json:"created_tx"`
	UpdatedTx   string `json:"updated_tx"`
	Erased      bool   `json:"erased"`
}

// RecordVersion is one immutable version of an object's payload.
type RecordVersion struct {
	ObjectID    string         `json:"object_id"`
	Version     uint64         `json:"version"`
	TxID        string         `json:"txid"`
	SchemaID    string         `json:"schema_id"`
	CreatedAt   int64          `json:"created_at"`
	Status      string         `json:"status"`
	PayloadHash string         `json:"payload_hash"`
	Payload     map[string]any `json:"payload,omitempty"`
	EncScope    string         `json:"enc_scope,omitempty"`
	Pruned      bool           `json:"pruned,omitempty"`
	PrunePolicy string         `json:"prune_policy,omitempty"`
	Redacted    []string       `json:"redacted,omitempty"`
	Erased      bool           `json:"erased,omitempty"`
}

// Task is a workflow proposal in flight.
type Task struct {
	ID                string         `json:"id"`
	Tenant            string         `json:"tenant"`
	Workflow          string         `json:"workflow"`
	Class             string         `json:"class"`
	ObjectID          string         `json:"object_id,omitempty"`
	State             string         `json:"state"`
	ProposerSub       string         `json:"proposer_sub"`
	ProposerRole      string         `json:"proposer_role"`
	Counterparty      string         `json:"counterparty,omitempty"`
	CounterpartyState string         `json:"counterparty_state,omitempty"`
	Payload           map[string]any `json:"payload,omitempty"`
	Evidence          map[string]any `json:"evidence,omitempty"`
	Message           string         `json:"message"`
	CreatedAt         int64          `json:"created_at"`
	UpdatedAt         int64          `json:"updated_at"`
	DecidedBy         string         `json:"decided_by,omitempty"`
	DecidedAt         int64          `json:"decided_at,omitempty"`
	DecisionReason    string         `json:"decision_reason,omitempty"`
	Blockers          []string       `json:"blockers,omitempty"`
	TxID              string         `json:"txid,omitempty"`
}

// Task states.
const (
	TaskProposed             = "proposed"
	TaskAwaitingCounterparty = "awaiting_counterparty"
	TaskAwaitingReview       = "awaiting_review"
	TaskApproved             = "approved"
	TaskRejected             = "rejected"
	TaskWithdrawn            = "withdrawn"
)

// Checkpoint is the signed statement that the register was in a given
// authenticated state at a given moment. Customers hold these
// externally; they are what closes the replay-an-old-store residual the
// engine cannot close on its own.
type Checkpoint struct {
	Register    string         `json:"register"`
	Version     uint64         `json:"version"`
	Root        string         `json:"root"`
	IssuedAt    int64          `json:"issued_at"`
	Reason      string         `json:"reason"`
	ImageDigest string         `json:"image_digest,omitempty"`
	TxSeq       uint64         `json:"tx_seq"`
	Summary     map[string]any `json:"summary,omitempty"`
	// Previous names the checkpoint before this one, so the chain links
	// itself. A register that served two histories has to have signed
	// two chains, and the fork is visible in the links.
	Previous *CheckpointRef `json:"previous,omitempty"`
}

// CheckpointRef identifies one checkpoint by the state it attests.
type CheckpointRef struct {
	Version uint64 `json:"version"`
	Root    string `json:"root"`
}

// SignedCheckpoint is a checkpoint with its detached signature and the
// key that produced it.
type SignedCheckpoint struct {
	Checkpoint Checkpoint `json:"checkpoint"`
	KeyID      string     `json:"key_id"`
	Algorithm  string     `json:"alg"`
	Signature  string     `json:"signature"`
}

// EvidenceBundle is the exportable proof package for one row: the
// ledger entry, its inclusion (or absence) proof, the state it was read
// at, and the signed checkpoint that anchors that state.
type EvidenceBundle struct {
	Register    string         `json:"register"`
	Statement   string         `json:"statement"`
	Table       string         `json:"table"`
	PrimaryKey  []any          `json:"primary_key"`
	Present     bool           `json:"present"`
	Row         map[string]any `json:"row,omitempty"`
	LedgerKey   string         `json:"ledger_key"`
	LedgerValue string         `json:"ledger_value,omitempty"`
	// Path is the leaf position the proof is about: the keyed hash of
	// the ledger key. An offline verifier needs it because the mapping
	// from key to path is under the commitment key, which stays in the
	// enclave.
	Path       string            `json:"path"`
	Proof      string            `json:"proof"`
	Root       string            `json:"root"`
	Version    uint64            `json:"version"`
	IssuedAt   int64             `json:"issued_at"`
	Checkpoint *SignedCheckpoint `json:"checkpoint,omitempty"`
	KeyID      string            `json:"key_id"`
	Algorithm  string            `json:"alg"`
	Signature  string            `json:"signature"`
}
