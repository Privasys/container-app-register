// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register

import (
	"fmt"

	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/pack"
	"github.com/Privasys/container-app-register/internal/store"
)

// The three shapes a record change takes. A register never edits in
// place: creating, updating and moving through a lifecycle all append a
// new immutable version, and the object's head moves to it.

// writeCtx carries what every effect of one transaction shares: the
// tenant, the instant, and the records the same write set has already
// created.
//
// That last part matters because a write set is built in full before
// any of it is applied. A first registration creates a vehicle and a
// plate that points at it, and the plate's reference has to resolve
// against a vehicle that exists in the write set but not yet in the
// store.
type writeCtx struct {
	tenant  string
	at      int64
	pending map[string]string // object id → class
}

func newWriteCtx(tenant string, at int64) *writeCtx {
	return &writeCtx{tenant: tenant, at: at, pending: map[string]string{}}
}

// createOps mints an object and writes its first version.
func (r *Register) createOps(tx *store.Tx, w *writeCtx, class *pack.Class, payload map[string]any, status string) (string, []model.WriteOp, error) {
	if status == "" {
		status = class.Initial
	}
	if !containsString(class.Statuses, status) {
		return "", nil, fmt.Errorf("%q is not a status of %s", status, class.Name)
	}
	objectID, err := NewObjectID(class.Name)
	if err != nil {
		return "", nil, err
	}
	schemaID, err := r.activeSchemaID(tx, class.Name)
	if err != nil {
		return "", nil, err
	}
	ops, err := r.buildRecordOps(tx, w, recordDraft{
		class: class, objectID: objectID, version: 1, status: status,
		payload: payload, schemaID: schemaID,
	})
	if err != nil {
		return "", nil, err
	}
	w.pending[objectID] = class.Name
	return objectID, ops, nil
}

// updateOps appends a new version of an existing object.
func (r *Register) updateOps(tx *store.Tx, w *writeCtx, class *pack.Class, objectID string, payload map[string]any, status string) ([]model.WriteOp, error) {
	head, err := r.objectRow(tx, w.tenant, objectID)
	if err != nil {
		return nil, err
	}
	if head.Str("class") != class.Name {
		return nil, fmt.Errorf("%s is a %s, not a %s", objectID, head.Str("class"), class.Name)
	}
	if head.Bool("erased") {
		return nil, fmt.Errorf("%s has been erased and cannot be amended", objectID)
	}
	if status == "" {
		status = head.Str("status")
	}
	if !containsString(class.Statuses, status) {
		return nil, fmt.Errorf("%q is not a status of %s", status, class.Name)
	}
	schemaID, err := r.activeSchemaID(tx, class.Name)
	if err != nil {
		return nil, err
	}
	return r.buildRecordOps(tx, w, recordDraft{
		class: class, objectID: objectID, version: head.Uint("head_version") + 1,
		status: status, payload: payload, schemaID: schemaID,
	})
}

// statusOps moves an object to a new status by appending a version that
// carries the same payload. The lifecycle is part of the record, so a
// status change is a version like any other and shows up in the
// object's history in the same place.
func (r *Register) statusOps(tx *store.Tx, w *writeCtx, class *pack.Class, objectID, status string) ([]model.WriteOp, error) {
	current, err := r.headVersion(tx, class, objectID)
	if err != nil {
		return nil, err
	}
	if current.Status == status {
		return nil, nil
	}
	return r.updateOps(tx, w, class, objectID, current.Payload, status)
}

// headVersion reads an object's current version with full access to its
// payload: the caller is the register itself, rewriting the record.
func (r *Register) headVersion(tx *store.Tx, class *pack.Class, objectID string) (*model.RecordVersion, error) {
	row, err := tx.QueryOne("SELECT * FROM `record_versions` WHERE object_id = " + store.Lit(objectID) +
		" ORDER BY version DESC LIMIT 1")
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, fmt.Errorf("%s has no versions", objectID)
	}
	if row.Bool("pruned") {
		return nil, &PruneError{ObjectID: objectID, Version: row.Uint("version"), Policy: row.Str("prune_policy")}
	}
	return r.readVersion(tx, nil, class, row)
}

func (r *Register) objectRow(tx *store.Tx, tenant, objectID string) (store.Row, error) {
	row, err := tx.QueryOne("SELECT * FROM `objects` WHERE id = " + store.Lit(objectID) +
		" AND tenant = " + store.Lit(tenant))
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, fmt.Errorf("%s is not registered", objectID)
	}
	return row, nil
}

// activeSchemaID names the schema version records of a class are being
// validated against right now.
func (r *Register) activeSchemaID(tx *store.Tx, class string) (string, error) {
	row, err := tx.QueryOne("SELECT id FROM `schemas` WHERE class = " + store.Lit(class) +
		" AND active = TRUE ORDER BY version DESC LIMIT 1")
	if err != nil {
		return "", err
	}
	if row == nil {
		return "", fmt.Errorf("register: class %s has no registered schema", class)
	}
	return row.Str("id"), nil
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
