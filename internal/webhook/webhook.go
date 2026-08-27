// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package webhook delivers committed transactions and issued
// checkpoints to subscribers.
//
// A webhook is a notification, not the record. The ledger is the
// record, and a subscriber that missed a delivery can always read the
// transaction log for what it missed. Delivery is therefore
// best-effort with bounded retries, and only the terminal outcome is
// written back, so an operator can see what was delivered without the
// register committing a row for every attempt.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/store"
)

// Event names a subscriber can filter on.
const (
	EventTransaction = "transaction.committed"
	EventCheckpoint  = "checkpoint.issued"
)

// Dispatcher delivers events to the register's subscribers.
type Dispatcher struct {
	st     *store.Store
	log    *slog.Logger
	client *http.Client

	queue chan job
	wg    sync.WaitGroup
	once  sync.Once
	stop  chan struct{}
}

type job struct {
	event   string
	tenant  string
	id      string
	payload []byte
}

// New builds a dispatcher. Start must be called to begin delivering.
func New(st *store.Store, log *slog.Logger) *Dispatcher {
	return &Dispatcher{
		st:     st,
		log:    log,
		client: &http.Client{Timeout: 10 * time.Second},
		queue:  make(chan job, 256),
		stop:   make(chan struct{}),
	}
}

// Start runs the delivery worker.
func (d *Dispatcher) Start() {
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		for {
			select {
			case <-d.stop:
				return
			case j := <-d.queue:
				d.deliver(j)
			}
		}
	}()
}

// Close stops the worker.
func (d *Dispatcher) Close() {
	d.once.Do(func() { close(d.stop) })
	d.wg.Wait()
}

// TransactionCommitted queues a committed transaction.
func (d *Dispatcher) TransactionCommitted(tx *model.Transaction) {
	payload, err := json.Marshal(map[string]any{
		"event": EventTransaction, "transaction": tx,
	})
	if err != nil {
		return
	}
	d.enqueue(job{event: EventTransaction, tenant: tx.Envelope.Tenant, id: tx.TxID, payload: payload})
}

// CheckpointIssued queues a signed checkpoint.
func (d *Dispatcher) CheckpointIssued(sc *model.SignedCheckpoint) {
	if sc == nil {
		return
	}
	payload, err := json.Marshal(map[string]any{
		"event": EventCheckpoint, "checkpoint": sc,
	})
	if err != nil {
		return
	}
	id := fmt.Sprintf("checkpoint-%d", sc.Checkpoint.Version)
	d.enqueue(job{event: EventCheckpoint, tenant: "", id: id, payload: payload})
}

func (d *Dispatcher) enqueue(j job) {
	select {
	case d.queue <- j:
	default:
		// A full queue means the register is committing faster than its
		// subscribers can be told. Dropping the notification is right:
		// the log still holds the change, and blocking a commit on an
		// unreachable endpoint would be worse.
		d.log.Warn("webhook queue full, notification dropped", "event", j.event, "id", j.id)
	}
}

func (d *Dispatcher) deliver(j job) {
	rows, err := d.st.Query("SELECT * FROM `webhooks` WHERE active = TRUE")
	if err != nil {
		d.log.Error("webhook: read subscribers", "error", err)
		return
	}
	for _, row := range rows {
		if j.tenant != "" && row.Str("tenant") != "" && row.Str("tenant") != j.tenant {
			continue
		}
		if events := row.Str("events"); events != "" && !strings.Contains(events, j.event) {
			continue
		}
		status, lastErr := d.post(row.Str("url"), row.Bytes("secret"), j)
		d.record(row.Str("id"), j.id, status, lastErr)
	}
}

func (d *Dispatcher) post(url string, secret []byte, j job) (string, string) {
	var lastErr string
	for attempt := 1; attempt <= 3; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(j.payload))
		if err != nil {
			cancel()
			return "failed", err.Error()
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Register-Event", j.event)
		req.Header.Set("X-Register-Delivery", j.id)
		mac := hmac.New(sha256.New, secret)
		mac.Write(j.payload)
		req.Header.Set("X-Register-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))

		resp, err := d.client.Do(req)
		cancel()
		if err != nil {
			lastErr = err.Error()
		} else {
			resp.Body.Close()
			if resp.StatusCode < 300 {
				return "delivered", ""
			}
			lastErr = fmt.Sprintf("status %d", resp.StatusCode)
		}
		select {
		case <-d.stop:
			return "failed", lastErr
		case <-time.After(time.Duration(attempt) * 2 * time.Second):
		}
	}
	return "failed", lastErr
}

// record writes the terminal outcome of a delivery.
func (d *Dispatcher) record(webhookID, deliveryID, status, lastErr string) {
	err := d.st.Do(func(tx *store.Tx) error {
		where := "webhook_id = " + store.Lit(webhookID) + " AND txid = " + store.Lit(deliveryID)
		values := map[string]any{
			"status": status, "attempts": int64(1),
			"last_error": lastErr, "updated_at": time.Now().UTC().Unix(),
		}
		n, err := tx.Count("SELECT COUNT(*) FROM `webhook_deliveries` WHERE " + where)
		if err != nil {
			return err
		}
		if n > 0 {
			return tx.Exec(store.Update("webhook_deliveries", values, where))
		}
		values["webhook_id"] = webhookID
		values["txid"] = deliveryID
		return tx.Exec(store.Insert("webhook_deliveries", values))
	})
	if err != nil {
		d.log.Error("webhook: record delivery", "webhook", webhookID, "error", err)
	}
}
