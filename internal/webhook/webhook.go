// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package webhook delivers committed transactions and issued
// checkpoints to subscribers.
//
// A webhook is a notification, not the record. The ledger is the
// record, and a subscriber that missed a delivery can always read the
// transaction log for what it missed. Delivery is therefore
// best-effort with bounded retries.
//
// Outcomes are kept in memory and nowhere else. Whether a subscriber's
// endpoint answered is not a fact about the register: it depends on
// somebody else's network, so writing it into the ledger would make the
// authenticated root a function of the weather. Two registers with
// identical governance histories would hold different roots, and every
// audit would have to walk transitions that record nothing about the
// register at all.
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

	mu         sync.RWMutex
	deliveries []Delivery
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
		d.record(row.Str("id"), j, status, lastErr)
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

// Delivery is the outcome of one attempt to notify one subscriber.
type Delivery struct {
	Webhook  string `json:"webhook"`
	Event    string `json:"event"`
	ID       string `json:"id"`
	Status   string `json:"status"`
	Error    string `json:"error,omitempty"`
	Finished int64  `json:"finished_at"`
}

// maxDeliveries is how many outcomes are kept for the operator to look
// at. Older ones fall off: they are an operational convenience, not a
// record, and the transaction log is where the record lives.
const maxDeliveries = 200

// record keeps the terminal outcome in memory.
func (d *Dispatcher) record(webhookID string, j job, status, lastErr string) {
	entry := Delivery{
		Webhook: webhookID, Event: j.event, ID: j.id,
		Status: status, Error: lastErr, Finished: time.Now().UTC().Unix(),
	}
	d.mu.Lock()
	d.deliveries = append(d.deliveries, entry)
	if len(d.deliveries) > maxDeliveries {
		d.deliveries = append([]Delivery(nil), d.deliveries[len(d.deliveries)-maxDeliveries:]...)
	}
	d.mu.Unlock()
	if status != "delivered" {
		d.log.Warn("webhook delivery failed", "webhook", webhookID, "event", j.event, "error", lastErr)
	}
}

// Deliveries returns the recent outcomes, newest first.
func (d *Dispatcher) Deliveries() []Delivery {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]Delivery, 0, len(d.deliveries))
	for i := len(d.deliveries) - 1; i >= 0; i-- {
		out = append(out, d.deliveries[i])
	}
	return out
}
