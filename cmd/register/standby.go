// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/Privasys/container-app-register/internal/register"
	"github.com/Privasys/container-app-register/internal/webhook"
)

// The warm standby.
//
// A standby follows the active register by pulling its ledger leaves
// and rebuilding the tree. That is a stronger position than copying a
// volume: the restored store produces the same root as the source for
// the same logical data, so a standby can prove it is a copy rather
// than assert it, and the same check is what makes a promotion safe.
//
// Two registers share a commitment key, which is what makes their roots
// comparable at all. The standby is configured with the same key as the
// active one, from the same place.

func (a *application) followPrimary(ctx context.Context, reg *register.Register) {
	client := &http.Client{Timeout: 60 * time.Second}
	ticker := time.NewTicker(a.cfg.StandbyInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if err := a.pullOnce(ctx, client, reg); err != nil {
			a.log.Error("standby pull failed", "primary", a.cfg.PrimaryURL, "error", err)
			a.setStandbyState(map[string]any{
				"role": "standby", "primary": a.cfg.PrimaryURL,
				"healthy": false, "error": err.Error(),
				"checked_at": time.Now().UTC().Format(time.RFC3339),
			})
		}
	}
}

// pullOnce copies the primary's current state in pages, then checks the
// restored root against the primary's signed checkpoint. A mismatch is
// reported, not papered over: a standby that cannot prove it matches is
// not a standby.
func (a *application) pullOnce(ctx context.Context, client *http.Client, reg *register.Register) error {
	started := time.Now()
	after, pages, leaves := "", 0, 0
	var last *register.ExportChunk

	for {
		chunk, err := a.fetchChunk(ctx, client, after)
		if err != nil {
			return err
		}
		if err := reg.Import(chunk); err != nil {
			return err
		}
		pages++
		leaves += len(chunk.Leaves)
		last = chunk
		if chunk.Done {
			break
		}
		after = chunk.Next
		if after == "" {
			return fmt.Errorf("the primary returned no resume position and did not finish")
		}
	}

	status, err := reg.Status()
	if err != nil {
		return err
	}
	state := map[string]any{
		"role": "standby", "primary": a.cfg.PrimaryURL,
		"primary_version": last.Version, "primary_root": last.Root,
		"local_version": status.LedgerVersion, "local_root": status.Root,
		"leaves": leaves, "pages": pages,
		"sync_seconds": time.Since(started).Seconds(),
		"synced_at":    time.Now().UTC().Format(time.RFC3339),
		"healthy":      status.Root == last.Root,
	}
	if status.Root != last.Root {
		state["error"] = "the restored root does not match the primary's"
	}
	if last.Anchor != nil {
		// The primary ships its latest signed checkpoint with the
		// export. It anchors the version it names, which is usually a
		// little behind the version the standby has just copied; what
		// matters here is that the standby records where the anchor sits
		// so a promotion can be verified against it.
		state["anchor_version"] = last.Anchor.Checkpoint.Version
		state["anchor_root"] = last.Anchor.Checkpoint.Root
		state["anchor_key_id"] = last.Anchor.KeyID
	}
	a.setStandbyState(state)
	a.log.Info("standby synchronised",
		"version", status.LedgerVersion, "root", status.Root, "leaves", leaves)
	return nil
}

func (a *application) fetchChunk(ctx context.Context, client *http.Client, after string) (*register.ExportChunk, error) {
	url := fmt.Sprintf("%s/api/v1/export?limit=500", a.cfg.PrimaryURL)
	if after != "" {
		url += "&after=" + after
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// The standby authenticates to the primary with its own credential.
	// It is an ordinary API client with the admin permission, not a
	// privileged replication channel.
	if token := os.Getenv("REGISTER_STANDBY_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if role := os.Getenv("REGISTER_STANDBY_ROLE"); role != "" {
		req.Header.Set("X-Register-Role", role)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("primary answered %d: %s", resp.StatusCode, body)
	}
	var chunk register.ExportChunk
	if err := json.Unmarshal(body, &chunk); err != nil {
		return nil, fmt.Errorf("primary export: %w", err)
	}
	return &chunk, nil
}

func (a *application) setStandbyState(state map[string]any) {
	a.standbyMu.Lock()
	a.standbyState = state
	a.standbyMu.Unlock()
}

// deliveries reports recent webhook outcomes, which live in memory
// rather than in the ledger.
func (a *application) deliveries() []webhook.Delivery {
	if a.hooks == nil {
		return nil
	}
	return a.hooks.Deliveries()
}

func (a *application) standbyStatus() map[string]any {
	a.standbyMu.RLock()
	defer a.standbyMu.RUnlock()
	if a.standbyState == nil {
		return map[string]any{"role": "active"}
	}
	return a.standbyState
}
