// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package platform

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// The app's attested identity, and pushes to a person's wallet.
//
// The control plane admits a call from an app that presents its identity
// leaf, minted by the in-enclave manager, with a fresh challenge and a
// quote committing to both: no secret is configured. The register uses it
// to ask the platform to push to the wallet of one of its own people.

// headerIdentityContext binds a quote to the header identity flow.
var headerIdentityContext = sha256.Sum256([]byte("privasys-ratls-attest-v2-header-identity"))

const protocolVersion = 2

// AppIdentity returns the headers of one control-plane call: the identity
// leaf, a fresh challenge (8 bytes of Unix seconds and 24 random), and a
// quote over both, each in standard base64.
func (m *Manager) AppIdentity(ctx context.Context) (identity, challenge, evidence string, err error) {
	if m == nil {
		return "", "", "", fmt.Errorf("platform: no manager: not running on the platform")
	}
	var leaf struct {
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if err := m.post(ctx, "/api/v1/egress-identity", map[string]any{"v": protocolVersion}, &leaf); err != nil {
		return "", "", "", err
	}
	pair, err := tls.X509KeyPair([]byte(leaf.CertPEM), []byte(leaf.KeyPEM))
	if err != nil {
		return "", "", "", fmt.Errorf("platform: identity leaf: %w", err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return "", "", "", fmt.Errorf("platform: identity leaf: %w", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", "", "", err
	}
	ch := make([]byte, 32)
	binary.BigEndian.PutUint64(ch[:8], uint64(time.Now().Unix()))
	if _, err := rand.Read(ch[8:]); err != nil {
		return "", "", "", err
	}
	spkiHash := sha256.Sum256(spki)
	var quoted struct {
		Quote string `json:"quote"`
	}
	if err := m.post(ctx, "/api/v1/egress-evidence", map[string]any{
		"v":           protocolVersion,
		"spki_sha256": base64.RawURLEncoding.EncodeToString(spkiHash[:]),
		"context":     base64.RawURLEncoding.EncodeToString(ch),
		"hctx":        base64.RawURLEncoding.EncodeToString(headerIdentityContext[:]),
	}, &quoted); err != nil {
		return "", "", "", err
	}
	quote, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(quoted.Quote, "="))
	if err != nil {
		return "", "", "", fmt.Errorf("platform: the quote is not base64url")
	}
	return base64.StdEncoding.EncodeToString(pair.Certificate[0]),
		base64.StdEncoding.EncodeToString(ch),
		base64.StdEncoding.EncodeToString(quote), nil
}

func (m *Manager) post(ctx context.Context, path string, body, into any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.baseURL+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+m.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("platform: %s: %w", path, err)
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("platform: %s: %d %s", path, resp.StatusCode, strings.TrimSpace(string(answer)))
	}
	return json.Unmarshal(answer, into)
}

// Notifier pushes to people's wallets through the control plane at base.
type Notifier struct {
	base    string
	manager *Manager
	client  *http.Client
}

// NewNotifier returns a notifier, or nil off the platform.
func NewNotifier(base string, m *Manager) *Notifier {
	if base == "" || m == nil {
		return nil
	}
	return &Notifier{base: strings.TrimRight(base, "/"), manager: m, client: &http.Client{Timeout: 20 * time.Second}}
}

// Notify asks the platform to push payload, of type typ, to the wallet of
// the person sub names.
func (n *Notifier) Notify(ctx context.Context, sub, typ string, payload map[string]any) error {
	id, ch, ev, err := n.manager.AppIdentity(ctx)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{"sub": sub, "type": typ, "payload": payload})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.base+"/api/v1/notify", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Privasys-App-Identity", id)
	req.Header.Set("X-Privasys-App-Challenge", ch)
	req.Header.Set("X-Privasys-App-Evidence", ev)
	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("notify: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("notify: %s: %s", resp.Status, strings.TrimSpace(string(detail)))
	}
	return nil
}
