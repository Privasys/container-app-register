// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Operation approvals.
//
// An act the pack names under step_up is refused until the person
// approves that very act on the wallet bound to them. The register asks
// the identity provider to put the operation in front of the wallet (by
// its hash and a one-line summary), polls for the answer, and receives a
// short-lived token signed by the identity provider that names the
// wallet and the hash of the operation it approved. The token stays with
// the register: the page only learns whether the approval was given.

// Approval is a verified operation approval.
type Approval struct {
	// Wallet is the approving wallet's subject under this client.
	Wallet string
	// OpHash is the base64url SHA-256 of the operation approved.
	OpHash string
	// SummaryHash is the hash of the summary the wallet showed.
	SummaryHash string
	// ID is the token's own identifier; an approval is spent once.
	ID string
	// IssuedAt is when the person approved, in Unix seconds.
	IssuedAt int64
}

// PendingApproval is an approval asked for and not yet answered.
type PendingApproval struct {
	ID         string `json:"approval_id"`
	ExpiresAt  int64  `json:"expires_at"`
	PushSent   bool   `json:"push_sent"`
	WalletLink string `json:"wallet_link,omitempty"`
}

// Answers a poll can give.
const (
	ApprovalPending  = "pending"
	ApprovalApproved = "approved"
	ApprovalDeclined = "declined"
	ApprovalExpired  = "expired"
)

// Approvals asks an identity provider for operation approvals.
type Approvals interface {
	// Begin asks the wallet bound to subject to approve an operation.
	Begin(ctx context.Context, subject, opHash, summary string) (*PendingApproval, error)
	// BeginBind asks whichever wallet scans the link to approve an
	// operation, which binds it; member is for the development stand-in.
	BeginBind(ctx context.Context, member, opHash, summary string) (*PendingApproval, error)
	// Poll returns the state of an approval, and its token once approved.
	Poll(ctx context.Context, id string) (state, token string, err error)
	// Verify checks an approval token.
	Verify(ctx context.Context, token string) (*Approval, error)
}

// OperationHash is the hash an operation is approved by: base64url,
// unpadded, of the SHA-256 of its canonical form.
func OperationHash(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ApprovalTTL is how long a person has to answer.
const ApprovalTTL = 300

// IdentityApprovals is the identity provider's approval service, called
// as the register's own confidential client.
type IdentityApprovals struct {
	base     string
	clientID string
	secret   string
	verifier *JWKSVerifier
	client   *http.Client
}

// NewIdentityApprovals returns the approval service of issuer, used as
// client clientID with its secret.
func NewIdentityApprovals(issuer, clientID, secret string) *IdentityApprovals {
	return &IdentityApprovals{
		base: strings.TrimRight(issuer, "/"), clientID: clientID, secret: secret,
		verifier: NewJWKSVerifier(issuer, clientID),
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (a *IdentityApprovals) Begin(ctx context.Context, subject, opHash, summary string) (*PendingApproval, error) {
	return a.begin(ctx, "/approvals", map[string]any{
		"subject": subject, "op_hash": opHash, "summary": summary, "ttl_seconds": ApprovalTTL,
	})
}

func (a *IdentityApprovals) BeginBind(ctx context.Context, _, opHash, summary string) (*PendingApproval, error) {
	return a.begin(ctx, "/approvals/bind", map[string]any{
		"op_hash": opHash, "summary": summary, "ttl_seconds": ApprovalTTL,
	})
}

func (a *IdentityApprovals) begin(ctx context.Context, path string, body map[string]any) (*PendingApproval, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	status, answer, err := a.call(ctx, http.MethodPost, path, raw)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return nil, fmt.Errorf("approval: the identity provider answered %d: %s", status, clipBody(answer))
	}
	var out PendingApproval
	if err := json.Unmarshal(answer, &out); err != nil || out.ID == "" {
		return nil, fmt.Errorf("approval: unexpected answer from the identity provider")
	}
	return &out, nil
}

func (a *IdentityApprovals) Poll(ctx context.Context, id string) (string, string, error) {
	status, answer, err := a.call(ctx, http.MethodGet, "/approvals/"+urlSegment(id), nil)
	if err != nil {
		return "", "", err
	}
	switch status {
	case http.StatusAccepted:
		return ApprovalPending, "", nil
	case http.StatusForbidden:
		return ApprovalDeclined, "", nil
	case http.StatusGone, http.StatusNotFound:
		return ApprovalExpired, "", nil
	case http.StatusOK:
		var out struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(answer, &out); err != nil || out.Token == "" {
			return "", "", fmt.Errorf("approval: unexpected answer from the identity provider")
		}
		return ApprovalApproved, out.Token, nil
	}
	return "", "", fmt.Errorf("approval: the identity provider answered %d: %s", status, clipBody(answer))
}

func (a *IdentityApprovals) call(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.SetBasicAuth(a.clientID, a.secret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("approval: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, raw, err
}

// Verify checks an approval token: the identity provider's signature,
// its type, issuer, audience (this client), a lifetime of minutes, and
// that the person was verified by a WebAuthn assertion.
func (a *IdentityApprovals) Verify(ctx context.Context, token string) (*Approval, error) {
	typ, claims, err := a.verifier.verifyJWT(ctx, token)
	if err != nil {
		return nil, err
	}
	if typ != "op-approval+jwt" {
		return nil, fmt.Errorf("approval: a token of type %q is not an operation approval", typ)
	}
	return approvalFromClaims(claims)
}

func approvalFromClaims(claims map[string]any) (*Approval, error) {
	str := func(k string) string { s, _ := claims[k].(string); return s }
	num := func(k string) int64 { f, _ := claims[k].(float64); return int64(f) }
	exp, iat := num("exp"), num("iat")
	switch {
	case exp == 0 || iat == 0 || exp-iat > 600:
		return nil, errors.New("approval: the token must say when it was issued and expire within minutes")
	case time.Now().Unix() > exp:
		return nil, errors.New("approval: the approval has expired")
	case claims["uv"] != true:
		return nil, errors.New("approval: the person was not verified on the wallet")
	case !amrHas(claims, "webauthn"):
		return nil, errors.New("approval: the approval was not given with WebAuthn")
	}
	out := &Approval{
		Wallet: str("sub"), OpHash: str("op_hash"), SummaryHash: str("summary_hash"),
		ID: str("jti"), IssuedAt: iat,
	}
	if out.Wallet == "" || out.OpHash == "" || out.ID == "" {
		return nil, errors.New("approval: the token lacks its subject, operation or identifier")
	}
	return out, nil
}

func amrHas(claims map[string]any, want string) bool {
	list, _ := claims["amr"].([]any)
	for _, v := range list {
		if s, _ := v.(string); s == want {
			return true
		}
	}
	return false
}

// DevApprovals stands in for the identity provider on a laptop and in
// tests, with the development verifier: every approval is given at once,
// and binding binds the wallet "dev-wallet:<member>".
type DevApprovals struct{}

// devApprovalPrefix marks a development approval token,
// "dev-approval|<wallet>|<op hash>|<nonce>"; its approval identifier is
// "dev-" and the token in base64url.
const devApprovalPrefix = "dev-approval|"

func (DevApprovals) Begin(_ context.Context, subject, opHash, _ string) (*PendingApproval, error) {
	return devPending(subject, opHash), nil
}

func (DevApprovals) BeginBind(_ context.Context, member, opHash, _ string) (*PendingApproval, error) {
	return devPending("dev-wallet:"+member, opHash), nil
}

func devPending(wallet, opHash string) *PendingApproval {
	return &PendingApproval{
		ID:        "dev-" + base64.RawURLEncoding.EncodeToString([]byte(DevApprovalToken(wallet, opHash))),
		ExpiresAt: time.Now().Unix() + ApprovalTTL, PushSent: true,
	}
}

func (DevApprovals) Poll(_ context.Context, id string) (string, string, error) {
	token, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(id, "dev-"))
	if err != nil || !strings.HasPrefix(id, "dev-") {
		return ApprovalExpired, "", nil
	}
	return ApprovalApproved, string(token), nil
}

func (DevApprovals) Verify(_ context.Context, token string) (*Approval, error) {
	return DevApproval(token)
}

// DevApproval reads a development approval token.
func DevApproval(token string) (*Approval, error) {
	parts := strings.Split(strings.TrimPrefix(token, devApprovalPrefix), "|")
	if !strings.HasPrefix(token, devApprovalPrefix) || len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return nil, errors.New("approval: a development approval is 'dev-approval|<wallet>|<op hash>|<nonce>'")
	}
	return &Approval{
		Wallet: parts[0], OpHash: parts[1], ID: "dev-" + parts[2],
		SummaryHash: "", IssuedAt: time.Now().Unix(),
	}, nil
}

// DevApprovalToken builds a development approval of opHash by wallet.
func DevApprovalToken(wallet, opHash string) string {
	nonce := make([]byte, 8)
	_, _ = rand.Read(nonce)
	return devApprovalPrefix + wallet + "|" + opHash + "|" + hex.EncodeToString(nonce)
}

func urlSegment(s string) string {
	return strings.NewReplacer("/", "%2F", "?", "%3F", "#", "%23").Replace(s)
}

func clipBody(b []byte) string {
	if len(b) > 200 {
		b = b[:200]
	}
	return strings.TrimSpace(string(b))
}
