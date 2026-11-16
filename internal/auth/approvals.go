// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

// Operation approvals.
//
// An act the pack names under step_up is refused until the person
// approves that very act on a wallet bound to them. The register sends
// the wallet an approval (a title, a few lines, and the digest of the act)
// through the platform; the wallet shows it, the person approves with
// their face or fingerprint, and the identity provider signs the answer,
// which the wallet delivers back to the register. The answer names the
// wallet, the approval and the act's digest; the register admits the act
// only if what it is about to commit has that digest.
//
// A wallet is bound by linking: the signed-in member's page asks the
// wallet to link the person's Privasys ID with a nonce the register made
// for that session, and the identity provider's token for that link
// names the person's subject under this register's client.

// Approval is a verified answer to an approval request.
type Approval struct {
	// Wallet is the approving person's subject under this client.
	Wallet string
	// OpHash is the act digest approved: hex SHA-256 of the act.
	OpHash string
	// ApprovalID and ApprovalDigest name the approval request answered.
	ApprovalID     string
	ApprovalDigest string
	// Decision is "approve" or "decline".
	Decision string
	// Acr is the assurance the person gave it with; Amr how.
	Acr string
	Amr []string
	// ID is the token's own identifier; an approval is spent once.
	ID string
	// IssuedAt is when the person answered, in Unix seconds.
	IssuedAt int64
	// Presence is the identity verifier's signed statement that the
	// person was present, for gov-presence.
	Presence json.RawMessage
	// Receipt is the signed answer, kept with the act it admitted.
	Receipt string
}

// Assurance levels, weakest first.
const (
	AssuranceDevice      = "device"
	AssuranceGovPresence = "gov-presence"
)

// AssuranceMeets reports whether level satisfies required.
func AssuranceMeets(level, required string) bool {
	rank := map[string]int{AssuranceDevice: 1, AssuranceGovPresence: 2}
	return rank[level] > 0 && rank[level] >= rank[required]
}

// ApprovalLine is one labelled line the wallet shows under the title.
type ApprovalLine struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// ApprovalRequest is what is sent to a wallet.
type ApprovalRequest struct {
	// Wallet is the subject to send it to.
	Wallet    string
	Title     string
	Lines     []ApprovalLine
	ActDigest string
	Assurance string
	// Callback is the rooted path the wallet delivers the answer to.
	Callback string
	TTL      int
}

// PendingApproval is an approval sent and not yet answered.
type PendingApproval struct {
	ID        string
	Digest    string
	ExpiresAt int64
	PushSent  bool
	// Answer is set when the answer is already known (the development
	// stand-in approves at once).
	Answer *Approval
}

// Approvals sends approval requests to wallets and verifies what comes
// back.
type Approvals interface {
	// Ask sends an approval request to a wallet.
	Ask(ctx context.Context, req ApprovalRequest) (*PendingApproval, error)
	// VerifyAnswer checks a signed answer delivered to the callback.
	VerifyAnswer(ctx context.Context, token string) (*Approval, error)
	// VerifyLink checks the identity provider's token for linking a
	// wallet, made with nonce, and returns the person's subject; name
	// is for the development stand-in.
	VerifyLink(ctx context.Context, idToken, nonce, name string) (string, error)
}

// OperationHash is the digest an act is approved by: hex SHA-256 of its
// canonical form.
func OperationHash(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

// ApprovalTTL is how long a person has to answer, in seconds.
const ApprovalTTL = 300

// Limits the wallet sets on what it shows.
const (
	maxTitle = 120
	maxLabel = 40
	maxValue = 200
	maxLines = 12
)

// approvalDocument renders the request the wallet receives, as the exact
// string its digest is taken over.
func approvalDocument(id string, req ApprovalRequest) (string, error) {
	lines := make([]ApprovalLine, 0, len(req.Lines))
	for _, l := range req.Lines {
		if len(lines) == maxLines {
			break
		}
		label, value := Displayable(l.Label, maxLabel), Displayable(l.Value, maxValue)
		if label != "" && value != "" {
			lines = append(lines, ApprovalLine{Label: label, Value: value})
		}
	}
	doc := struct {
		V         int            `json:"v"`
		ID        string         `json:"id"`
		Title     string         `json:"title"`
		Lines     []ApprovalLine `json:"lines"`
		ActDigest string         `json:"act_digest"`
		Assurance string         `json:"assurance"`
		Callback  string         `json:"callback"`
		TTL       int            `json:"ttl"`
	}{1, id, Displayable(req.Title, maxTitle), lines, req.ActDigest, req.Assurance, req.Callback, req.TTL}
	raw, err := json.Marshal(doc)
	return string(raw), err
}

// Displayable cleans text for the wallet: one line, no control,
// direction or zero-width characters, at most n characters.
func Displayable(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), unicode.Is(unicode.Bidi_Control, r):
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > n {
		s = string(r[:n-1]) + "…"
	}
	return s
}

// newApprovalID is the register's reference for one approval request.
func newApprovalID() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func digestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Notifier pushes a payload to a person's wallet through the platform.
type Notifier func(ctx context.Context, sub, typ string, payload map[string]any) error

// WalletApprovals is the platform's approval path: requests go to the
// wallet through the control plane, answers are signed by the identity
// provider for the audience approval:<app id>.
type WalletApprovals struct {
	notify  Notifier
	answers *JWKSVerifier
	links   *JWKSVerifier
}

// NewWalletApprovals returns the approval path for the app appID, whose
// pages sign people in as clientID, with tokens from issuer.
func NewWalletApprovals(issuer, appID, clientID string, notify Notifier) *WalletApprovals {
	return &WalletApprovals{
		notify:  notify,
		answers: NewJWKSVerifier(issuer, "approval:"+appID),
		links:   NewJWKSVerifier(issuer, clientID),
	}
}

func (a *WalletApprovals) Ask(ctx context.Context, req ApprovalRequest) (*PendingApproval, error) {
	id := newApprovalID()
	doc, err := approvalDocument(id, req)
	if err != nil {
		return nil, err
	}
	out := &PendingApproval{ID: id, Digest: digestOf(doc), ExpiresAt: time.Now().Unix() + int64(req.TTL)}
	if err := a.notify(ctx, req.Wallet, "approval", map[string]any{"approval": doc}); err != nil {
		return nil, fmt.Errorf("approval: %w", err)
	}
	out.PushSent = true
	return out, nil
}

// VerifyAnswer checks the identity provider's signature (ES256), the
// token type, issuer, audience and a lifetime of minutes, and reads the
// answer. Whether it answers the approval asked, with the act's digest,
// on a bound wallet and at the assurance needed is for the caller.
func (a *WalletApprovals) VerifyAnswer(ctx context.Context, token string) (*Approval, error) {
	typ, alg, claims, err := a.answers.verifyJWT(ctx, token)
	if err != nil {
		return nil, err
	}
	if typ != "op-approval+jwt" || alg != "ES256" {
		return nil, fmt.Errorf("approval: a %s token signed %s is not an operation approval", typ, alg)
	}
	return answerFromClaims(claims, token)
}

func answerFromClaims(claims map[string]any, token string) (*Approval, error) {
	str := func(k string) string { s, _ := claims[k].(string); return s }
	num := func(k string) int64 { f, _ := claims[k].(float64); return int64(f) }
	exp, iat := num("exp"), num("iat")
	switch {
	case exp == 0 || iat == 0 || exp-iat > 600:
		return nil, errors.New("approval: the answer must say when it was given and expire within minutes")
	case num("v") != 1:
		return nil, errors.New("approval: the answer is not in a format this register reads (v 1)")
	case time.Now().Unix() > exp:
		return nil, errors.New("approval: the answer has expired")
	}
	out := &Approval{
		Wallet: str("sub"), OpHash: str("act_digest"), ApprovalID: str("approval_id"),
		ApprovalDigest: str("approval_digest"), Decision: str("decision"), Acr: str("acr"),
		Amr: stringList(claims["amr"]), ID: str("jti"), IssuedAt: iat, Receipt: token,
	}
	if p, ok := claims["presence"]; ok && p != nil {
		out.Presence, _ = json.Marshal(p)
	}
	if out.Wallet == "" || out.OpHash == "" || out.ID == "" || out.ApprovalID == "" || out.ApprovalDigest == "" {
		return nil, errors.New("approval: the answer lacks its subject, act, approval or identifier")
	}
	if out.Decision != "approve" && out.Decision != "decline" {
		return nil, fmt.Errorf("approval: %q is not a decision", out.Decision)
	}
	return out, nil
}

// VerifyLink checks the link token: the identity provider's signature,
// issuer, this client as audience, expiry, the nonce made for the
// session, and a WebAuthn sign-in.
func (a *WalletApprovals) VerifyLink(ctx context.Context, idToken, nonce, _ string) (string, error) {
	_, _, claims, err := a.links.verifyJWT(ctx, idToken)
	if err != nil {
		return "", err
	}
	if n, _ := claims["nonce"].(string); n == "" || n != nonce {
		return "", errors.New("link: the token was not made for this request")
	}
	if !containsStr(stringList(claims["amr"]), "webauthn") {
		return "", errors.New("link: the person did not confirm on their wallet")
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return "", errors.New("link: the token names nobody")
	}
	return sub, nil
}

func stringList(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, x := range list {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func containsStr(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// DevApprovals stands in for the wallet on a laptop and in tests, with
// the development verifier: every approval is given at once, on the
// wallet asked, at the assurance asked; linking binds the wallet
// "dev-wallet:<member>", or "dev-wallet:<member>:<label>" when a label
// is given.
type DevApprovals struct{}

func (DevApprovals) Ask(_ context.Context, req ApprovalRequest) (*PendingApproval, error) {
	id := newApprovalID()
	doc, err := approvalDocument(id, req)
	if err != nil {
		return nil, err
	}
	out := &PendingApproval{ID: id, Digest: digestOf(doc), ExpiresAt: time.Now().Unix() + int64(req.TTL), PushSent: true}
	a := DevApproval(req.Wallet, req.ActDigest)
	a.ApprovalID, a.ApprovalDigest, a.Acr = id, out.Digest, req.Assurance
	if req.Assurance == AssuranceGovPresence {
		a.Amr = append(a.Amr, "face")
	}
	out.Answer = a
	return out, nil
}

func (DevApprovals) VerifyAnswer(context.Context, string) (*Approval, error) {
	return nil, errors.New("approval: the development stand-in answers at once")
}

func (DevApprovals) VerifyLink(_ context.Context, _, _, name string) (string, error) {
	return "dev-wallet:" + name, nil
}

// DevApproval is a development approval of opHash on wallet.
func DevApproval(wallet, opHash string) *Approval {
	nonce := make([]byte, 8)
	_, _ = rand.Read(nonce)
	return &Approval{
		Wallet: wallet, OpHash: opHash, Decision: "approve", Acr: AssuranceDevice,
		Amr: []string{"webauthn"}, ID: "dev-" + hex.EncodeToString(nonce), IssuedAt: time.Now().Unix(),
		Receipt: "development approval",
	}
}

// The states of an approval sent.
const (
	ApprovalPending  = "pending"
	ApprovalApproved = "approved"
	ApprovalDeclined = "declined"
	ApprovalExpired  = "expired"
)
