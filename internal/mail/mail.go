// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package mail sends the register's emails through Microsoft Graph, as
// an Entra app registration holding the Mail.Send application permission.
//
// An email is a notification, not the record, and whether it arrived
// depends on somebody else's network, so no outcome reaches the ledger.
// A message carries a single-use link, so it is not kept in the sender's
// Sent Items, and neither the address nor the link is ever logged.
package mail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// settingsFile lives on the sealed volume, because the configure call
// runs again on every restart and should not have to carry the secret.
const settingsFile = "mail.json"

// Settings is one installation's sender. Each installation names its
// own: the app registration belongs to whoever operates the mailbox.
type Settings struct {
	TenantID     string `json:"tenant_id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	Sender       string `json:"sender"`
	// BaseURL is the address people reach this register at.
	BaseURL string `json:"base_url"`
	// Office is who an invitation says it comes from: an office, not a person.
	Office       string `json:"office,omitempty"`
	Organisation string `json:"organisation,omitempty"`
	SignInMethod string `json:"sign_in_method,omitempty"`
	SupportEmail string `json:"support_email,omitempty"`
	// Production removes the test notice every other instance's emails carry.
	Production bool `json:"production,omitempty"`
}

// Validate says whether these settings could send anything.
func (s Settings) Validate() error {
	switch {
	case s.TenantID == "" || s.ClientID == "" || s.ClientSecret == "":
		return errors.New("mail: tenant_id, client_id and client_secret are all needed")
	case !plainAddress(s.Sender):
		return errors.New("mail: sender must be an email address")
	case !strings.HasPrefix(s.BaseURL, "https://"):
		return errors.New("mail: base_url must be https")
	}
	return nil
}

// plainAddress accepts a bare address and nothing that could carry a
// display name or a second recipient.
func plainAddress(s string) bool {
	a, err := mail.ParseAddress(s)
	return err == nil && a.Address == s && a.Name == ""
}

// ValidAddress reports whether s is usable as a recipient.
func ValidAddress(s string) bool { return len(s) <= 254 && plainAddress(s) }

// Merge applies a configure call's settings over what is held: a field
// the call leaves out keeps its value, so whoever holds the secret can
// set it without knowing the rest, and the reverse.
func (s Settings) Merge(held Settings) Settings {
	for _, f := range []struct{ into, from *string }{
		{&s.TenantID, &held.TenantID}, {&s.ClientID, &held.ClientID}, {&s.ClientSecret, &held.ClientSecret},
		{&s.Sender, &held.Sender}, {&s.BaseURL, &held.BaseURL}, {&s.Office, &held.Office},
		{&s.Organisation, &held.Organisation}, {&s.SignInMethod, &held.SignInMethod}, {&s.SupportEmail, &held.SupportEmail},
	} {
		if *f.into == "" {
			*f.into = *f.from
		}
	}
	s.Production = s.Production || held.Production
	return s
}

// LoadSettings reads what an earlier configure call left on the volume;
// nil when none has.
func LoadSettings(dir string) (*Settings, error) {
	raw, err := os.ReadFile(filepath.Join(dir, settingsFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("mail: %w", err)
	}
	var s Settings
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("mail: %s: %w", settingsFile, err)
	}
	return &s, nil
}

// SaveSettings writes the settings to the volume.
func SaveSettings(dir string, s Settings) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, settingsFile), raw, 0o600); err != nil {
		return fmt.Errorf("mail: %w", err)
	}
	return nil
}

// Invitation is what one invitation email says.
type Invitation struct {
	To           string
	Name         string
	Organisation string
	RoleTitle    string
	RoleSummary  string
	// Link is the path that opens the invitation, secret included.
	Link      string
	ExpiresAt int64
	Reminder  bool
}

// Mailer sends through one app registration.
type Mailer struct {
	settings   Settings
	invitation *template.Template
	client     *http.Client
	loginURL   string
	graphURL   string

	mu      sync.Mutex
	token   string
	expires time.Time
}

// New prepares a mailer from the site's email templates.
func New(s Settings, templateDir string) (*Mailer, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	tpl, err := template.ParseFiles(filepath.Join(templateDir, "invitation.html"))
	if err != nil {
		return nil, fmt.Errorf("mail: %w", err)
	}
	return &Mailer{
		settings: s, invitation: tpl,
		client:   &http.Client{Timeout: 20 * time.Second},
		loginURL: "https://login.microsoftonline.com",
		graphURL: "https://graph.microsoft.com",
	}, nil
}

var titlePattern = regexp.MustCompile(`(?s)<title>(.*?)</title>`)

// render returns an invitation's subject, which is its page title, and body.
func (m *Mailer) render(inv Invitation) (string, string, error) {
	s := m.settings
	base := strings.TrimRight(s.BaseURL, "/")
	var buf bytes.Buffer
	err := m.invitation.Execute(&buf, map[string]any{
		"BaseURL": base, "AcceptURL": base + inv.Link,
		"RecipientName": inv.Name, "InvitedBy": s.Office, "RoleTitle": inv.RoleTitle,
		"RoleSummary": inv.RoleSummary, "OrganisationName": first(inv.Organisation, s.Organisation),
		"OrganisationAdmin": false, "SignInMethod": s.SignInMethod, "SupportEmail": s.SupportEmail,
		"ExpiresOn": time.Unix(inv.ExpiresAt, 0).UTC().Format("2 January 2006"),
		"Reminder":  inv.Reminder, "TestNotice": !s.Production,
	})
	if err != nil {
		return "", "", fmt.Errorf("mail: %w", err)
	}
	found := titlePattern.FindSubmatch(buf.Bytes())
	if found == nil {
		return "", "", errors.New("mail: the invitation template has no title")
	}
	return html.UnescapeString(strings.TrimSpace(string(found[1]))), buf.String(), nil
}

func first(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// SendInvitation sends an invitation or its reminder.
func (m *Mailer) SendInvitation(ctx context.Context, inv Invitation) error {
	if !ValidAddress(inv.To) {
		return errors.New("mail: not a usable address")
	}
	subject, body, err := m.render(inv)
	if err != nil {
		return err
	}
	return m.send(ctx, inv.To, subject, body)
}

func (m *Mailer) send(ctx context.Context, to, subject, body string) error {
	token, err := m.accessToken(ctx)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]any{
		"message": map[string]any{
			"subject":      subject,
			"body":         map[string]string{"contentType": "HTML", "content": body},
			"toRecipients": []map[string]any{{"emailAddress": map[string]string{"address": to}}},
		},
		"saveToSentItems": false,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		m.graphURL+"/v1.0/users/"+url.PathEscape(m.settings.Sender)+"/sendMail", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return errors.New("mail: Microsoft Graph could not be reached")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusAccepted {
		return nil
	}
	return fmt.Errorf("mail: Microsoft Graph refused the message: %d %s", resp.StatusCode, graphCode(resp.Body))
}

// graphCode keeps the error's code and drops its text, which may quote
// the message it refused.
func graphCode(body io.Reader) string {
	var out struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(body, 1<<16)).Decode(&out)
	return out.Error.Code
}

func (m *Mailer) accessToken(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.token != "" && time.Now().Before(m.expires) {
		return m.token, nil
	}
	form := url.Values{
		"client_id":     {m.settings.ClientID},
		"client_secret": {m.settings.ClientSecret},
		"scope":         {"https://graph.microsoft.com/.default"},
		"grant_type":    {"client_credentials"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		m.loginURL+"/"+url.PathEscape(m.settings.TenantID)+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := m.client.Do(req)
	if err != nil {
		return "", errors.New("mail: the Microsoft sign-in could not be reached")
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", errors.New("mail: the Microsoft sign-in gave an unreadable answer")
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("mail: the Microsoft sign-in refused the app registration: %s", out.Error)
	}
	m.token, m.expires = out.AccessToken, time.Now().Add(time.Duration(out.ExpiresIn-60)*time.Second)
	return m.token, nil
}
