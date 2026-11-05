// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/Privasys/container-app-register/internal/config"
	"github.com/Privasys/container-app-register/internal/mail"
	"github.com/Privasys/container-app-register/internal/register"
)

// mailConfiguration is the sender's part of the deployer's document. The
// fields are flat because the platform draws a form from them. Each is
// optional: a call sets what it names and keeps the rest, so whoever holds
// the secret can set it without knowing the others, and the reverse.
type mailConfiguration struct {
	TenantID     string `json:"mail_tenant_id,omitempty"`
	ClientID     string `json:"mail_client_id,omitempty"`
	ClientSecret string `json:"mail_client_secret,omitempty"`
	Sender       string `json:"mail_sender,omitempty"`
	BaseURL      string `json:"mail_base_url,omitempty"`
	Office       string `json:"mail_office,omitempty"`
	Organisation string `json:"mail_organisation,omitempty"`
	SignInMethod string `json:"mail_sign_in_method,omitempty"`
	SupportEmail string `json:"mail_support_email,omitempty"`
	Production   bool   `json:"mail_production,omitempty"`
}

func (c mailConfiguration) settings() mail.Settings {
	return mail.Settings{
		TenantID: c.TenantID, ClientID: c.ClientID, ClientSecret: c.ClientSecret, Sender: c.Sender,
		BaseURL: c.BaseURL, Office: c.Office, Organisation: c.Organisation,
		SignInMethod: c.SignInMethod, SupportEmail: c.SupportEmail, Production: c.Production,
	}
}

// configureMail applies a configure call to the sender, and brings back
// the one a previous call sealed on the volume. Settings that cannot send
// yet are kept and reported, so they can be completed by a later call.
func (a *application) configureMail(document []byte) (string, error) {
	if a.cfg.Mode == config.ModeStandby {
		return "", nil
	}
	var doc mailConfiguration
	if len(document) > 0 {
		if err := json.Unmarshal(document, &doc); err != nil {
			return "", fmt.Errorf("configuration: %w", err)
		}
	}
	held, err := mail.LoadSettings(a.cfg.DataDir)
	if err != nil {
		return "", err
	}
	given := doc != (mailConfiguration{})
	if !given && held == nil {
		return "", nil
	}
	settings := doc.settings()
	if held != nil {
		settings = settings.Merge(*held)
	}
	if given {
		if err := mail.SaveSettings(a.cfg.DataDir, settings); err != nil {
			return "", err
		}
	}
	mailer, err := mail.New(settings, filepath.Join(a.cfg.SiteDir, "emails"))
	if err != nil {
		a.server.Mailer.Store(nil)
		return "not ready: " + err.Error(), nil
	}
	a.server.Mailer.Store(mailer)
	return "ready", nil
}

// invitationLoop sends the reminders that are due and forgets who the
// expired invitations were for. A reminder that fails is tried again on
// the next pass; one that is sent is recorded, so it goes out once.
func (a *application) invitationLoop(ctx context.Context, reg *register.Register) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		a.passInvitations(ctx, reg)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (a *application) passInvitations(ctx context.Context, reg *register.Register) {
	if _, err := reg.ForgetExpiredRecipients(); err != nil {
		a.log.Warn("invitations: could not forget expired recipients", "error", err)
	}
	mailer := a.server.Mailer.Load()
	if mailer == nil {
		return
	}
	due, err := reg.InviteReminders()
	if err != nil {
		a.log.Warn("invitations: could not list reminders", "error", err)
		return
	}
	for _, d := range due {
		if err := mailer.SendInvitation(ctx, a.server.InvitationEmail(reg, d.Invite, d.To, true)); err != nil {
			a.log.Warn("invitations: reminder not sent", "invite", d.Invite.ID, "error", err)
			continue
		}
		if err := reg.MarkReminded(d.Invite.ID); err != nil {
			a.log.Warn("invitations: reminder not recorded", "invite", d.Invite.ID, "error", err)
		}
	}
}
