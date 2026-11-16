// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/Privasys/container-app-register/internal/mail"
	"github.com/Privasys/container-app-register/internal/register"
)

type fakeMailer struct {
	fail int
	sent []mail.Notification
}

func (f *fakeMailer) SendNotification(_ context.Context, n mail.Notification) error {
	if f.fail > 0 {
		f.fail--
		return errors.New("graph unreachable")
	}
	f.sent = append(f.sent, n)
	return nil
}

func (f *fakeMailer) BaseURL() string { return "https://register.example.org" }

// One email per recipient, retried, with the record page the site names.
func TestNoticesAreSentToEachRecipient(t *testing.T) {
	_, srv, reg := newTestServer(t)
	srv.site = &Site{Records: map[string]string{"vehicle": "/vehicles/{key}"}}
	n := NewNoticeSender(srv, reg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	fake := &fakeMailer{fail: 2}
	n.Mailer = func() NoticeMailer { return fake }
	n.Wait = func(int) time.Duration { return 0 }
	n.send(context.Background(), register.Notice{
		Template: "approved", Workflow: "first_registration", Event: "approved", Class: "vehicle", Key: "VF1 X",
		Recipients: []register.NoticeRecipient{{Sub: "a", Name: "Ana", Email: "ana@example.org"}, {Sub: "b", Email: "bo@example.org"}},
	})
	if len(fake.sent) != 2 || fake.sent[0].To != "ana@example.org" || fake.sent[0].Data["RecipientName"] != "Ana" ||
		fake.sent[0].Data["RecordURL"] != "https://register.example.org/vehicles/VF1%20X" {
		t.Fatalf("sent %+v", fake.sent)
	}

	// Without a sender, nothing is attempted and nothing fails.
	n.Mailer = func() NoticeMailer { return nil }
	n.send(context.Background(), register.Notice{Template: "approved", Recipients: []register.NoticeRecipient{{Email: "ana@example.org"}}})
}
