// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"context"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/Privasys/container-app-register/internal/mail"
	"github.com/Privasys/container-app-register/internal/register"
)

// NoticeMailer is what sends one notification email.
type NoticeMailer interface {
	SendNotification(ctx context.Context, n mail.Notification) error
	BaseURL() string
}

// NoticeSender writes the notifications that follow workflow events. The
// register hands it each notice once the event has committed; it sends
// one email per recipient, trying each up to three times, and records in
// the history how many people a notice reached. Without a configured
// sender, notices are dropped without a word: email is optional.
type NoticeSender struct {
	srv   *Server
	reg   *register.Register
	log   *slog.Logger
	queue chan register.Notice
	// Mailer returns the sender to use, nil when there is none. It is
	// the server's configured mailer unless a test replaces it.
	Mailer func() NoticeMailer
	// Wait is the pause before a retry.
	Wait func(attempt int) time.Duration
}

// NewNoticeSender builds a sender; Run must be called to send anything.
func NewNoticeSender(srv *Server, reg *register.Register, log *slog.Logger) *NoticeSender {
	n := &NoticeSender{srv: srv, reg: reg, log: log, queue: make(chan register.Notice, 256)}
	n.Mailer = func() NoticeMailer {
		if m := srv.Mailer.Load(); m != nil {
			return m
		}
		return nil
	}
	n.Wait = func(attempt int) time.Duration { return time.Duration(attempt) * 2 * time.Second }
	return n
}

// Deliver queues a notice. A full queue drops it, as the webhook queue
// does: the record holds the event, and a commit never waits on email.
func (n *NoticeSender) Deliver(notice register.Notice) {
	select {
	case n.queue <- notice:
	default:
		n.log.Warn("notifications: queue full, notice dropped", "workflow", notice.Workflow, "event", notice.Event, "task", notice.TaskID)
	}
}

// Run sends queued notices until the context ends.
func (n *NoticeSender) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case notice := <-n.queue:
			n.send(ctx, notice)
		}
	}
}

func (n *NoticeSender) send(ctx context.Context, notice register.Notice) {
	mailer := n.Mailer()
	if mailer == nil {
		return
	}
	sent := 0
	for _, to := range notice.Recipients {
		email := mail.Notification{To: to.Email, Template: notice.Template, Data: n.data(mailer, notice, to)}
		for attempt := 1; attempt <= 3; attempt++ {
			err := mailer.SendNotification(ctx, email)
			if err == nil {
				sent++
				break
			}
			n.log.Warn("notifications: not sent", "template", notice.Template, "task", notice.TaskID, "attempt", attempt, "error", err)
			if attempt == 3 {
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(n.Wait(attempt)):
			}
		}
	}
	n.log.Info("notifications: sent", "template", notice.Template, "task", notice.TaskID, "sent", sent, "of", len(notice.Recipients))
	if _, err := n.reg.RecordNotified(notice, sent); err != nil {
		n.log.Warn("notifications: not recorded", "task", notice.TaskID, "error", err)
	}
}

// data is what a notification template reads.
func (n *NoticeSender) data(mailer NoticeMailer, notice register.Notice, to register.NoticeRecipient) map[string]any {
	out := map[string]any{
		"Workflow": notice.Workflow, "WorkflowTitle": notice.WorkflowTitle, "Event": notice.Event,
		"Class": notice.Class, "ClassTitle": notice.ClassTitle, "Key": notice.Key,
		"TaskID": notice.TaskID, "Reason": notice.Reason, "RecipientName": to.Name,
		"Public": notice.Public, "RecordURL": "",
	}
	if notice.At != 0 {
		out["At"] = time.Unix(notice.At, 0).UTC().Format(time.RFC3339)
	}
	if n.srv != nil && n.srv.site != nil && notice.Key != "" {
		if page, ok := n.srv.site.Records[notice.Class]; ok {
			out["RecordURL"] = mailer.BaseURL() + strings.ReplaceAll(page, "{key}", url.PathEscape(notice.Key))
		}
	}
	return out
}
