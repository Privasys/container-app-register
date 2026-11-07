// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/drafts"
	"github.com/Privasys/container-app-register/internal/register"
)

// draftOwner is whose drafts a person works on: their organisation's when
// they belong to one, so colleagues share them, and otherwise their own.
func draftOwner(req *request) (string, error) {
	affs, err := req.reg.Affiliations(req.p.Tenant, req.p.Sub)
	if err != nil {
		return "", err
	}
	if len(affs) > 0 {
		return "organisation:" + affs[0].Organisation, nil
	}
	return "person:" + req.p.Sub, nil
}

func (s *Server) draftStore() (*drafts.Store, error) {
	if s.Drafts == nil {
		return nil, errors.New("this register keeps no drafts")
	}
	return s.Drafts, nil
}

func mayDraft(req *request, workflow string) error {
	if req.reg.Pack().Workflow(workflow) == nil {
		return fmt.Errorf("no workflow named %q", workflow)
	}
	if !req.p.CanOn(auth.PermPropose, workflow) {
		return fmt.Errorf("%s may not propose %s", req.p.Acting, workflow)
	}
	return nil
}

func draftError(err error) error {
	switch {
	case errors.Is(err, drafts.ErrNotFound):
		return errors.New("no such draft")
	case errors.Is(err, drafts.ErrConflict):
		return errors.New("the draft is already registered at a newer revision: it was changed elsewhere since you opened it")
	}
	return err
}

func (s *Server) listDrafts(req *request) (any, error) {
	store, err := s.draftStore()
	if err != nil {
		return nil, err
	}
	owner, err := draftOwner(req)
	if err != nil {
		return nil, err
	}
	list, err := store.List(req.p.Tenant, owner)
	if err != nil {
		return nil, err
	}
	return map[string]any{"drafts": list}, nil
}

func (s *Server) createDraft(req *request) (any, error) {
	var in struct {
		Workflow string         `json:"workflow"`
		Title    string         `json:"title"`
		Payload  map[string]any `json:"payload"`
	}
	if err := decode(req.r, &in); err != nil {
		return nil, err
	}
	if err := mayDraft(req, in.Workflow); err != nil {
		return nil, err
	}
	store, err := s.draftStore()
	if err != nil {
		return nil, err
	}
	owner, err := draftOwner(req)
	if err != nil {
		return nil, err
	}
	if in.Payload == nil {
		in.Payload = map[string]any{}
	}
	d, err := store.Create(req.p.Tenant, owner, req.p.Sub, in.Workflow, clipTitle(in.Title), req.reg.Pack().Version, in.Payload)
	return map[string]any{"draft": d}, err
}

func clipTitle(t string) string {
	t = strings.TrimSpace(t)
	if r := []rune(t); len(r) > 160 {
		return string(r[:160])
	}
	return t
}

func (s *Server) getDraft(req *request) (any, error) {
	store, err := s.draftStore()
	if err != nil {
		return nil, err
	}
	owner, err := draftOwner(req)
	if err != nil {
		return nil, err
	}
	d, err := store.Get(req.p.Tenant, owner, req.r.PathValue("id"))
	if err != nil {
		return nil, draftError(err)
	}
	return map[string]any{"draft": d, "scheme_current": d.Scheme == req.reg.Pack().Version}, nil
}

func (s *Server) saveDraft(req *request) (any, error) {
	var in struct {
		Revision int               `json:"revision"`
		Title    string            `json:"title"`
		Payload  map[string]any    `json:"payload"`
		Evidence map[string]string `json:"evidence"`
	}
	if err := decode(req.r, &in); err != nil {
		return nil, err
	}
	store, err := s.draftStore()
	if err != nil {
		return nil, err
	}
	owner, err := draftOwner(req)
	if err != nil {
		return nil, err
	}
	current, err := store.Get(req.p.Tenant, owner, req.r.PathValue("id"))
	if err != nil {
		return nil, draftError(err)
	}
	if err := mayDraft(req, current.Workflow); err != nil {
		return nil, err
	}
	if in.Payload == nil {
		in.Payload = map[string]any{}
	}
	d, err := store.Save(req.p.Tenant, owner, req.p.Sub, current.ID, in.Revision, clipTitle(in.Title), in.Payload, in.Evidence)
	if err != nil {
		return nil, draftError(err)
	}
	return map[string]any{"draft": d}, nil
}

func (s *Server) deleteDraft(req *request) (any, error) {
	store, err := s.draftStore()
	if err != nil {
		return nil, err
	}
	owner, err := draftOwner(req)
	if err != nil {
		return nil, err
	}
	if err := store.Delete(req.p.Tenant, owner, req.r.PathValue("id")); err != nil {
		return nil, draftError(err)
	}
	return map[string]any{"deleted": true}, nil
}

// submitDraft proposes what the draft holds, with the evidence presented,
// and deletes the draft once the proposal is recorded. A proposal the
// register refuses leaves the draft as it was, to be corrected.
func (s *Server) submitDraft(req *request) (any, error) {
	var in struct {
		Revision int               `json:"revision"`
		Evidence map[string]string `json:"evidence"`
		Message  string            `json:"message"`
	}
	if err := decode(req.r, &in); err != nil {
		return nil, err
	}
	store, err := s.draftStore()
	if err != nil {
		return nil, err
	}
	owner, err := draftOwner(req)
	if err != nil {
		return nil, err
	}
	d, err := store.Get(req.p.Tenant, owner, req.r.PathValue("id"))
	if err != nil {
		return nil, draftError(err)
	}
	if d.Revision != in.Revision {
		return nil, draftError(drafts.ErrConflict)
	}
	evidence := map[string]string{}
	for k, v := range d.Evidence {
		evidence[k] = v
	}
	for k, v := range in.Evidence {
		evidence[k] = v
	}
	out, err := req.reg.Propose(req.p, d.Workflow, register.ProposeRequest{Payload: d.Payload, Evidence: evidence, Message: in.Message})
	if err != nil {
		return nil, err
	}
	if err := store.Delete(req.p.Tenant, owner, d.ID); err != nil {
		return nil, err
	}
	return out, nil
}
