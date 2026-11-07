// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

// organisationMembers lists the people of an organisation, for its
// administrators and for whoever manages the register's members.
func (s *Server) organisationMembers(req *request) (any, error) {
	members, err := req.reg.OrganisationMembers(req.p, req.r.PathValue("key"))
	if err != nil {
		return nil, err
	}
	return map[string]any{"members": members}, nil
}

// setOrganisationAdmin makes a person an administrator of their
// organisation, or stops them being one.
func (s *Server) setOrganisationAdmin(req *request) (any, error) {
	var in struct {
		Sub   string `json:"sub"`
		Admin bool   `json:"admin"`
	}
	if err := decode(req.r, &in); err != nil {
		return nil, err
	}
	txn, err := req.reg.SetOrganisationAdmin(req.p, req.r.PathValue("key"), in.Sub, in.Admin)
	if err != nil {
		return nil, err
	}
	return map[string]any{"transaction": txn}, nil
}

// recordOrganisation records an organisation no source holds, from the
// details given when its first person is invited.
func (s *Server) recordOrganisation(req *request) (any, error) {
	var in struct {
		Payload map[string]any `json:"payload"`
	}
	if err := decode(req.r, &in); err != nil {
		return nil, err
	}
	id, txn, err := req.reg.RecordOrganisation(req.p, in.Payload)
	if err != nil {
		return nil, err
	}
	return map[string]any{"object_id": id, "transaction": txn}, nil
}
