// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/Privasys/container-app-register/internal/register"
)

// resolveIdentifier is the resolver of the identifiers the register
// assigns: /id/{property}/{value} answers 303 See Other to the page of the
// record, which the adopter site names (records), or to the public reader.
// A value typed in another case or without its hyphens is sent to its
// written form; one that is malformed or fails its check digits is 400.
// Anyone may ask: it says no more than the public record does.
func (s *Server) resolveIdentifier(w http.ResponseWriter, r *http.Request) {
	reg, _, ready := s.register()
	if !ready {
		writeError(w, http.StatusServiceUnavailable, "the register is not open yet", "")
		return
	}
	property, value := r.PathValue("property"), r.PathValue("value")
	class, id := reg.IdentifierClass(property)
	if class == nil {
		writeError(w, http.StatusNotFound, "no such identifier", property)
		return
	}
	canonical, err := register.Canonical(id, value)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "")
		return
	}
	if canonical != value {
		http.Redirect(w, r, "/id/"+url.PathEscape(property)+"/"+url.PathEscape(canonical), http.StatusPermanentRedirect)
		return
	}
	target := "/public/v1/" + url.PathEscape(class.Name) + "/" + url.PathEscape(canonical)
	if s.site != nil && s.site.Records[class.Name] != "" {
		target = strings.ReplaceAll(s.site.Records[class.Name], "{key}", url.PathEscape(canonical))
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}
