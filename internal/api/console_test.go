// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"net/http"
	"testing"

	"github.com/Privasys/container-app-register/internal/auth"
)

// A pack names the roles its console is open to: /me says whether it is
// open to the caller, and the console shows itself only then.
func TestTheConsoleIsOpenToTheRolesThePackNames(t *testing.T) {
	ts, srv, reg := newTestServerWith(t, func(doc map[string]any) {
		doc["console_roles"] = []any{"operator"}
	})
	srv.TrustSession = true
	for sub, role := range map[string]string{"sub-olga": "operator", "sub-carl": "clerk"} {
		if _, err := reg.BootstrapMember(sub, role); err != nil {
			t.Fatal(err)
		}
	}
	srv.Ready(reg, auth.DevVerifier{})
	if _, me := call(t, ts, http.MethodGet, "/api/v1/me", "sub-olga", ""); me["console"] != true {
		t.Fatalf("operator: %v", me["console"])
	}
	if _, me := call(t, ts, http.MethodGet, "/api/v1/me", "sub-carl", ""); me["console"] != false {
		t.Fatalf("clerk: %v", me["console"])
	}
	if status, _ := call(t, ts, http.MethodGet, "/", "", ""); status == http.StatusNotFound {
		t.Fatal("a console open to some roles was not served")
	}
}

// An empty list switches the console off: its page is not served.
func TestAPackCanSwitchTheConsoleOff(t *testing.T) {
	ts, srv, reg := newTestServerWith(t, func(doc map[string]any) {
		doc["console_roles"] = []any{}
	})
	srv.Ready(reg, auth.DevVerifier{})
	if status, _ := call(t, ts, http.MethodGet, "/", "", ""); status != http.StatusNotFound {
		t.Fatalf("console page served: %d", status)
	}
	if status, _ := call(t, ts, http.MethodGet, "/api/v1/status", "", ""); status == http.StatusNotFound {
		t.Fatal("the API went with the console")
	}
}
