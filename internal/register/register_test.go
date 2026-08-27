// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/canon"
	"github.com/Privasys/container-app-register/internal/checkpoint"
	"github.com/Privasys/container-app-register/internal/keys"
	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/pack"
	"github.com/Privasys/container-app-register/internal/register"
	"github.com/Privasys/container-app-register/internal/store"
)

// The car register is the pack the generic core is proved against.
// Everything below drives the real pack shipped in this repository: if a
// mechanism in the core cannot express what a vehicle register needs,
// these tests are where it shows.

const packPath = "../../packs/car-register/pack.json"

type harness struct {
	t   *testing.T
	reg *register.Register
	dir string
	now time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessIn(t, t.TempDir())
}

func newHarnessIn(t *testing.T, dir string) *harness {
	t.Helper()
	doc, err := os.ReadFile(packPath)
	if err != nil {
		t.Fatalf("read pack: %v", err)
	}
	loaded, err := pack.Load(doc)
	if err != nil {
		t.Fatalf("load pack: %v", err)
	}
	material, err := keys.Load(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	ck, source, err := material.CommitmentKey(nil)
	if err != nil {
		t.Fatalf("commitment key: %v", err)
	}
	st, err := store.Open(filepath.Join(dir, "register"), ck)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	h := &harness{t: t, dir: dir, now: time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)}
	reg, err := register.New(st, loaded, material, register.Options{
		Name: "test-register", Tenant: "gov", ImageDigest: strings.Repeat("ab", 32),
		KeySource: source, Now: func() time.Time { return h.now },
	})
	if err != nil {
		st.Close()
		t.Fatalf("new register: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	h.reg = reg
	return h
}

// tick moves the harness clock so successive transactions do not share a
// timestamp; two transactions with the same envelope and the same
// effects at the same instant are the same transaction by construction.
func (h *harness) tick() { h.now = h.now.Add(time.Minute) }

func (h *harness) principal(sub string, roles ...string) *auth.Principal {
	h.t.Helper()
	idpRoles := make([]string, 0, len(roles))
	for _, r := range roles {
		idpRoles = append(idpRoles, "register:"+r)
	}
	p, err := h.reg.Pack().Model().Resolve(
		&auth.Identity{Sub: sub, Display: sub, Roles: idpRoles}, "gov", roles[0])
	if err != nil {
		h.t.Fatalf("resolve %s: %v", sub, err)
	}
	return p
}

func (h *harness) vehicleByVIN(vin string) string {
	h.t.Helper()
	p := h.principal("auditor-1", "auditor")
	records, err := h.reg.ListObjects(p, register.ListFilter{Class: "vehicle", Search: vin})
	if err != nil {
		h.t.Fatalf("list vehicles: %v", err)
	}
	for _, r := range records {
		if r.NaturalKey == vin {
			return r.ID
		}
	}
	h.t.Fatalf("no vehicle with VIN %s", vin)
	return ""
}

// -- bootstrap -------------------------------------------------------------

func TestBootstrapRegistersSchemasAndSeed(t *testing.T) {
	h := newHarness(t)
	auditor := h.principal("auditor-1", "auditor")

	entries, err := h.reg.Log(auditor, register.LogFilter{Limit: 200})
	if err != nil {
		t.Fatalf("log: %v", err)
	}
	kinds := map[string]int{}
	for _, e := range entries {
		kinds[e.Envelope.Kind]++
		if e.State != model.TxApplied {
			t.Errorf("transaction %s is %s", e.TxID, e.State)
		}
		if e.Envelope.Message == "" {
			t.Errorf("transaction %s has no message", e.TxID)
		}
	}
	if kinds[model.KindSchemaRegister] != 5 {
		t.Errorf("expected 5 schema registrations, got %d", kinds[model.KindSchemaRegister])
	}
	if kinds[model.KindPolicySet] != 3 {
		t.Errorf("expected 3 retention policies, got %d", kinds[model.KindPolicySet])
	}
	if kinds[model.KindRecordCreate] != 9 {
		t.Errorf("expected 9 seeded records, got %d", kinds[model.KindRecordCreate])
	}

	vehicles, err := h.reg.ListObjects(auditor, register.ListFilter{Class: "vehicle"})
	if err != nil {
		t.Fatalf("list vehicles: %v", err)
	}
	if len(vehicles) != 2 {
		t.Fatalf("expected 2 seeded vehicles, got %d", len(vehicles))
	}
	if vehicles[0].Projection["make"] == nil {
		t.Error("the query projection was not populated")
	}
}

func TestSeedIsAppliedOnlyOnce(t *testing.T) {
	dir := t.TempDir()
	h := newHarnessIn(t, dir)
	before, err := h.reg.Status()
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	h.reg.Store().Close()

	// A restart reopens the same store and reruns the pack reconciliation.
	h2 := newHarnessIn(t, dir)
	after, err := h2.reg.Status()
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if after.Objects != before.Objects {
		t.Errorf("restart changed the record count: %d then %d", before.Objects, after.Objects)
	}
	if after.Transactions != before.Transactions {
		t.Errorf("restart wrote %d extra transactions", after.Transactions-before.Transactions)
	}
	if after.Root != before.Root {
		t.Errorf("restart moved the root without a transaction:\n  %s\n  %s", before.Root, after.Root)
	}
}

// -- first registration ----------------------------------------------------

func newVehicle(vin, plate string) map[string]any {
	return map[string]any{
		"vin": vin, "make": "Peugeot", "model": "208", "year": float64(2024),
		"colour": "red", "fuel": "petrol", "engine_cc": float64(1199),
		"first_registration": "2024-06-01", "plate": plate,
	}
}

func TestFirstRegistrationIssuesAPlate(t *testing.T) {
	h := newHarness(t)
	clerk := h.principal("clerk-1", "clerk")
	registrar := h.principal("registrar-1", "registrar")

	out, err := h.reg.Propose(clerk, "first_registration", register.ProposeRequest{
		Payload:  newVehicle("VF3CCHMZ3PT000010", "CC-789-CC"),
		Evidence: map[string]string{"proof_of_conformity": strings.Repeat("a", 64)},
	})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if out.Task.State != model.TaskAwaitingReview {
		t.Fatalf("expected review, got %s", out.Task.State)
	}
	if out.Applied != nil {
		t.Fatal("a workflow without automatic approval must not commit on proposal")
	}

	h.tick()
	decided, err := h.reg.Decide(registrar, out.Task.ID, register.Decision{Approve: true})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decided.Task.State != model.TaskApproved {
		t.Fatalf("expected approved, got %s", decided.Task.State)
	}
	if want := "Register vehicle VF3CCHMZ3PT000010"; decided.Applied.Envelope.Summary() != want {
		t.Errorf("commit summary = %q, want %q", decided.Applied.Envelope.Summary(), want)
	}

	view, err := h.reg.GetObject(registrar, decided.ObjectID)
	if err != nil {
		t.Fatalf("read the new vehicle: %v", err)
	}
	if view.Object.Status != "registered" {
		t.Errorf("status = %s", view.Object.Status)
	}

	plates, err := h.reg.ListObjects(registrar, register.ListFilter{
		Class: "plate", Match: map[string]string{"vehicle_id": decided.ObjectID},
	})
	if err != nil {
		t.Fatalf("list plates: %v", err)
	}
	if len(plates) != 1 || plates[0].NaturalKey != "CC-789-CC" {
		t.Fatalf("the approval did not issue the plate: %+v", plates)
	}
}

func TestRequiredEvidenceIsEnforced(t *testing.T) {
	h := newHarness(t)
	clerk := h.principal("clerk-1", "clerk")
	_, err := h.reg.Propose(clerk, "first_registration", register.ProposeRequest{
		Payload: newVehicle("VF3CCHMZ3PT000011", "CD-789-CD"),
	})
	if err == nil || !strings.Contains(err.Error(), "Certificate of conformity") {
		t.Fatalf("expected the missing certificate to be refused, got %v", err)
	}
}

func TestDuplicateVINIsRefusedAtProposal(t *testing.T) {
	h := newHarness(t)
	clerk := h.principal("clerk-1", "clerk")
	_, err := h.reg.Propose(clerk, "first_registration", register.ProposeRequest{
		Payload:  newVehicle("WVWZZZ1JZXW000001", "CE-789-CE"),
		Evidence: map[string]string{"proof_of_conformity": strings.Repeat("a", 64)},
	})
	if err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Fatalf("expected a duplicate VIN to be refused, got %v", err)
	}
}

func TestSchemaViolationIsRefused(t *testing.T) {
	h := newHarness(t)
	clerk := h.principal("clerk-1", "clerk")
	bad := newVehicle("not-a-vin", "CF-789-CF")
	_, err := h.reg.Propose(clerk, "first_registration", register.ProposeRequest{
		Payload:  bad,
		Evidence: map[string]string{"proof_of_conformity": strings.Repeat("a", 64)},
	})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected a schema violation, got %v", err)
	}
}

// -- separation of duties --------------------------------------------------

func TestProposerCannotApproveTheirOwnProposal(t *testing.T) {
	h := newHarness(t)
	registrar := h.principal("registrar-1", "registrar")

	out, err := h.reg.Propose(registrar, "first_registration", register.ProposeRequest{
		Payload:  newVehicle("VF3CCHMZ3PT000012", "CG-789-CG"),
		Evidence: map[string]string{"proof_of_conformity": strings.Repeat("a", 64)},
	})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	h.tick()
	_, err = h.reg.Decide(registrar, out.Task.ID, register.Decision{Approve: true})
	if err == nil || !strings.Contains(err.Error(), "separation of duties") {
		t.Fatalf("expected separation of duties to refuse, got %v", err)
	}

	h.tick()
	other := h.principal("registrar-2", "registrar")
	if _, err := h.reg.Decide(other, out.Task.ID, register.Decision{Approve: true}); err != nil {
		t.Fatalf("a second registrar should be able to decide: %v", err)
	}
}

func TestIncompatibleRolesAreRefused(t *testing.T) {
	h := newHarness(t)
	_, err := h.reg.Pack().Model().Resolve(&auth.Identity{
		Sub: "both", Roles: []string{"register:registrar", "register:clerk"},
	}, "gov", "")
	if err == nil || !strings.Contains(err.Error(), "separation of duties") {
		t.Fatalf("expected incompatible roles to be refused, got %v", err)
	}
}

func TestClerkCannotApprove(t *testing.T) {
	h := newHarness(t)
	clerk := h.principal("clerk-1", "clerk")
	out, err := h.reg.Propose(clerk, "first_registration", register.ProposeRequest{
		Payload:  newVehicle("VF3CCHMZ3PT000013", "CH-789-CH"),
		Evidence: map[string]string{"proof_of_conformity": strings.Repeat("a", 64)},
	})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	h.tick()
	if _, err := h.reg.Decide(clerk, out.Task.ID, register.Decision{Approve: true}); err == nil {
		t.Fatal("a clerk must not be able to decide")
	}
}

// -- ownership transfer ----------------------------------------------------

func TestTransferNeedsTheBuyerAndThenSettlesUnderPolicy(t *testing.T) {
	h := newHarness(t)
	seller := h.principal("alice", "citizen")
	buyer := h.principal("bruno", "citizen")

	vehicle := h.vehicleByVIN("WVWZZZ1JZXW000001")
	owners := h.ownerByReference("PTY-0002")

	out, err := h.reg.Propose(seller, "ownership_transfer", register.ProposeRequest{
		ObjectID: vehicle,
		Payload: map[string]any{
			"buyer_id": owners, "buyer_sub": "bruno", "buyer_reference": "PTY-0002",
		},
	})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if out.Task.State != model.TaskAwaitingCounterparty {
		t.Fatalf("expected the buyer's acceptance to be required, got %s", out.Task.State)
	}

	h.tick()
	if _, err := h.reg.Accept(seller, out.Task.ID, true, "not mine to accept"); err == nil {
		t.Fatal("only the named buyer may accept")
	}

	h.tick()
	accepted, err := h.reg.Accept(buyer, out.Task.ID, true, "agreed")
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if accepted.Task.State != model.TaskApproved {
		t.Fatalf("expected policy to settle the transfer, got %s (%v)",
			accepted.Task.State, accepted.Task.Blockers)
	}

	// One link closed, one opened; the history is the ownership record.
	auditor := h.principal("auditor-1", "auditor")
	links, err := h.reg.ListObjects(auditor, register.ListFilter{
		Class: "ownership", Match: map[string]string{"vehicle_id": vehicle},
	})
	if err != nil {
		t.Fatalf("list ownership: %v", err)
	}
	if len(links) != 2 {
		t.Fatalf("expected two ownership links, got %d", len(links))
	}
	states := map[string]int{}
	for _, l := range links {
		states[l.Status]++
	}
	if states["open"] != 1 || states["closed"] != 1 {
		t.Errorf("expected one open and one closed link, got %v", states)
	}
}

func (h *harness) ownerByReference(reference string) string {
	h.t.Helper()
	p := h.principal("auditor-1", "auditor")
	owners, err := h.reg.ListObjects(p, register.ListFilter{Class: "owner", Search: reference})
	if err != nil {
		h.t.Fatalf("list owners: %v", err)
	}
	if len(owners) == 0 {
		h.t.Fatalf("no owner %s", reference)
	}
	return owners[0].ID
}

func TestAnOpenLienRoutesATransferToAHuman(t *testing.T) {
	h := newHarness(t)
	registrar := h.principal("registrar-1", "registrar")
	vehicle := h.vehicleByVIN("WVWZZZ1JZXW000001")

	h.tick()
	lien, err := h.reg.Propose(registrar, "register_lien", register.ProposeRequest{
		Payload: map[string]any{
			"vehicle_id": vehicle, "lender": "Specimen Finance", "secured_on": "2026-01-04",
			"amount": float64(8500),
		},
	})
	if err != nil {
		t.Fatalf("register a lien: %v", err)
	}
	if lien.Task.State != model.TaskApproved {
		t.Fatalf("the lien should settle under policy, got %s", lien.Task.State)
	}

	h.tick()
	seller := h.principal("alice", "citizen")
	buyer := h.principal("bruno", "citizen")
	out, err := h.reg.Propose(seller, "ownership_transfer", register.ProposeRequest{
		ObjectID: vehicle,
		Payload: map[string]any{
			"buyer_id": h.ownerByReference("PTY-0002"), "buyer_sub": "bruno",
			"buyer_reference": "PTY-0002",
		},
	})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	h.tick()
	accepted, err := h.reg.Accept(buyer, out.Task.ID, true, "agreed")
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if accepted.Task.State != model.TaskAwaitingReview {
		t.Fatalf("an open lien should route to review, got %s", accepted.Task.State)
	}

	// The registrar can still take the decision, and the blocker is
	// visible to them when they do.
	h.tick()
	task, err := h.reg.Task(registrar, out.Task.ID)
	if err != nil {
		t.Fatalf("read the proposal: %v", err)
	}
	if len(task.Blockers) != 1 || !strings.Contains(task.Blockers[0], "lien") {
		t.Fatalf("expected the lien to be reported as a blocker, got %v", task.Blockers)
	}
	h.tick()
	if _, err := h.reg.Decide(registrar, out.Task.ID, register.Decision{
		Approve: true, Reason: "lien acknowledged by the lender in writing",
	}); err != nil {
		t.Fatalf("registrar decision: %v", err)
	}
}

// -- corrections, scrappage, stolen ----------------------------------------

func TestCorrectionLinksToWhatItCorrects(t *testing.T) {
	h := newHarness(t)
	clerk := h.principal("clerk-1", "clerk")
	registrar := h.principal("registrar-1", "registrar")
	vehicle := h.vehicleByVIN("WVWZZZ1JZXW000001")

	corrected := newVehicle("WVWZZZ1JZXW000001", "AA-123-AA")
	corrected["make"] = "Volkswagen"
	corrected["model"] = "Golf"
	corrected["year"] = float64(2019)
	corrected["colour"] = "green"
	corrected["engine_cc"] = float64(1498)
	corrected["first_registration"] = "2019-04-02"

	h.tick()
	out, err := h.reg.Propose(clerk, "correction", register.ProposeRequest{
		ObjectID: vehicle,
		Payload:  corrected,
		Evidence: map[string]string{"correction_evidence": strings.Repeat("b", 64)},
		Body:     "The colour was recorded as blue at first registration; the vehicle is green.",
	})
	if err != nil {
		t.Fatalf("propose a correction: %v", err)
	}
	h.tick()
	decided, err := h.reg.Decide(registrar, out.Task.ID, register.Decision{Approve: true})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decided.Applied.Envelope.Kind != model.KindRecordCorrect {
		t.Errorf("kind = %s, want %s", decided.Applied.Envelope.Kind, model.KindRecordCorrect)
	}
	var corrects bool
	for _, ref := range decided.Applied.Envelope.Refs {
		if ref.Type == model.RefCorrects && ref.Target == vehicle {
			corrects = true
		}
	}
	if !corrects {
		t.Errorf("the correction does not link to what it corrects: %+v", decided.Applied.Envelope.Refs)
	}

	// Both versions survive, and the timeline shows the change.
	history, err := h.reg.History(registrar, vehicle)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("expected two versions, got %d", len(history))
	}
	diff := history[0].Diff
	if got, ok := diff["colour"]; !ok || got[0] != "blue" || got[1] != "green" {
		t.Errorf("expected the colour change in the diff, got %v", diff)
	}
}

func TestScrappageRetiresThePlateAndClosesOwnership(t *testing.T) {
	h := newHarness(t)
	clerk := h.principal("clerk-1", "clerk")
	registrar := h.principal("registrar-1", "registrar")
	vehicle := h.vehicleByVIN("VF1RFB00X66000002")

	h.tick()
	out, err := h.reg.Propose(clerk, "scrappage", register.ProposeRequest{
		ObjectID: vehicle,
		Evidence: map[string]string{"certificate_of_destruction": strings.Repeat("c", 64)},
	})
	if err != nil {
		t.Fatalf("propose scrappage: %v", err)
	}
	h.tick()
	if _, err := h.reg.Decide(registrar, out.Task.ID, register.Decision{Approve: true}); err != nil {
		t.Fatalf("decide: %v", err)
	}

	view, err := h.reg.GetObject(registrar, vehicle)
	if err != nil {
		t.Fatalf("read the vehicle: %v", err)
	}
	if view.Object.Status != "scrapped" {
		t.Errorf("vehicle status = %s", view.Object.Status)
	}
	plates, err := h.reg.ListObjects(registrar, register.ListFilter{
		Class: "plate", Match: map[string]string{"vehicle_id": vehicle},
	})
	if err != nil {
		t.Fatalf("list plates: %v", err)
	}
	if len(plates) != 1 || plates[0].Status != "retired" {
		t.Fatalf("the plate was not retired: %+v", plates)
	}
	links, err := h.reg.ListObjects(registrar, register.ListFilter{
		Class: "ownership", Match: map[string]string{"vehicle_id": vehicle},
	})
	if err != nil {
		t.Fatalf("list ownership: %v", err)
	}
	if len(links) != 1 || links[0].Status != "closed" {
		t.Fatalf("the ownership link was not closed: %+v", links)
	}

	// The record stays provable for ever: existence history survives.
	if _, err := h.reg.RecordEvidence(registrar, vehicle, 1); err != nil {
		t.Errorf("the first version should still be provable: %v", err)
	}
}

func TestPoliceCanFlagStolenUnderPolicy(t *testing.T) {
	h := newHarness(t)
	police := h.principal("police-1", "police")
	vehicle := h.vehicleByVIN("WVWZZZ1JZXW000001")

	h.tick()
	out, err := h.reg.Propose(police, "flag_stolen", register.ProposeRequest{
		ObjectID: vehicle,
		Payload:  map[string]any{"report_reference": "PR-2026-0912", "reported_on": "2026-08-20"},
	})
	if err != nil {
		t.Fatalf("flag stolen: %v", err)
	}
	if out.Task.State != model.TaskApproved {
		t.Fatalf("expected policy approval, got %s", out.Task.State)
	}
	view, err := h.reg.GetObject(police, vehicle)
	if err != nil {
		t.Fatalf("read the vehicle: %v", err)
	}
	if view.Object.Status != "stolen" {
		t.Errorf("status = %s", view.Object.Status)
	}
}

// -- personal data ---------------------------------------------------------

func TestPersonalDataIsWithheldFromRolesWithoutClearance(t *testing.T) {
	h := newHarness(t)
	owner := h.ownerByReference("PTY-0001")

	registrar := h.principal("registrar-1", "registrar")
	view, err := h.reg.GetObject(registrar, owner)
	if err != nil {
		t.Fatalf("registrar read: %v", err)
	}
	if view.Version.Payload["name"] != "SPECIMEN, Alice" {
		t.Errorf("a cleared role should see the name, got %v", view.Version.Payload["name"])
	}

	auditor := h.principal("auditor-1", "auditor")
	redacted, err := h.reg.GetObject(auditor, owner)
	if err != nil {
		t.Fatalf("auditor read: %v", err)
	}
	if _, present := redacted.Version.Payload["name"]; present {
		t.Error("an uncleared role must not see personal data")
	}
	if len(redacted.Version.Redacted) == 0 {
		t.Error("the withheld fields should be named, not silently dropped")
	}
	if redacted.Version.Payload["reference"] != "PTY-0001" {
		t.Error("non-personal fields should still be readable")
	}
}

func TestErasureDestroysTheKeyAndLeavesTheRecordProvable(t *testing.T) {
	h := newHarness(t)
	dpo := h.principal("dpo-1", "dpo")
	registrar := h.principal("registrar-1", "registrar")
	owner := h.ownerByReference("PTY-0001")

	before, err := h.reg.RecordEvidence(registrar, owner, 1)
	if err != nil {
		t.Fatalf("evidence before erasure: %v", err)
	}

	h.tick()
	result, err := h.reg.Erase(dpo, register.ErasureRequest{
		ObjectID: owner, PolicyID: "P01",
		Reason: "The data subject asked for erasure and the retention period has passed.",
	})
	if err != nil {
		t.Fatalf("erase: %v", err)
	}
	if result.Versions == 0 {
		t.Error("the erasure reported no affected versions")
	}

	view, err := h.reg.GetObject(registrar, owner)
	if err != nil {
		t.Fatalf("read after erasure: %v", err)
	}
	if !view.Version.Erased {
		t.Error("the record should report itself erased")
	}
	if _, present := view.Version.Payload["name"]; present {
		t.Error("the personal data is still readable after erasure")
	}
	if view.Version.Payload["reference"] != "PTY-0001" {
		t.Error("the non-personal half of the record should survive erasure")
	}

	// The commitment is unchanged, so everything that ever verified
	// still verifies.
	after, err := h.reg.RecordEvidence(registrar, owner, 1)
	if err != nil {
		t.Fatalf("evidence after erasure: %v", err)
	}
	if after.LedgerValue != before.LedgerValue {
		t.Error("erasure rewrote the ledger entry; it must only destroy the key")
	}
	if err := checkpoint.VerifyBundleProof(after); err != nil {
		t.Errorf("the record no longer proves: %v", err)
	}

	// A second erasure is refused rather than silently repeated.
	h.tick()
	if _, err := h.reg.Erase(dpo, register.ErasureRequest{ObjectID: owner, PolicyID: "P01"}); err == nil {
		t.Error("erasing twice should be refused")
	}
}

func TestErasureNeedsAPolicyThatPermitsIt(t *testing.T) {
	h := newHarness(t)
	dpo := h.principal("dpo-1", "dpo")
	owner := h.ownerByReference("PTY-0001")
	if _, err := h.reg.Erase(dpo, register.ErasureRequest{ObjectID: owner, PolicyID: "P02"}); err == nil {
		t.Fatal("a policy that does not permit erasure must refuse it")
	}
}

func TestRegistrarCannotErase(t *testing.T) {
	h := newHarness(t)
	registrar := h.principal("registrar-1", "registrar")
	owner := h.ownerByReference("PTY-0001")
	if _, err := h.reg.Erase(registrar, register.ErasureRequest{ObjectID: owner, PolicyID: "P01"}); err == nil {
		t.Fatal("erasure is the data protection officer's to run, not the registrar's")
	}
}

// -- retention -------------------------------------------------------------

func TestRetentionPrunesSupersededVersionsOnly(t *testing.T) {
	h := newHarness(t)
	clerk := h.principal("clerk-1", "clerk")
	registrar := h.principal("registrar-1", "registrar")
	operator := h.principal("operator-1", "operator")
	vehicle := h.vehicleByVIN("WVWZZZ1JZXW000001")

	corrected := newVehicle("WVWZZZ1JZXW000001", "AA-123-AA")
	corrected["make"] = "Volkswagen"
	corrected["model"] = "Golf"
	corrected["year"] = float64(2019)
	corrected["colour"] = "green"
	corrected["first_registration"] = "2019-04-02"
	h.tick()
	out, err := h.reg.Propose(clerk, "correction", register.ProposeRequest{
		ObjectID: vehicle, Payload: corrected,
		Evidence: map[string]string{"correction_evidence": strings.Repeat("b", 64)},
	})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	h.tick()
	if _, err := h.reg.Decide(registrar, out.Task.ID, register.Decision{Approve: true}); err != nil {
		t.Fatalf("decide: %v", err)
	}

	// Move the clock past the retention window.
	h.now = h.now.Add(11 * 365 * 24 * time.Hour)

	dry, err := h.reg.Prune(operator, register.PruneRequest{PolicyID: "P02", DryRun: true})
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if dry.Versions == 0 {
		t.Fatal("the dry run found nothing to prune")
	}
	if dry.Transaction != nil {
		t.Error("a dry run must not commit")
	}

	result, err := h.reg.Prune(operator, register.PruneRequest{PolicyID: "P02"})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if result.Transaction == nil {
		t.Fatal("a prune must be a transaction")
	}

	// The superseded version is gone, and says why.
	_, err = h.reg.GetVersion(registrar, vehicle, 1)
	var pruned *register.PruneError
	if !asPruneError(err, &pruned) {
		t.Fatalf("expected a prune error, got %v", err)
	}
	if pruned.Policy != "P02" {
		t.Errorf("the read should name the policy, got %q", pruned.Policy)
	}
	// The current version is untouched: retention removes history, not
	// the present.
	if _, err := h.reg.GetObject(registrar, vehicle); err != nil {
		t.Errorf("the head version should survive a retention prune: %v", err)
	}
}

func asPruneError(err error, target **register.PruneError) bool {
	if err == nil {
		return false
	}
	pruned, ok := err.(*register.PruneError)
	if ok {
		*target = pruned
	}
	return ok
}

func TestHorizonsReportEveryPolicy(t *testing.T) {
	h := newHarness(t)
	operator := h.principal("operator-1", "operator")
	horizons, err := h.reg.Horizons(operator)
	if err != nil {
		t.Fatalf("horizons: %v", err)
	}
	if len(horizons) != 3 {
		t.Fatalf("expected 3 policies, got %d", len(horizons))
	}
	for _, h := range horizons {
		if h.Horizon == 0 {
			t.Errorf("policy %s reports no horizon", h.PolicyID)
		}
	}
}

// -- proofs and checkpoints ------------------------------------------------

func TestVerifiedLookupAndAbsenceProof(t *testing.T) {
	h := newHarness(t)
	registrar := h.principal("registrar-1", "registrar")

	present, err := h.reg.NaturalKeyEvidence(registrar, "vehicle", "WVWZZZ1JZXW000001")
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	if !present.Present {
		t.Fatal("a registered VIN should come back present")
	}
	if err := checkpoint.VerifyBundleProof(present); err != nil {
		t.Fatalf("inclusion proof: %v", err)
	}
	if err := checkpoint.VerifyBundleSignature(h.reg.Keys().PublicKey(), present); err != nil {
		t.Fatalf("bundle signature: %v", err)
	}

	absent, err := h.reg.NaturalKeyEvidence(registrar, "vehicle", "WVWZZZ1JZXW999999")
	if err != nil {
		t.Fatalf("absence evidence: %v", err)
	}
	if absent.Present {
		t.Fatal("an unregistered VIN should come back absent")
	}
	if err := checkpoint.VerifyBundleProof(absent); err != nil {
		t.Fatalf("absence proof: %v", err)
	}

	// A bundle that has been edited must stop verifying.
	tampered := *present
	tampered.Root = strings.Repeat("00", 32)
	if err := checkpoint.VerifyBundleProof(&tampered); err == nil {
		t.Error("a bundle with a substituted root must not verify")
	}
	tampered = *present
	tampered.Statement = "something else entirely"
	if err := checkpoint.VerifyBundleSignature(h.reg.Keys().PublicKey(), &tampered); err == nil {
		t.Error("an edited bundle must not verify against the signature")
	}
}

func TestCheckpointsAnchorTheState(t *testing.T) {
	h := newHarness(t)
	operator := h.principal("operator-1", "operator")

	h.tick()
	first, err := h.reg.IssueCheckpoint(register.ReasonManual)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := checkpoint.VerifyCheckpoint(h.reg.Keys().PublicKey(), first); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if first.Checkpoint.ImageDigest == "" {
		t.Error("a checkpoint should say which build signed it")
	}

	// A quiet register does not issue a scheduled checkpoint.
	h.tick()
	quiet, err := h.reg.IssueCheckpoint(register.ReasonScheduled)
	if err != nil {
		t.Fatalf("scheduled: %v", err)
	}
	if quiet.Checkpoint.Version != first.Checkpoint.Version {
		t.Errorf("a scheduled checkpoint over unchanged state should be a no-op, got version %d then %d",
			first.Checkpoint.Version, quiet.Checkpoint.Version)
	}

	// After a change, it does.
	h.tick()
	registrar := h.principal("registrar-1", "registrar")
	if _, err := h.reg.Propose(registrar, "register_lien", register.ProposeRequest{
		Payload: map[string]any{
			"vehicle_id": h.vehicleByVIN("WVWZZZ1JZXW000001"),
			"lender":     "Specimen Finance", "secured_on": "2026-02-02",
		},
	}); err != nil {
		t.Fatalf("register a lien: %v", err)
	}
	h.tick()
	next, err := h.reg.IssueCheckpoint(register.ReasonScheduled)
	if err != nil {
		t.Fatalf("scheduled: %v", err)
	}
	if next.Checkpoint.Version <= first.Checkpoint.Version {
		t.Error("a scheduled checkpoint after a change should advance")
	}

	chain, err := h.reg.Checkpoints(operator, 50)
	if err != nil {
		t.Fatalf("chain: %v", err)
	}
	if len(chain) < 2 {
		t.Fatalf("expected a chain, got %d entries", len(chain))
	}
	seen := map[uint64]string{}
	for _, sc := range chain {
		if err := checkpoint.VerifyCheckpoint(h.reg.Keys().PublicKey(), sc); err != nil {
			t.Errorf("checkpoint %d does not verify: %v", sc.Checkpoint.Version, err)
		}
		if root, dup := seen[sc.Checkpoint.Version]; dup && root != sc.Checkpoint.Root {
			t.Errorf("version %d is claimed with two roots", sc.Checkpoint.Version)
		}
		seen[sc.Checkpoint.Version] = sc.Checkpoint.Root
	}
}

// -- saved queries ---------------------------------------------------------

func TestSavedQueriesAnswerTheRegisterQuestions(t *testing.T) {
	h := newHarness(t)
	auditor := h.principal("auditor-1", "auditor")

	byStatus, err := h.reg.RunQuery(auditor, "vehicles_by_status", nil)
	if err != nil {
		t.Fatalf("vehicles_by_status: %v", err)
	}
	if len(byStatus) != 1 || byStatus[0].Str("status") != "registered" || byStatus[0].Int("vehicles") != 2 {
		t.Errorf("unexpected counts: %+v", byStatus)
	}

	byMake, err := h.reg.RunQuery(auditor, "vehicles_by_make_and_year",
		map[string]string{"make": "Renault", "from_year": "2020"})
	if err != nil {
		t.Fatalf("vehicles_by_make_and_year: %v", err)
	}
	if len(byMake) != 1 || byMake[0].Str("model") != "Zoe" {
		t.Errorf("unexpected result: %+v", byMake)
	}

	owned, err := h.reg.RunQuery(auditor, "vehicles_ever_owned_by",
		map[string]string{"owner_id": h.ownerByReference("PTY-0001")})
	if err != nil {
		t.Fatalf("vehicles_ever_owned_by: %v", err)
	}
	if len(owned) != 1 || owned[0].Str("vin") != "WVWZZZ1JZXW000001" {
		t.Errorf("unexpected history walk: %+v", owned)
	}

	if _, err := h.reg.RunQuery(auditor, "no_such_query", nil); err == nil {
		t.Error("an undeclared query must be refused")
	}

	insurer := h.principal("insurer-1", "insurer")
	if _, err := h.reg.RunQuery(insurer, "vehicles_ever_owned_by",
		map[string]string{"owner_id": "anything"}); err == nil {
		t.Error("an insurer must not be able to walk ownership history")
	}
}

func TestQueryParametersCannotChangeTheStatement(t *testing.T) {
	h := newHarness(t)
	auditor := h.principal("auditor-1", "auditor")
	rows, err := h.reg.RunQuery(auditor, "vehicles_by_make_and_year", map[string]string{
		"make": "' OR 1=1 --", "from_year": "0",
	})
	if err != nil {
		t.Fatalf("the parameter should be a value, not syntax: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("the injected parameter matched %d rows", len(rows))
	}
}

// -- the log ---------------------------------------------------------------

func TestEveryTransactionCarriesAReason(t *testing.T) {
	h := newHarness(t)
	auditor := h.principal("auditor-1", "auditor")
	entries, err := h.reg.Log(auditor, register.LogFilter{Limit: 500})
	if err != nil {
		t.Fatalf("log: %v", err)
	}
	for _, e := range entries {
		if err := e.Envelope.Validate(); err != nil {
			t.Errorf("transaction %s: %v", e.TxID, err)
		}
		if e.RootBefore == "" {
			t.Errorf("transaction %s does not record where the ledger stood", e.TxID)
		}
		// An action is one commit, so it always produces the next
		// version. That is the claim the lineage chain can be checked
		// against; there is no root-after field to be wrong.
		if e.VersionAfter != e.VersionBefore+1 {
			t.Errorf("transaction %s spans versions %d → %d, want one commit",
				e.TxID, e.VersionBefore, e.VersionAfter)
		}
	}
}

func TestInsurerCannotReadOwners(t *testing.T) {
	h := newHarness(t)
	insurer := h.principal("insurer-1", "insurer")
	if _, err := h.reg.ListObjects(insurer, register.ListFilter{Class: "owner"}); err == nil {
		t.Fatal("a purpose-scoped read credential must not reach owner records")
	}
	if _, err := h.reg.Log(insurer, register.LogFilter{}); err == nil {
		t.Fatal("an insurer has no business in the transaction log")
	}
}

// -- crash recovery --------------------------------------------------------

// A governance action is written ahead of its effects and marked
// applied afterwards, so a crash in between leaves a transaction the
// ledger records but has not carried out. The next start finishes it.
// Applying a write set twice must land on the same rows, or recovery
// would be repair rather than replay.
func TestPendingTransactionsAreReplayedOnStart(t *testing.T) {
	dir := t.TempDir()
	h := newHarnessIn(t, dir)

	env := model.Envelope{
		Kind: model.KindPolicySet, Tenant: "gov",
		Author:    model.Author{Sub: "operator-1", Display: "Operator", Role: "operator"},
		Timestamp: h.now.Unix(), Message: "Record an interrupted action",
	}
	ops := []model.WriteOp{{
		Table:  "registry",
		Key:    map[string]any{"k": "replay-probe"},
		Values: map[string]any{"v": model.Binary("carried out"), "updated_at": h.now.Unix()},
	}}
	txid := writePendingTransaction(t, h, env, ops)

	// Nothing has been carried out yet.
	if probe := readRegistry(t, h, "replay-probe"); probe != "" {
		t.Fatalf("the effect landed before the replay: %q", probe)
	}
	h.reg.Store().Close()

	h2 := newHarnessIn(t, dir)
	if probe := readRegistry(t, h2, "replay-probe"); probe != "carried out" {
		t.Fatalf("the pending transaction was not replayed, probe = %q", probe)
	}
	rows, err := h2.reg.Store().Query("SELECT state, version_after FROM `transactions` WHERE txid = '" + txid + "'")
	if err != nil || len(rows) != 1 {
		t.Fatalf("read the transaction back: %v", err)
	}
	if rows[0].Str("state") != model.TxApplied {
		t.Errorf("state = %s, want applied", rows[0].Str("state"))
	}
	if rows[0].Uint("version_after") == 0 {
		t.Error("the replayed transaction does not record where the ledger ended up")
	}
	h2.reg.Store().Close()

	// A third start must be a no-op: there is nothing left pending.
	h3 := newHarnessIn(t, dir)
	if probe := readRegistry(t, h3, "replay-probe"); probe != "carried out" {
		t.Fatalf("a second restart disturbed the effect, probe = %q", probe)
	}
}

func writePendingTransaction(t *testing.T, h *harness, env model.Envelope, ops []model.WriteOp) string {
	t.Helper()
	body, err := canonical(map[string]any{"envelope": env, "write_set": ops})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	txid := hex.EncodeToString(sum[:])

	envelope, err := canonical(env)
	if err != nil {
		t.Fatal(err)
	}
	writeSet, err := canonical(ops)
	if err != nil {
		t.Fatal(err)
	}
	err = h.reg.Store().Do(func(tx *store.Tx) error {
		root, version := tx.Root()
		return tx.Exec(store.Insert("transactions", map[string]any{
			"txid": txid, "tenant": env.Tenant, "kind": env.Kind, "class": "",
			"object_id": "", "author_sub": env.Author.Sub,
			"author_display": env.Author.Display, "author_role": env.Author.Role,
			"summary": env.Summary(), "created_at": env.Timestamp, "state": model.TxPending,
			"root_before": root, "version_before": version,
			"version_after": uint64(0), "envelope": envelope, "write_set": writeSet,
		}))
	})
	if err != nil {
		t.Fatalf("write the pending transaction: %v", err)
	}
	return txid
}

func readRegistry(t *testing.T, h *harness, key string) string {
	t.Helper()
	rows, err := h.reg.Store().Query("SELECT v FROM `registry` WHERE k = " + store.Lit(key))
	if err != nil {
		t.Fatalf("read the registry: %v", err)
	}
	if len(rows) == 0 {
		return ""
	}
	return string(rows[0].Bytes("v"))
}

// canonical is the same encoding the register hashes transactions
// under; the replay test has to produce a transaction id the register
// would have produced itself.
func canonical(v any) ([]byte, error) { return canon.Marshal(v) }
