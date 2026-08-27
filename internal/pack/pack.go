// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package pack loads and validates a register pack: the declarative
// description of one register's classes, workflows, roles and retention
// policies.
//
// The generic core knows nothing about vehicles, owners or plates. A
// pack is what turns it into a particular register, and a pack is data,
// not code: it is validated on load and committed to the ledger, so the
// rules a decision was taken under are as auditable as the decision.
package pack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/Privasys/container-app-register/internal/auth"
	"github.com/Privasys/container-app-register/internal/jsonschema"
)

// Pack is one register's declarative definition.
type Pack struct {
	Name        string             `json:"name"`
	Title       string             `json:"title"`
	Version     string             `json:"version"`
	Description string             `json:"description,omitempty"`
	Tenant      string             `json:"tenant,omitempty"`
	Roles       []auth.RoleSpec    `json:"roles"`
	Classes     []*Class           `json:"classes"`
	Workflows   []*Workflow        `json:"workflows"`
	Queries     []*NamedQuery      `json:"queries,omitempty"`
	Retention   []*RetentionPolicy `json:"retention,omitempty"`
	Seed        *Seed              `json:"seed,omitempty"`

	classByName    map[string]*Class
	workflowByName map[string]*Workflow
	queryByName    map[string]*NamedQuery
	model          *auth.Model
}

// NamedQuery is a saved, role-gated read over the register's own SQL.
//
// The register does not accept SQL from callers: the application is the
// policy boundary in front of its data, and an arbitrary-query endpoint
// would move that boundary to whoever holds a token. What it accepts
// instead are the queries a pack declared, with typed parameters
// substituted as literals.
type NamedQuery struct {
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	// Roles that may run the query. Empty means any role with read
	// permission over the query's class.
	Roles  []string     `json:"roles,omitempty"`
	SQL    string       `json:"sql"`
	Params []QueryParam `json:"params,omitempty"`
}

// QueryParam is one typed input to a saved query.
type QueryParam struct {
	Name     string `json:"name"`
	Title    string `json:"title,omitempty"`
	Type     string `json:"type,omitempty"`
	Required bool   `json:"required,omitempty"`
	Default  string `json:"default,omitempty"`
}

// Class is one kind of record the register holds.
type Class struct {
	Name  string `json:"name"`
	Title string `json:"title,omitempty"`
	// NaturalKey names the property that uniquely identifies a record of
	// this class within its tenant (a VIN, a plate number). Empty when
	// records have no natural key.
	NaturalKey string `json:"natural_key,omitempty"`
	// Statuses is the closed set of lifecycle states, and Initial is the
	// one a new record starts in.
	Statuses []string `json:"statuses"`
	Initial  string   `json:"initial_status"`
	// Encryption selects the data-encryption-key scope for this class:
	// "none", "tenant", "class" or "subject". A subject scope gives each
	// record its own key, which is what makes per-person crypto-erasure
	// a single key deletion.
	Encryption string `json:"encryption,omitempty"`
	// Schema is the JSON Schema records of this class are validated
	// against. Its x-register annotations decide which properties are
	// personal data and which project into the query table.
	Schema json.RawMessage `json:"schema"`

	compiled *jsonschema.Schema
}

// Compiled returns the validated schema.
func (c *Class) Compiled() *jsonschema.Schema { return c.compiled }

// QueryTable is the SQL table name a class's queryable properties
// project into.
func (c *Class) QueryTable() string { return "q_" + c.Name }

// Encryption scopes.
const (
	EncNone    = "none"
	EncTenant  = "tenant"
	EncClass   = "class"
	EncSubject = "subject"
)

// Workflow is a propose/review/decide procedure over one class.
type Workflow struct {
	Name  string `json:"name"`
	Title string `json:"title,omitempty"`
	Class string `json:"class"`
	// Action is "create", "update", "status" or "correct". It decides
	// whether the proposal needs a target object and what the default
	// effect does.
	Action string `json:"action"`
	// ProposeRoles and ApproveRoles gate the two halves of the
	// procedure.
	ProposeRoles []string `json:"propose_roles"`
	ApproveRoles []string `json:"approve_roles"`
	// Independence refuses an approval from the proposer, whatever roles
	// they hold.
	Independence bool `json:"independence,omitempty"`
	// Evidence lists documents that must accompany the proposal. Only
	// the hash is held: the register records that a document with this
	// digest was presented, never the document.
	Evidence []Evidence `json:"evidence,omitempty"`
	// Counterparty, when set, adds a second-party acceptance step before
	// review.
	Counterparty *Counterparty `json:"counterparty,omitempty"`
	// Conditions are checked at proposal and again at decision time.
	Conditions []Condition `json:"conditions,omitempty"`
	// AutoApprove lets a proposal that satisfies every condition be
	// committed under policy, without a human decision. A failing
	// condition routes it to manual review instead.
	AutoApprove bool `json:"auto_approve,omitempty"`
	// Message is the template for the commit message summary.
	Message string `json:"message"`
	// Effects are what approval does. An empty list means the default
	// effect for the action.
	Effects []Effect `json:"effects,omitempty"`
	// Status is the status a "status" action moves the target to.
	Status string `json:"status,omitempty"`
	// Input, when set, validates the proposal payload for workflows
	// whose payload is not a whole record (a status change carrying
	// evidence, say).
	Input json.RawMessage `json:"input,omitempty"`

	compiledInput *jsonschema.Schema
}

// CompiledInput returns the validated input schema, or nil.
func (w *Workflow) CompiledInput() *jsonschema.Schema { return w.compiledInput }

// Workflow actions.
const (
	ActionCreate  = "create"
	ActionUpdate  = "update"
	ActionStatus  = "status"
	ActionCorrect = "correct"
)

// Evidence is a required document digest.
type Evidence struct {
	Key      string `json:"key"`
	Title    string `json:"title,omitempty"`
	Required bool   `json:"required,omitempty"`
}

// Counterparty describes the second-party acceptance step.
type Counterparty struct {
	// Field names the proposal property carrying the counterparty's
	// subject identifier.
	Field string `json:"field"`
	// Prompt is shown to the counterparty in the explorer.
	Prompt string `json:"prompt,omitempty"`
}

// Condition is a predicate evaluated against the register's own SQL.
type Condition struct {
	ID          string `json:"id"`
	Description string `json:"description,omitempty"`
	// SQL is a single SELECT returning one value, with {{…}} references
	// substituted as SQL literals before it runs.
	SQL string `json:"sql"`
	// Expect is "zero" or "nonzero".
	Expect string `json:"expect"`
	// OnFail is "review" (route to a human) or "reject".
	OnFail string `json:"on_fail"`
	// Message explains a failure in the task's blocker list.
	Message string `json:"message,omitempty"`
}

// Condition outcomes.
const (
	ExpectZero    = "zero"
	ExpectNonZero = "nonzero"
	OnFailReview  = "review"
	OnFailReject  = "reject"
)

// Effect is one consequence of an approval.
type Effect struct {
	Type string `json:"type"`
	// Class is the target class for create_object, close_link and
	// open_link.
	Class string `json:"class,omitempty"`
	// Target is an object reference template for set_status.
	Target string `json:"target,omitempty"`
	// Status is the status to set.
	Status string `json:"status,omitempty"`
	// Payload templates the record body written by create_object and
	// open_link.
	Payload map[string]any `json:"payload,omitempty"`
	// Match selects the link record close_link acts on.
	Match map[string]any `json:"match,omitempty"`
	// Set is applied to the matched link record.
	Set map[string]any `json:"set,omitempty"`
	// Optional suppresses the error when close_link matches nothing.
	Optional bool `json:"optional,omitempty"`
}

// Effect types.
const (
	EffectRecord    = "record"
	EffectSetStatus = "set_status"
	EffectCreate    = "create_object"
	EffectCloseLink = "close_link"
	EffectOpenLink  = "open_link"
)

// RetentionPolicy is a retention policy: how long versions of a class
// are kept before a policy-gated prune may remove their content.
type RetentionPolicy struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Class string `json:"class"`
	// WindowDays is the retention window measured from the version's
	// commit time.
	WindowDays int `json:"window_days"`
	// Scope is "pii" (prune personal-data-bearing versions only) or
	// "all".
	Scope string `json:"scope"`
	// Erasure permits data-subject erasure under this policy, i.e.
	// destroying the record's data-encryption key.
	Erasure bool `json:"erasure,omitempty"`
}

// Retention scopes.
const (
	ScopePII = "pii"
	ScopeAll = "all"
)

// Seed is optional demo content, applied once on a fresh register.
type Seed struct {
	Message string       `json:"message,omitempty"`
	Objects []SeedObject `json:"objects,omitempty"`
}

// SeedObject is one seeded record.
type SeedObject struct {
	Class   string         `json:"class"`
	Ref     string         `json:"ref,omitempty"`
	Status  string         `json:"status,omitempty"`
	Payload map[string]any `json:"payload"`
	Message string         `json:"message,omitempty"`
}

var nameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,47}$`)

// Load parses and validates a pack document.
func Load(doc []byte) (*Pack, error) {
	var p Pack
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("pack: %w", err)
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *Pack) validate() error {
	if !nameRe.MatchString(p.Name) {
		return fmt.Errorf("pack: name %q must match %s", p.Name, nameRe)
	}
	if p.Version == "" {
		return fmt.Errorf("pack: version is required")
	}
	if len(p.Classes) == 0 {
		return fmt.Errorf("pack: no classes declared")
	}

	model, err := auth.NewModel(p.Roles)
	if err != nil {
		return fmt.Errorf("pack: %w", err)
	}
	p.model = model

	p.classByName = map[string]*Class{}
	for _, c := range p.Classes {
		if !nameRe.MatchString(c.Name) {
			return fmt.Errorf("pack: class name %q must match %s", c.Name, nameRe)
		}
		if _, dup := p.classByName[c.Name]; dup {
			return fmt.Errorf("pack: class %q is declared twice", c.Name)
		}
		if len(c.Statuses) == 0 {
			return fmt.Errorf("pack: class %q declares no statuses", c.Name)
		}
		if !contains(c.Statuses, c.Initial) {
			return fmt.Errorf("pack: class %q initial status %q is not one of its statuses", c.Name, c.Initial)
		}
		if c.Encryption == "" {
			c.Encryption = EncNone
		}
		switch c.Encryption {
		case EncNone, EncTenant, EncClass, EncSubject:
		default:
			return fmt.Errorf("pack: class %q has unknown encryption scope %q", c.Name, c.Encryption)
		}
		compiled, err := jsonschema.Compile(c.Schema)
		if err != nil {
			return fmt.Errorf("pack: class %q: %w", c.Name, err)
		}
		c.compiled = compiled
		if c.NaturalKey != "" {
			prop, ok := compiled.Properties[c.NaturalKey]
			if !ok {
				return fmt.Errorf("pack: class %q natural key %q is not a declared property", c.Name, c.NaturalKey)
			}
			if prop.Register != nil && prop.Register.PII {
				return fmt.Errorf("pack: class %q natural key %q is personal data: a natural key is an index "+
					"term and is held in the clear", c.Name, c.NaturalKey)
			}
		}
		if c.Encryption != EncNone && len(compiled.PIIFields()) == 0 {
			return fmt.Errorf("pack: class %q is encrypted but marks no property as personal data", c.Name)
		}
		if c.Encryption == EncNone && len(compiled.PIIFields()) > 0 {
			return fmt.Errorf("pack: class %q marks personal data but declares no encryption scope", c.Name)
		}
		for _, proj := range compiled.Projections() {
			if !nameRe.MatchString(proj.Column) {
				return fmt.Errorf("pack: class %q column %q must match %s", c.Name, proj.Column, nameRe)
			}
			if prop := compiled.Properties[proj.Property]; prop.Register.PII {
				return fmt.Errorf("pack: class %q property %q is personal data and cannot be queryable: "+
					"a projected column is plaintext in the query table", c.Name, proj.Property)
			}
		}
		p.classByName[c.Name] = c
	}

	for _, c := range p.Classes {
		for prop, ref := range c.compiled.References() {
			if _, ok := p.classByName[ref]; !ok {
				return fmt.Errorf("pack: class %q property %q references unknown class %q", c.Name, prop, ref)
			}
		}
	}

	p.workflowByName = map[string]*Workflow{}
	for _, w := range p.Workflows {
		if !nameRe.MatchString(w.Name) {
			return fmt.Errorf("pack: workflow name %q must match %s", w.Name, nameRe)
		}
		if _, dup := p.workflowByName[w.Name]; dup {
			return fmt.Errorf("pack: workflow %q is declared twice", w.Name)
		}
		class, ok := p.classByName[w.Class]
		if !ok {
			return fmt.Errorf("pack: workflow %q targets unknown class %q", w.Name, w.Class)
		}
		switch w.Action {
		case ActionCreate, ActionUpdate, ActionStatus, ActionCorrect:
		default:
			return fmt.Errorf("pack: workflow %q has unknown action %q", w.Name, w.Action)
		}
		if w.Action == ActionStatus && !contains(class.Statuses, w.Status) {
			return fmt.Errorf("pack: workflow %q sets status %q, which class %q does not declare",
				w.Name, w.Status, class.Name)
		}
		if strings.TrimSpace(w.Message) == "" {
			return fmt.Errorf("pack: workflow %q has no commit-message template", w.Name)
		}
		for _, role := range append(append([]string{}, w.ProposeRoles...), w.ApproveRoles...) {
			if model.Role(role) == nil {
				return fmt.Errorf("pack: workflow %q names unknown role %q", w.Name, role)
			}
		}
		if len(w.ApproveRoles) == 0 && !w.AutoApprove {
			return fmt.Errorf("pack: workflow %q has no approvers and no automatic approval", w.Name)
		}
		for _, cond := range w.Conditions {
			if err := validateCondition(w.Name, cond); err != nil {
				return err
			}
		}
		for i, e := range w.Effects {
			if err := p.validateEffect(w, i, e); err != nil {
				return err
			}
		}
		if w.Input != nil {
			compiled, err := jsonschema.Compile(w.Input)
			if err != nil {
				return fmt.Errorf("pack: workflow %q input: %w", w.Name, err)
			}
			w.compiledInput = compiled
		}
		p.workflowByName[w.Name] = w
	}

	p.queryByName = map[string]*NamedQuery{}
	for _, q := range p.Queries {
		if !nameRe.MatchString(q.Name) {
			return fmt.Errorf("pack: query name %q must match %s", q.Name, nameRe)
		}
		if _, dup := p.queryByName[q.Name]; dup {
			return fmt.Errorf("pack: query %q is declared twice", q.Name)
		}
		if !selectRe.MatchString(q.SQL) || strings.Contains(q.SQL, ";") {
			return fmt.Errorf("pack: query %q must be a single SELECT", q.Name)
		}
		for _, role := range q.Roles {
			if model.Role(role) == nil {
				return fmt.Errorf("pack: query %q names unknown role %q", q.Name, role)
			}
		}
		for _, param := range q.Params {
			if !nameRe.MatchString(param.Name) {
				return fmt.Errorf("pack: query %q parameter %q must match %s", q.Name, param.Name, nameRe)
			}
			switch param.Type {
			case "", "string", "integer", "number":
			default:
				return fmt.Errorf("pack: query %q parameter %q has unknown type %q", q.Name, param.Name, param.Type)
			}
		}
		p.queryByName[q.Name] = q
	}

	seenPolicy := map[string]bool{}
	for _, r := range p.Retention {
		if r.ID == "" {
			return fmt.Errorf("pack: a retention policy has no id")
		}
		if seenPolicy[r.ID] {
			return fmt.Errorf("pack: retention policy %q is declared twice", r.ID)
		}
		seenPolicy[r.ID] = true
		if _, ok := p.classByName[r.Class]; !ok {
			return fmt.Errorf("pack: retention policy %q targets unknown class %q", r.ID, r.Class)
		}
		if r.WindowDays < 0 {
			return fmt.Errorf("pack: retention policy %q has a negative window", r.ID)
		}
		switch r.Scope {
		case ScopePII, ScopeAll:
		default:
			return fmt.Errorf("pack: retention policy %q has unknown scope %q", r.ID, r.Scope)
		}
	}

	if p.Seed != nil {
		for i, o := range p.Seed.Objects {
			if _, ok := p.classByName[o.Class]; !ok {
				return fmt.Errorf("pack: seed object %d targets unknown class %q", i, o.Class)
			}
		}
	}
	return nil
}

var selectRe = regexp.MustCompile(`(?is)^\s*select\s`)

func validateCondition(workflow string, c Condition) error {
	if c.ID == "" {
		return fmt.Errorf("pack: workflow %q has a condition with no id", workflow)
	}
	if !selectRe.MatchString(c.SQL) {
		return fmt.Errorf("pack: workflow %q condition %q must be a SELECT", workflow, c.ID)
	}
	if strings.Contains(c.SQL, ";") {
		return fmt.Errorf("pack: workflow %q condition %q must be a single statement", workflow, c.ID)
	}
	switch c.Expect {
	case ExpectZero, ExpectNonZero:
	default:
		return fmt.Errorf("pack: workflow %q condition %q expects %q, want zero or nonzero", workflow, c.ID, c.Expect)
	}
	switch c.OnFail {
	case OnFailReview, OnFailReject:
	default:
		return fmt.Errorf("pack: workflow %q condition %q has unknown on_fail %q", workflow, c.ID, c.OnFail)
	}
	return nil
}

func (p *Pack) validateEffect(w *Workflow, i int, e Effect) error {
	where := fmt.Sprintf("pack: workflow %q effect %d", w.Name, i)
	switch e.Type {
	case EffectRecord:
	case EffectSetStatus:
		if e.Status == "" {
			return fmt.Errorf("%s sets no status", where)
		}
		class := w.Class
		if e.Class != "" {
			class = e.Class
		}
		c, ok := p.classByName[class]
		if !ok {
			return fmt.Errorf("%s targets unknown class %q", where, class)
		}
		if !contains(c.Statuses, e.Status) {
			return fmt.Errorf("%s sets status %q, which class %q does not declare", where, e.Status, class)
		}
	case EffectCreate, EffectOpenLink:
		if _, ok := p.classByName[e.Class]; !ok {
			return fmt.Errorf("%s targets unknown class %q", where, e.Class)
		}
		if len(e.Payload) == 0 {
			return fmt.Errorf("%s has no payload template", where)
		}
	case EffectCloseLink:
		if _, ok := p.classByName[e.Class]; !ok {
			return fmt.Errorf("%s targets unknown class %q", where, e.Class)
		}
		if len(e.Match) == 0 || len(e.Set) == 0 {
			return fmt.Errorf("%s needs both a match and a set", where)
		}
	default:
		return fmt.Errorf("%s has unknown type %q", where, e.Type)
	}
	return nil
}

// Model returns the pack's role model.
func (p *Pack) Model() *auth.Model { return p.model }

// Class looks up a class by name.
func (p *Pack) Class(name string) *Class { return p.classByName[name] }

// Workflow looks up a workflow by name.
func (p *Pack) Workflow(name string) *Workflow { return p.workflowByName[name] }

// Query looks up a saved query by name.
func (p *Pack) Query(name string) *NamedQuery { return p.queryByName[name] }

// WorkflowsFor lists the workflows over one class, in name order.
func (p *Pack) WorkflowsFor(class string) []*Workflow {
	var out []*Workflow
	for _, w := range p.Workflows {
		if w.Class == class {
			out = append(out, w)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// RetentionFor lists the retention policies covering a class.
func (p *Pack) RetentionFor(class string) []*RetentionPolicy {
	var out []*RetentionPolicy
	for _, r := range p.Retention {
		if r.Class == class {
			out = append(out, r)
		}
	}
	return out
}

// Policy looks up a retention policy by id.
func (p *Pack) Policy(id string) *RetentionPolicy {
	for _, r := range p.Retention {
		if r.ID == id {
			return r
		}
	}
	return nil
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
