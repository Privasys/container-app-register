# Pack reference

A pack is the declarative definition of one register: what it holds,
who may do what to it, under which procedure, for how long, and which
questions it will answer. It is data, validated on load and committed
to the ledger, so the rules a decision was taken under are as auditable
as the decision itself.

The complete example is
[`packs/car-register/pack.json`](../packs/car-register/pack.json).

## Document

```json
{
  "name": "car_register",
  "title": "National vehicle register",
  "version": "1.0.0",
  "description": "…",
  "tenant": "gov",
  "roles":     [ … ],
  "classes":   [ … ],
  "workflows": [ … ],
  "queries":   [ … ],
  "retention": [ … ],
  "seed":      { … }
}
```

`name` must match `^[a-z][a-z0-9_]{0,47}$`; it becomes part of SQL
identifiers, so it is deliberately narrow. The directory a pack is
baked into may be named more freely: the vehicle register is
`packs/car-register/`, referenced as `pack_ref: "car-register"`.

The loader refuses unknown fields anywhere in the document. A pack that
appears to declare something the register does not implement would be
worse than one that fails to load.

## Classes

```json
{
  "name": "owner",
  "title": "Owner",
  "natural_key": "reference",
  "statuses": ["active", "closed"],
  "initial_status": "active",
  "encryption": "subject",
  "schema": { … }
}
```

| Field | |
| --- | --- |
| `natural_key` | The property that identifies a record within its tenant. Optional. Uniqueness is enforced, and the key becomes provable in its own right: an absence proof answers "was this ever registered here". |
| `statuses` | The closed set of lifecycle states. A status change appends a version like any other change. |
| `encryption` | `none`, `tenant`, `class` or `subject`. A subject scope gives each record its own key, which is what makes per-person crypto-erasure a single key deletion. |
| `schema` | JSON Schema, in the subset below, with `x-register` annotations. |

### The schema subset

Supported keywords: `type`, `title`, `description`, `enum`, `const`,
`required`, `properties`, `additionalProperties`, `items`, `minItems`,
`maxItems`, `uniqueItems`, `minLength`, `maxLength`, `pattern`,
`format`, `minimum`, `maximum`, `exclusiveMinimum`,
`exclusiveMaximum`, `multipleOf`, `x-register`.

Types: `object`, `array`, `string`, `number`, `integer`, `boolean`,
`null`. Formats: `date`, `date-time`, `email`, `uri`, `sha256`.

Anything else is refused at load. A schema is a ledger object: once
committed, a record validated against it must keep validating the same
way on every later build, and a large validator with its own release
cadence is a poor fit for that promise.

### `x-register` on a property

| Field | |
| --- | --- |
| `pii` | Personal data. Encrypted under the class's data-encryption key, redacted for roles without clearance, and destroyed by an erasure. |
| `queryable` | Projected into the class's query table so SQL can filter, sort and count on it. |
| `indexed` | A secondary index on the projected column. |
| `unique` | A unique index, and a core-level check that gives a readable error before the constraint fires. |
| `column` | Override the projected column name. The names `object_id`, `tenant`, `status` and `updated_at` belong to every query table and are refused. |
| `member` | Project one scalar member of an object-valued property instead of the object. A record that wraps every value in an envelope `{"value": …, "status": …}` sets `"member": "value"`; the column takes the member's type, and an envelope that is absent or lacks the member projects the column's zero value. The property must be an object that declares the member, and the member must be a scalar. |
| `reference` | The class this property points at. The core enforces the referential rule the SQL layer has no foreign keys for, including against records created earlier in the same write set. |
| `public` | Shown to anyone, without signing in, by the public reader (`GET /public/v1/{class}` and `/public/v1/{class}/{key}`). A class with no public property is not read there. An envelope shows its value and status only; inside a group, an entry shows its public members. A search matches the start of the natural key and any public text column, ignoring case. |

Two combinations the loader refuses: a property that is both `pii` and
`queryable`, because a query projection is plaintext and everything in
it is readable by every query the register can run; and a `natural_key`
that is `pii`, because a natural key is an index term.

## Workflows

```json
{
  "name": "ownership_transfer",
  "title": "Ownership transfer",
  "class": "vehicle",
  "action": "update",
  "propose_roles": ["citizen", "clerk", "registrar"],
  "approve_roles": ["registrar"],
  "independence": true,
  "auto_approve": true,
  "message": "Transfer {{object.natural_key}} to {{payload.buyer_reference}}",
  "counterparty": { "field": "buyer_sub", "prompt": "…" },
  "input":      { … },
  "conditions": [ … ],
  "effects":    [ … ]
}
```

| Field | |
| --- | --- |
| `action` | `create`, `update`, `status` or `correct`. Decides whether a proposal needs a target record and what the default effect does. |
| `independence` | Refuses an approval from the proposer, whatever roles they hold. |
| `auto_approve` | A proposal that satisfies every condition is committed under policy, in a second transaction authored by `policy` rather than folded silently into the first. A failing condition routes it to a human instead. |
| `evidence` | Documents that must accompany a proposal, as SHA-256 digests. The register records that a document with this digest was presented, never the document. |
| `counterparty` | Names the proposal property carrying a second party's subject. Only that party can accept, whatever roles they hold. |
| `input` | A schema for proposals that carry something other than a whole record. Without it, `create`, `update` and `correct` validate the payload against the class schema at proposal time. |
| `message` | The commit-summary template. Required: a workflow that cannot say what it did has no business committing. |

### Conditions

```json
{
  "id": "no_open_lien",
  "description": "A vehicle under an undischarged lien needs a registrar's decision",
  "sql": "SELECT COUNT(*) FROM `q_lien` WHERE vehicle_id = {{object.id}} AND status = 'open'",
  "expect": "zero",
  "on_fail": "review",
  "message": "an undischarged lien is recorded against this vehicle"
}
```

A condition is a single `SELECT` returning one value. `{{…}}`
references are substituted **as SQL literals**, so a value in a
proposal can be a value in the query and never syntax. `expect` is
`zero` or `nonzero`; `on_fail` is `review` (route to a human) or
`reject` (refuse outright). Conditions run at proposal and again at
decision.

### Effects

An empty `effects` list means the default for the action: write the
proposed record.

| Type | |
| --- | --- |
| `record` | Create, update or move the target record, per the action. |
| `set_status` | Move a record to a status. `target` templates the record; `class` names its class when it is not the workflow's. |
| `create_object` | Create a companion record of another class from a templated payload. |
| `open_link` | The same, for a link record such as an ownership. |
| `close_link` | Find the matching link through the class's query table, apply `set` to its payload, and optionally move it to `status`. `optional` tolerates finding nothing. |

### Template references

`{{payload.<field>}}`, `{{object.id}}`, `{{object.natural_key}}`,
`{{object.class}}`, `{{object.status}}`, `{{task.id}}`,
`{{actor.sub}}`, `{{actor.display}}`, `{{actor.role}}`, `{{tenant}}`,
`{{today}}`, `{{now}}`, and `{{created.<class>.id}}` for a record
created by an earlier effect in the same approval.

## Roles

```json
{
  "name": "clerk",
  "title": "Counter clerk",
  "oidc_roles": ["register:clerk"],
  "permissions": ["read:vehicle", "propose:first_registration"],
  "pii": true,
  "incompatible_with": ["registrar"]
}
```

Permissions are a bare verb or `verb:scope`; `verb:*` grants the verb
over every scope. The verbs are `read`, `propose`, `approve`,
`explorer`, `proofs`, `checkpoints`, `retention`, `erasure`, `schema`,
`keys`, `admin`.

`pii` clears the role to see personal data in the clear. A role without
it sees those fields named in `redacted` rather than silently dropped.

`incompatible_with` is separation of duties. A caller who holds two
incompatible roles is refused outright rather than acting under the
more powerful of the two: a breach the system does not notice is not a
control.

`history_actors: true` shows the role who made each change, in the
histories and logs it may already read: the author's name and email
from their sealed profile, and the organisation they acted for (recorded
with the change as `author.organisation`; for a change made before that
was recorded, the organisation they belonged to then, when known). A
history entry and a transaction carry it as `actor`; the log as
`actors`, by transaction id. A history entry whose version an approval
wrote also carries `proposer_actor`: who filed what was approved, beside
who decided it (or nobody, when it was approved under policy). Without the flag a change names its author
by subject and role only, which is all a transaction ever holds: a name
in it could not be erased. When a person's profile is erased, their
changes go back to naming a subject. Changes the register makes on its
own (system authors, approvals under policy) have no actor.

### What a change wrote

The log, a transaction and a record's history serve each transaction's
write set as far as the reader may read it. A write to a record (its
object, versions, natural key or projection) keeps its values for a
reader who may read the record's class within their scope; any other
write keeps them only for a role that holds both `admin` and `pii`.
Otherwise the write keeps its table, key and whether it deletes, and its
values give way to a `summary`: the columns, the size and a SHA-256
digest. An auditor checks what changed, and when, without reading it.

### The console

```json
"console_roles": ["operator", "auditor"]
```

names the roles the register's console is open to: `GET /api/v1/me`
says `console: true` or `false`, and the console shows itself only when
it is open. An empty list switches the console off: its page is not
served at all. Absent, every role may use it. The console is a view of
the API, and every call it makes is checked as any other is: this
setting says who is offered it, not what they may do.

### Invitation rules

An organisation's administrator invites colleagues into it. A pack can let
another role invite people into an organisation it does not administer:

```json
"invitations": [{ "inviter": "fleet_manager", "role": "driver", "class": "fleet" }]
```

A holder of `inviter` may then invite someone to `role` into the
organisation whose key is the natural key of a record of `class` within
the inviter's scope: here, a fleet manager invites the drivers of a fleet
it manages. Outside its scope, or to another role, the
invitation is refused.

### How a role is held

`held` says where a role comes from: `person` (the default), granted to
one named person; `organisation`, held by an organisation whose members
inherit it; `either`; or `appointment`, given by an appointment record.

### Appointments

An appointment is a record that names a role, held personally by the one
person bound to it, for as long as the record is current. A designated
driver appointed to one fleet drives for that fleet only, and colleagues
at their own firm inherit nothing:

```json
"appointments": [
  { "class": "driver_appointment", "role": "designated_driver",
    "keys": ["fleet_number"], "ended_by": "ceased_on" },
  { "class": "inspector_appointment", "role_property": "kind",
    "roles": { "BRAKES": "brake_inspector", "EMISSIONS": "emissions_inspector" },
    "keys": ["fleet_number", "vin"] }
]
```

| Field | Meaning |
|---|---|
| `class` | The appointment class. Needs a natural key; one entry per class. |
| `role` | The role every record of the class gives. Or: |
| `role_property`, `roles` | The property whose value names the role, and the role each value gives. |
| `keys` | The properties a scope compares against when the person acts under the role. |
| `ended_by` | Optional. A property that ends the appointment when it holds a value. |

Every role an appointment gives is declared `"held": "appointment"`.

A record is **current** while it is in its class's initial status, its
head version is not pruned, the record is not erased, and `ended_by`
(when named) is empty. The person bound to a current record holds its
role. When the record leaves its initial status, or `ended_by` is set,
the role lapses at once: no further transaction is needed, because the
register reads the record whenever it asks what a person holds.

**Binding.** A person is bound to a record by accepting an invitation to
it: `POST /api/v1/invites` with `role` and `appointment_key` (the
record's natural key; `appointment_class` when several classes give the
role), as a link or by email. Whoever manages members may invite to any
appointment. An invitation rule whose class is an appointment class lets
another role invite to the records within its scope:

```json
"invitations": [{ "inviter": "fleet_manager", "role": "designated_driver", "class": "driver_appointment" }]
```

The invitation is refused when the record has ended, gives another role,
or is already held: one person per appointment. Acceptance is a
transaction with a message, refused if the role would breach the
person's `incompatible_with`. Whoever manages members may unbind the
holder before the record ends, saying why:
`DELETE /api/v1/appointments/{class}/{key}/holder?reason=…`.

**Scopes.** When the acting role is held by appointment, a scope compares
the record against the values of `keys` on the person's current
appointments for that role (all of them, when they hold several),
instead of their organisations' keys. Scope declarations are unchanged:

```json
{ "class": "fleet", "roles": ["designated_driver"], "property": "fleet_number" }
```

A pack whose scoped roles are all held by appointment needs no
`organisations`.

`GET /api/v1/me` lists the person's current `appointments` (class, key,
role, and the values of `keys`), and `GET /api/v1/members` lists each
current holding with the `appointment` that gives it.

## Step-up: acts approved on a wallet

A signed-in session says who is at the keyboard. For the acts that carry
the most weight, a pack can ask for more: that the person approves the act
itself, at the time, on the wallet bound to them, with their fingerprint or
face. `step_up` names those acts:

```json
"step_up": {
  "workflows": ["first_registration", "scrappage"],
  "decisions": ["approve", "reject", "return"],
  "propose": false,
  "grant_roles": ["registrar"],
  "revoke_roles": ["registrar"],
  "erasure": true
}
```

- `workflows` and `decisions`: a reviewer's decisions on these workflows
  (all three when `decisions` is absent). `propose: true` adds proposing
  into them. A decision made under policy is not a person's act and needs
  nothing.
- `grant_roles` and `revoke_roles`: granting these roles, directly or by an
  invitation to them, and removing them, directly or by ending an
  appointment that confers them.
- `erasure`: every erasure of personal data, of a record or of a profile.

**How an act is approved.** The register computes the operation: the act,
the register, the tenant, the acting member and the request it is about to
commit (for a decision, also the task as it stands). It asks the identity
provider to put the operation's hash and a one-line summary in front of
the member's bound wallet, and answers `428` with `error: "step_up_required"`,
`approval_id`, `summary`, `push_sent`, `wallet_link` (to show as a QR code
when no push reached the wallet) and `expires_at`. The page polls
`GET /api/v1/step-up/{approval_id}` (`pending`, `approved`, `declined`,
`expired`) and, once approved, sends the same request again with the header
`Step-Up-Approval: <approval_id>`. The register holds the token the
identity provider issued, checks it names the member's bound wallet and the
operation it is about to commit, and commits. The transaction's envelope
records the `approval` (operation hash, wallet, approval identifier, time),
and the approval is spent: it never admits a second act. A changed request
(another decision, another reason) needs a fresh approval. Acting with no
wallet bound is refused with `412` and `detail: "wallet_not_bound"`.

**Binding wallets.** A member binds wallets as they would register
devices. `POST /api/v1/me/wallets` (optional `{"label": "Work phone"}`) is
approved the same way, by whichever wallet scans the link, and binds the
approving wallet to the caller. A member may bind several, and any of them
approves (the one used last is asked first); a wallet serves one member.
The member lists theirs (`GET /api/v1/me/wallets`: label, `bound_at`,
`last_used_at`) and removes one (`DELETE /api/v1/me/wallets/{wallet}`).
Administrators (`members` permission) list them for everyone or one member
(`GET /api/v1/wallet-bindings?member=…`) and remove one wallet, with a
reason, leaving the member and their other wallets as they are
(`DELETE /api/v1/wallet-bindings/{member}/{wallet}?reason=…`), say for a
lost phone. Each binding and removal is a transaction, and can be written
to the member and to administrators, so a binding nobody expected is
noticed:

```json
"notifications": [
  { "on": "wallet:bound", "to": [{ "member": true }, { "role": "operator" }], "template": "wallet-bound" },
  { "on": "wallet:removed", "to": [{ "member": true }], "template": "wallet-removed" }
]
```

The templates read `.Member` (the member's name), `.WalletLabel`, `.At`
and `.Reason`. `GET /api/v1/me` says `step_up: true` and the caller's
`wallet` (`state`: `none` or `bound`, and `count`).

The identity provider and client are set by the configure call
(`step_up_issuer`, `step_up_client_id`, `step_up_client_secret`); with
development sign-in, a stand-in approves everything at once and binds the
wallet `dev-wallet:<sub>`.

## Notifications

A pack can have the register write to people when a workflow event
happens:

```json
"notifications": [
  { "on": "first_registration:approved", "template": "vehicle-registered",
    "to": [{ "proposer_organisation": true }, { "role": "fleet_manager" }] },
  { "on": "first_registration:returned", "template": "more-information",
    "to": [{ "proposer": true }] }
]
```

| Field | Meaning |
|---|---|
| `on` | `<workflow>:<event>`, the event one of `proposed`, `approved`, `rejected`, `returned`. A proposal approved under policy is `proposed`, then `approved`. A counterparty who declines is `rejected`. |
| `template` | The site's email template `emails/<template>.html`. Its `<title>` is the subject. |
| `to` | Recipient rules, each setting one of: `role` (everyone the register gives that role, by grant, organisation or appointment, whose scope admits the record), `proposer_organisation` (every member of the proposer's organisation), `proposer`. |

Recipients are resolved once the event's transaction has committed,
from what is true then. Each person receives one email, at the address
the register holds for them; a person with none is skipped. Roles an
identity provider asserts at sign-in are not known to the register and
reach nobody. Sending never touches the transaction: each email is tried
three times and failures are logged. When a notice has reached anyone,
the history records `Notified N people: <workflow> <event>, <class> <key>`
as a `notification.sent` transaction, never who or where. A register
without an email sender skips notifications silently.

The template receives `WorkflowTitle`, `Workflow`, `Event`, `ClassTitle`,
`Class`, `Key` (the record's natural key), `TaskID`, `Reason` (the
reviewer's, on a rejection or return), `RecipientName`, `Public` (the
record's public fields, for a class that has any), `RecordURL` (the
page the site's `records` names for the class, on the register's
address, when there is one), and the sender's `BaseURL`, `Office`,
`OrganisationName`, `SupportEmail` and `TestNotice`. Nothing else of the
record reaches an email.

## Saved queries

```json
{
  "name": "vehicles_ever_owned_by",
  "title": "Vehicles ever owned by a party",
  "roles": ["registrar", "auditor", "police", "dpo"],
  "params": [ { "name": "owner_id", "type": "string", "required": true } ],
  "sql": "SELECT v.vin, o.from_date, o.to_date FROM `q_ownership` AS o JOIN `q_vehicle` AS v ON v.object_id = o.vehicle_id WHERE o.owner_id = {{param.owner_id}} ORDER BY o.from_date"
}
```

The register accepts no SQL from callers. It runs the queries a pack
declared, with typed parameters (`string`, `integer`, `number`)
substituted as literals, gated by role. Query tables are named
`q_<class>` and always carry `object_id`, `tenant`, `status` and
`updated_at` alongside the class's projected columns.

## Retention policies

```json
{ "id": "P01", "title": "Owner personal data", "class": "owner",
  "window_days": 3650, "scope": "pii", "erasure": true }
```

`scope` is `pii` (only versions carrying encrypted personal data) or
`all`. `erasure` permits data-subject erasure under this policy, which
also requires the class to use a subject-scoped key: erasing a person
whose key is shared with others would erase the others.

A prune removes the content of superseded versions past the horizon. It
never touches a live record's current version — retention removes
history, not the present. Ending a record is a status change, which is
a different act with a different name.

## Seed

Optional demonstration content, written once on a fresh register as
ordinary transactions with an ordinary author, so the log says plainly
where it came from. A payload value of `"@name"` resolves to the
identifier of an earlier seed object declared with `"ref": "name"`.
