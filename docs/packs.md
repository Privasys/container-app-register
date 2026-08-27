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
| `column` | Override the projected column name. |
| `reference` | The class this property points at. The core enforces the referential rule the SQL layer has no foreign keys for, including against records created earlier in the same write set. |

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
