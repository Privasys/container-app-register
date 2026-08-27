# Contributing

Thank you for your interest in the Privasys register.

## Layout

This is a single Go module with two commands and a set of internal
packages, plus the schema packs that turn the generic core into a
particular register.

| Path | Purpose |
| --- | --- |
| [`cmd/register`](cmd/register) | The service: HTTP surface, configure gate, checkpoint scheduler, standby follower. |
| [`cmd/register-verify`](cmd/register-verify) | The customer-side verifier. Checks evidence bundles and checkpoint chains offline, with no access to the register. |
| [`internal/register`](internal/register) | The core: transactions, records, the workflow primitive, retention and erasure, checkpoints, reads and proofs. |
| [`internal/store`](internal/store) | The binding to [immutable-ledger](https://github.com/Privasys/immutable-ledger): the authenticated store, the SQL layer over it, and the statement builder. |
| [`internal/pack`](internal/pack) | Loads and validates a register pack: classes, workflows, roles, queries, retention. |
| [`internal/jsonschema`](internal/jsonschema) | The JSON Schema subset record schemas are validated against. |
| [`internal/byok`](internal/byok) | Payload encryption and the customer-held key hierarchy. |
| [`internal/checkpoint`](internal/checkpoint) | Signing and offline verification, shared by the service and the verifier. |
| [`internal/api`](internal/api) | REST surface, tool endpoints, and the operator explorer. |
| [`packs/`](packs) | Schema packs. `car-register` is the national vehicle register the core is proved against. |
| [`tools/`](tools) | `browser-verify.mjs`, which runs the explorer's in-page verifier outside a browser so it cannot silently drift from the Go one. |
| [`e2e/`](e2e) | Playwright tests that drive the explorer in real browsers against a real register. |

## Building and testing

```bash
git clone https://github.com/Privasys/container-app-register.git
cd container-app-register
go vet ./...
go test ./...
go test -race ./...
gofmt -l .
```

CI runs exactly these, then builds the image and drives it end to end:
it configures a register, fetches a proof of presence and a proof of
absence, verifies both with the shipped verifier, and confirms that an
edited bundle stops verifying.

The operator explorer has its own suite, in real browsers against a
real register:

```bash
cd e2e
npm ci
npx playwright install --with-deps chromium firefox
npm test                 # both browsers
npm run test:headed      # watch it happen
```

It builds the binary, starts it on a fresh volume with the car-register
pack, and drives the console. Most of it is about the proof view, and
most of *that* is negative: the tests intercept the evidence on its way
to the page and edit it — flip the answer, substitute the root, rewrite
the row, forge the signature, detach the anchor, truncate the proof —
and require the page to notice each time. A passing tamper test would
mean the page is trusting the server, and the verification is theatre.

To run one locally:

```bash
PORT=8080 REGISTER_DATA_DIR=./.data REGISTER_DEV_AUTH=1 \
REGISTER_SELF_CONFIGURE=1 REGISTER_PACK=packs/car-register/pack.json \
go run ./cmd/register
```

Then open `http://localhost:8080/explorer/` and connect with the
development token `dev:you:You:register:registrar`. Development
authentication accepts tokens of the form
`dev:<subject>:<display name>:<identity-provider roles>`; the register
refuses to enable it when the platform's callback credentials are
present.

## Invariants

Three properties are contracts. Tests enforce them, and a change that
breaks one is a bug or a deliberate, documented format change.

- **No state change without a transaction.** Every write goes through
  the core's commit path: a validated envelope, a write set, the
  transaction recorded before its effects, then marked applied. The
  only exception is catalogue structure at bootstrap, which the schema
  transaction that follows fingerprints.
- **Write sets replay to the same rows.** Recovery after a crash is a
  replay, not a repair. Every write-set entry is an upsert or a delete
  keyed by primary key, and every value in one survives a JSON round
  trip unchanged, byte columns included.
- **Nothing reaches SQL except through the builder.** Values go through
  `store.Lit`, identifiers through `store.Ident`. There is no other
  route, including for pack-declared queries and workflow conditions.

## Writing a pack

A pack is data, not code, and it is committed to the ledger. Add or
change one and the register registers a new schema version on next
start, keeping the old one so records validated under it still point at
the rules they were validated under.

Two rules the loader enforces, worth knowing before you write one:
a property marked as personal data cannot also be queryable, because a
query projection is plaintext; and a natural key cannot be personal
data, because it is an index term.

## Changes we welcome

Bug reports and fixes, schema packs for other domains, workflow gate
types, explorer improvements, documentation, and anything that
tightens the evidence a reader can check without trusting the
register. For larger changes, please open an issue describing the
design first.

## Style

British English in prose and in user-facing strings. Error messages are
written for the person who has to act on them: say what was refused and
why, not which function returned an error.

## Licence

By contributing you agree that your contributions are licensed under
the [AGPL-3.0](LICENSE).
