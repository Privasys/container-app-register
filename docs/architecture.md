# Architecture

## Where the data lives

Almost everything the register persists is a ledger entry: rows, the
catalogue, the transaction log, the schemas, the policies and the
wrapped keys alike. They sit under one versioned sparse Merkle tree
from
[immutable-ledger](https://github.com/Privasys/immutable-ledger), so a
single 32-byte root attests the whole database and any entry can be
returned with a proof that verifies against that root by a pure
function.

```
                    ┌──────────────────────────────────────┐
   RA-TLS  ────────▶│  register (this app)                 │
   (Caddy)          │                                      │
                    │  api ─── register core ─── pack      │
                    │            │        │                │
                    │            │        └── byok, keys   │
                    │            ▼                         │
                    │       store ── sqlledger ──┐         │
                    │            └── ledger ─────┤         │
                    └────────────────────────────┼─────────┘
                                                 ▼
                                     Pebble on /data
                                (LUKS + dm-integrity, key
                                 released to an approved
                                 measurement at boot)
```

The SQL engine is embedded in-process with no network listener. That is
a deliberate boundary: the register is the only thing in front of its
data, and a wire protocol would move the policy boundary to whoever
holds a database credential.

Confidentiality at rest is the confidential VM's encrypted volume. The
ledger therefore runs in its default one-key mode; a second
application-level key on top of an attested LUKS volume buys little,
and the engine's optional `WithStorageKey` stays available for
defence-in-depth deployments that want it. Roots and proofs are
identical either way.

## Keyspace

The SQL layer owns the whole keyspace. Base tables:

| Table | |
| --- | --- |
| `transactions` | The log. Envelope, write set, state, roots and versions before and after. |
| `tx_refs` | Typed links out of a transaction. |
| `objects` | One row per record: class, natural key, head version, status. |
| `natural_keys` | `(tenant, class, natural key) → record`. Its own key, so absence is provable. |
| `record_versions` | Every immutable version: payload hash, payload, encryption scope, prune state. |
| `schemas`, `policies` | The pack's rules, versioned. |
| `tasks` | Workflow proposals in flight. |
| `keks`, `dek_keys` | Enrolled customer keys, and per-scope data-encryption keys under both wraps. |
| `prune_marks` | What retention and erasure removed, and under which policy. |
| `webhooks`, `webhook_deliveries` | Subscribers and terminal delivery outcomes. |
| `registry` | Small internal markers: projection fingerprints, seed markers. |
| `q_<class>` | Per-class query projection, derived from the clear half of the head version. |

The one thing beside the ledger rather than inside it is the checkpoint
chain, which lives in its own backend keyspace.

### Why checkpoints are not rows

Storing each checkpoint as a row would let the root attest the chain,
which sounds better and cannot work. A checkpoint states the root at a
version; writing it advances the version past the one it states. Every
checkpoint would attest a state the register had already left, and no
evidence read afterwards could ever be anchored exactly — the anchor
would always be a version or two behind, and a verifier would have to
accept "close enough", which is not what evidence is for.

So the chain carries its own integrity instead. Each checkpoint names
the version and root of the one before it, and all of them are signed.
Issuing one moves no version, so a checkpoint always attests exactly
the state that was current when it was taken, and an evidence bundle
read immediately afterwards anchors to it exactly. What the tree would
have added — that the register committed to the chain — the signatures
already provide, and better: a register that served two histories has
to have signed both, which is what `register-verify chain` looks for.

## The commit path

```go
commit(envelope, writeSet):
    validate(envelope)                 // refuses a messageless change
    txid = SHA-256(canonical(envelope, writeSet))
    if already committed: return it    // a retry is not a second change
    BEGIN
      record transaction (root before, version_before + 1)
      apply(writeSet)                  // upserts and deletes, by primary key
    COMMIT                             // one ledger version, one chain link
    assert the store moved by exactly one
```

Three properties fall out of that order.

**The reason precedes the effect.** The ledger never contains a change
whose envelope it does not already contain. An interrupted action is
visible as a pending transaction carrying its own write set, which is
enough to finish it.

**There is nothing to recover.** The action is one atomic commit, so a
crash either committed all of it or none of it. Write-set entries are
still upserts and deletes keyed by primary key, and startup still drains
any transaction an older build left pending, but on this build that
drain finds nothing. The write set survives its JSON round trip byte for
byte, which is why byte columns are tagged rather than left as bare
base64 strings.

**Identity is content, not sequence.** The transaction id is the hash
of the envelope and the effects together, so a retried request is
recognised as the same transaction, and two changes with identical
effects but different reasons are different transactions. The id is
substituted into the write set through a placeholder, because a write
set that contained the literal id would be defining it in terms of
itself.

### Why there is no "root after"

A row cannot carry the root of the commit that writes it: whatever value
it holds becomes part of the bytes that root is computed over. This is
the same circularity that keeps checkpoints out of the tree, and no
amount of transaction support removes it.

So a transaction records where it started, and nothing about where it
ended except the version — which is predictable, because an action is
one commit. The root at that version lives in the lineage chain, where
it can actually be verified. A field that looks verifiable and is not is
worse than no field.

### The one thing outside the log

Creating the catalogue is structure rather than state: base tables at
bootstrap, and a per-class query table whenever a pack changes which
properties are queryable. Those statements advance the root without a
transaction of their own. The schema transaction that follows records a
fingerprint of the structure it produced, so the step is visible in the
log even though it is not a transaction.

Everything else that once moved the root quietly is now a transaction of
its own: the marker that a pack's seed ran, the fingerprint of a query
table, the registration of a subscriber. Webhook *delivery* outcomes
went the other way and left the ledger entirely — whether somebody
else's endpoint answered is not a fact about this register, and
nondeterministic data has no business in an attested tree.

## Reads

`GET /api/v1/records` joins `objects` with the class's query table.
Rows come back through the ledger, which re-reads and re-verifies each
one rather than serving content from the derived index keyspace; the
index decides *which* rows, never *what* they say.

A record version is materialised through three filters, in this order:
pruned (the content was lawfully removed, and the read says so),
erased (the key was destroyed), and redacted (the caller's roles do not
clear them for personal data). A diff between versions compares
redacted fields as absent rather than as values, so a timeline never
leaks what a reader is not cleared to see.

## Lineage

Every commit extends a hash chain over the root sequence, and the chain
head is written as a reserved leaf, so the live root commits to the head
and the head commits to every root before it. Rewriting history between
two anchors and still arriving at the anchored head is a preimage
attack.

The chain is a create-time choice in the ledger and cannot be added
later, so a register created before it existed opens without one and
says so at  rather than refusing to start.

What makes it useful to a third party is that the link function is pure
and its inputs are not secret. An auditor given two signed anchors and
the roots between them folds one into the other themselves, with no
commitment key and no trust in the register. See
[auditing.md](auditing.md).

This is also what makes erasure finish. Superseded and erased content
lives in prunable history until an audit vouches for the period and
collects it; verification has to come first, because pruning destroys
the root records the check walks. The audit cadence is therefore the
erasure latency.

## Evidence

An evidence bundle is a row, its inclusion or absence proof, the root
and version it was read at, the signed checkpoint anchoring that state,
and the register's signature over all of it.

Verification has four steps, three of which need nothing from the
register:

1. **The proof folds to the claimed root.** Arithmetic over hashes. The
   browser and the verifier both do it.
2. **The signature covers the bundle.** Ed25519 under a key whose
   public half the customer fetched once. An edited bundle stops
   verifying.
3. **The root is one the register committed to publicly.** Compare
   against a checkpoint the customer already held.
4. **The register asserts the key-to-position mapping.** The mapping
   from a ledger key to its leaf position is under the commitment key,
   which stays in the enclave; the signature in step 2 is what makes
   that assertion attributable to a measured build.

Step 3 is exact rather than approximate because the register anchors
before it reads: producing evidence issues a checkpoint for the current
state if there is not one already, which costs nothing when the state
has not moved. The number of checkpoints therefore follows the rate of
change, not the rate of requests, and every state anyone has been given
evidence about is a state the register publicly committed to.

`register-verify chain` adds the check that catches a fork: two
checkpoints claiming different roots for the same version cannot both
be honest, and both carry the register's signature.

## Personal data

Personal fields are split out of the payload before it is written and
sealed under a data-encryption key whose scope the class declares. The
stored payload is `{clear, enc}`; the row also carries the SHA-256 of
the **whole plaintext** payload. That is what makes erasure clean: the
commitment is to the hash and the ciphertext, so destroying the key
changes neither the entry nor anything that ever proved against it.

The same boundary covers the proposal that carried the data in. A
workflow submission is split and sealed exactly as a record is, under a
key of its own, and that key is destroyed the moment the proposal is
decided: from then on the record is the truth, and a second readable
copy would sit outside the erasure that covers it. The payload
commitment is keyed too — an unkeyed digest of a name, an address and a
date of birth is searchable, so one kept past an erasure would preserve
the personal data in a form that only looks safe.

Each data-encryption key is kept under two wraps: an operational wrap
under a key derived from the sealed master secret, which is what the
running service uses, and a recovery wrap under the customer's enrolled
key-encryption key, which only the customer can open. An erasure
destroys both, because leaving either would make the erasure a promise
rather than a fact.

A key enrolled today does not retroactively wrap keys that already
exist. Saying so is more useful than a silent partial guarantee.

## Roles

A bearer token is verified offline against the identity provider's
published key set, so authorising a request never means sending the
request anywhere. The token's `roles` claim is mapped onto the pack's
roles; a caller holding two roles the pack declares incompatible is
refused rather than quietly acting under the stronger one.

The acting role is chosen per request with `X-Register-Role` and is
recorded in the commit envelope, because "who did this" and "in what
capacity" are different questions and a register has to answer both.

## Resilience

Backup and standby both use ledger-level export: leaves are `(path,
value)` pairs, paths are keyed hashes, so an export carries no logical
keys and needs none. A restored tree is keyed by path exactly as the
original was and produces the same root for the same logical data. A
standby that has finished a pull compares roots with the primary and
reports a mismatch rather than papering over it.

Two registers can only compare roots if they share a commitment key, so
a standby is configured with the same key as its primary, from the same
place.
