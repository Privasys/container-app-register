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
    record transaction (state=pending, roots before)
    apply(writeSet)                    // upserts and deletes, by primary key
    record transaction (state=applied, roots after)
```

Three properties fall out of that order.

**The reason precedes the effect.** The ledger never contains a change
whose envelope it does not already contain. An interrupted action is
visible as a pending transaction carrying its own write set, which is
enough to finish it.

**Recovery is a replay.** Every write-set entry is an upsert or a
delete keyed by primary key, so applying one twice lands on the same
rows. Startup drains pending transactions before anything else runs.
The one thing this needs is that a write set survives its JSON round
trip byte for byte, which is why byte columns are tagged rather than
left as bare base64 strings.

**Identity is content, not sequence.** The transaction id is the hash
of the envelope and the effects together, so a retried request is
recognised as the same transaction, and two changes with identical
effects but different reasons are different transactions. The id is
substituted into the write set through a placeholder, because a write
set that contained the literal id would be defining it in terms of
itself.

### Why an action is several commits

The SQL layer is autocommit-only: each statement is one atomic ledger
commit. A governance action therefore lands as a short ordered sequence
— the transaction row, its effects, the mark that it was applied —
rather than as a single commit, and the ledger version moves several
times per action. `version_after` on a transaction is the version at
which its write set is fully applied; the row recording that fact is
itself committed one version later.

This is the honest description of what the code does. A single-commit
form would need a batching API in the SQL layer, which does not exist
yet, and the write-ahead order is what makes the sequence safe in the
meantime.

### The one thing outside the log

Creating the catalogue is structure rather than state: base tables at
bootstrap, and a per-class query table whenever a pack changes which
properties are queryable. Those statements advance the root without a
transaction of their own. The schema transaction that follows records a
fingerprint of the structure it produced, so the step is visible in the
log even though it is not a transaction.

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
