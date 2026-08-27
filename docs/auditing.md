# Auditing a register

An auditor's job is to be convinced without having to trust. Proofs
answer questions you think to ask; they do not tell you whether you have
been shown everything, and they say nothing about how the state got
here. This is what closes both gaps.

## What the auditor holds

One thing, kept outside the register: **signed checkpoints**, collected
as they are issued. Fetch the verification key once and keep it too.

```bash
curl -H "$AUTH" https://<register>/api/v1/checkpoints/key > register.key
curl -H "$AUTH" "https://<register>/api/v1/checkpoints?limit=500" > checkpoints.json
```

A checkpoint carries the version, the root, and the **lineage head** —
a hash chain over every root before it:

```
head_v = SHA-256("immutable-ledger:history:v1" ‖ head_{v-1} ‖ root_{v-1} ‖ v)
```

The head is stored as an ordinary leaf, so the live root commits to it,
and it commits to the whole sequence behind it. That is what makes a
checkpoint an audit anchor rather than a snapshot.

Holding only the latest checkpoint proves nothing about what came
before. Collect them.

## The four checks

### 1. Is this fact true, and in a state you already knew about?

```bash
curl -H "$AUTH" ".../api/v1/proofs/natural-keys/vehicle/$VIN" > evidence.json
register-verify bundle evidence.json --key register.key --checkpoint mine.json
```

Recomputes the Merkle root from the proof, checks the register's
signature over the bundle, and checks the state it was read at against a
checkpoint you already held. Needs no key material beyond the public
one, and no access to the register.

### 2. Did the register ever serve two histories?

```bash
register-verify chain checkpoints.json --key register.key
```

Every checkpoint signed, versions monotone, and no version claimed with
two different roots. A register that forked has to have signed both
branches.

### 3. Is the history between two anchors the one they commit to?

This is the check that needs no key at all, and the one that catches a
rewrite *between* two honestly signed anchors.

```bash
curl -H "$AUTH" ".../api/v1/audit/roots?from=$A&to=$B" > roots.json
# combine the two anchors and the roots into one document
register-verify lineage lineage.json --key register.key
```

The verifier folds the recorded roots through the link function and
confirms the result is the head the later anchor commits to. Roots and
heads are not secret — they are hashes of state, not state — and the
link function is pure. Only the two signatures come from the register.

A register that altered anything between the anchors cannot produce a
root sequence leading from the first head to the second; doing so is a
preimage attack. Substituting a root, dropping a version and reordering
the sequence all fail, and there are tests for each.

### 4. Is the head the register quotes really the one in the tree?

```bash
curl -H "$AUTH" .../api/v1/audit/lineage
```

Returns the head with the inclusion proof for the reserved chain-head
leaf, so the head is bound to the live root rather than asserted.

## Reviewing what changed

```bash
curl -H "$AUTH" .../api/v1/audit/changes/$VERSION
```

Leaf-level differences for one commit: the tree position, whether it was
a put or a delete, and the size and digest of the value. Positions are
keyed hashes, so logical keys are not recoverable from them, and values
are summarised rather than served — a ledger value is a row, and rows
carry personal data. Two independent copies of a register can be
compared on digests alone.

Raw values are available at `?values=true` to a caller holding both the
administrative permission and clearance for personal data. Content
normally comes from the record and proof surfaces instead, which are
role-aware and redact.

## Closing an audit

An audit period ends by verifying the lineage from the previous anchor,
signing a new one, and then — and only then — collecting the history the
new signature now vouches for.

```bash
curl -H "$AUTH" -X POST .../api/v1/audit/close -d '{
  "from_version": 146,
  "from_head": "2d9090079238fbcd…",
  "collect": true,
  "message": "Quarterly audit"
}'
```

```json
{ "verified": true, "from_version": 146, "to_version": 157,
  "collected": true, "records_removed": 1231 }
```

The order is not negotiable. Verification walks the stored root records,
so pruning first would destroy the evidence the check needs; a register
that collected before verifying could never prove the history it was
about to discard. A failed verification leaves everything intact.

Closing an audit is itself a transaction (`audit.close`), so the log
says who closed which period and what the anchor was.

Requires both the checkpoint permission and the retention one, because
the act both attests and destroys. In the vehicle-register pack that is
the operator: the auditor reads everything but collects nothing, and the
data protection officer runs erasures but signs no anchors.

## Erasure latency

This is the part worth writing into a data-protection policy.

Between audits, superseded and erased content remains in the ledger's
prunable history. It is unreadable where a key was destroyed, but the
records themselves are still there. Collection at the next audit is what
physically removes them.

**So the audit cadence is the erasure latency.** Data deleted just after
an audit persists until the next one; a missed audit extends the window,
and storage carries the full inter-audit history in the meantime. Pick a
cadence you are willing to state, and state it.

## What none of this proves

- **That the pre-audit history was what anyone says it was.** Once
  collected, it is gone; the signed anchor stands in for it. Trust rolls
  forward from audit to audit, which is exactly the trade being made for
  erasure to be real.
- **That you have been shown every record.** Proofs are per-key. Total
  state verification means rebuilding the tree from a leaf export, and
  that needs the commitment key — so it is an operation for the key
  holder, not an arbitrary third party. Handing out the commitment key
  would also let its holder test guesses against every leaf, which is
  the same reason a hash of personal data is not anonymous.
- **That the register is running the code you think.** That is the
  RA-TLS handshake's job, not this file's: the certificate carries a
  hardware quote over the build's measurement, and each checkpoint
  records the measurement that signed it.
