# Operating a register

## Deploying

The image is deployed like any other Privasys container app, pinned by
digest. The platform's configure-then-freeze gate holds every path
except the health probe and `/configure` at HTTP 503 until the deployer
configures it, and re-arms on every restart.

```bash
privasys apps deploy <app> --image ghcr.io/privasys/container-app-register@sha256:…
```

Then configure it. Only an owner or admin of the app can: the gate
authorises the caller before it lets the call through.

```json
{
  "tenant": "gov",
  "pack_ref": "car-register",
  "commitment_key": "<64 hex characters, optional>",
  "checkpoint_interval": "24h",
  "customer_kek": { "id": "ministry-2026", "algo": "x25519", "public_key": "<base64>" }
}
```

A pack can also be delivered inline as `pack`, which is how a register
for a domain other than the one baked into the image is brought up
without rebuilding.

### The commitment key

Delivering it makes the key that binds the whole state something that
arrives over an attested channel and lives only in memory. The register
publishes SHA-256 of it at OID `1.3.6.1.4.1.65230.3.5.1`, so a
verifying client confirms the register was given the key it expects
without the key leaving the enclave. The cost is that the register
cannot start unattended: the gate re-arms on restart, so the key must
be re-delivered each time.

Omitting it has the register derive one from the master secret on its
sealed volume, which starts unattended and is the right answer for a
single-custodian deployment. `/api/v1/status` reports which of the two
is in force as `commitment_key_source`, so nobody has to guess.

Either way the register writes a check value on first start and
enforces it thereafter. A restart with the wrong key says the key is
wrong; it does not open the store and report corruption.

## Day one

```bash
AUTH="Authorization: Bearer $TOKEN"

# Keep the verification key. Everything later is checked against it.
curl -H "$AUTH" https://<register>/api/v1/checkpoints/key > register.key

# Enrol your own key-encryption key, before any personal data is written.
curl -H "$AUTH" -X POST https://<register>/api/v1/keys \
  -d '{"id":"ministry-2026","algo":"x25519","public_key":"<base64>"}'

# Subscribe to committed transactions and issued checkpoints.
curl -H "$AUTH" -X POST https://<register>/api/v1/webhooks \
  -d '{"id":"ministry","url":"https://…","events":["checkpoint.issued"]}'
```

Enrol the key first. A key enrolled later does not retroactively wrap
data-encryption keys that already exist, and the register says so
rather than implying otherwise.

The webhook's signing secret is returned once, at creation. Deliveries
carry `X-Register-Signature: sha256=<hmac>` over the body.

## Checkpoints

A checkpoint is `(ledger version, root)` plus a summary and a link to
the checkpoint before it, signed by a key on the sealed volume and
stamped with the measurement of the build that signed it. They are
issued at bootstrap, on the configured cadence when something has
changed, on demand, and whenever someone asks for evidence about a
state that does not have one yet.

They are only worth anything held **outside** the register. Pull them
and keep them:

```bash
curl -H "$AUTH" https://<register>/api/v1/checkpoints?limit=500 > checkpoints.json
register-verify chain checkpoints.json --key register.key
```

`chain` checks every signature, and that no version is claimed with two
different roots. That second check is what catches a fork: a register
that served two histories has to have signed both.

A quiet register issues no checkpoint. One that repeats the previous
one is not more evidence.

The chain lives beside the ledger rather than inside it, which is what
lets a checkpoint attest exactly the state that was current when it was
taken. A standby's ledger export therefore carries the primary's latest
checkpoint but not the whole chain: keep the chain where you keep your
backups, which is where it does its job anyway.

## Backup and standby

The backup unit is a ledger export rather than a volume snapshot: it is
engine-portable, restores verifiably entry by entry, and produces a
store whose root is the root it came from.

```bash
curl -H "$AUTH" "https://<register>/api/v1/export?limit=500" > page-0.json
# follow `next` until `done` is true
```

A warm standby does the same continuously:

```
REGISTER_MODE=standby
REGISTER_PRIMARY_URL=https://<primary>
REGISTER_STANDBY_TOKEN=<a token with the admin permission>
REGISTER_STANDBY_ROLE=operator
REGISTER_COMMITMENT_KEY=<the primary's key>
```

`GET /api/v1/standby` reports the position: the primary's version and
root, the standby's own, the sync duration, and whether the two roots
agree. They must, and a mismatch is reported rather than smoothed over.
Both registers need the same commitment key, or their roots are not
comparable at all.

### Restoring

Bring a register up with the same commitment key and an empty volume,
replay the export pages through the standby path, and compare the
resulting root with a checkpoint you hold. Restoring without that
comparison restores a store; restoring with it restores a store you can
show is the right one.

## Retention

```bash
# What is eligible, per policy, right now.
curl -H "$AUTH" https://<register>/api/v1/retention

# Always dry-run first.
curl -H "$AUTH" -X POST https://<register>/api/v1/retention/prune \
  -d '{"policy_id":"P02","dry_run":true}'

curl -H "$AUTH" -X POST https://<register>/api/v1/retention/prune \
  -d '{"policy_id":"P02","message":"Quarterly retention run","collect_history":true}'
```

`collect_history` also collects the ledger's own superseded versions
below the horizon, so pruned content stops being reachable through a
historical read as well as through the current state. Without it the
content is removed from the present but the ledger still holds the
older versions.

A prune never touches a live record's current version. Ending a record
is a status change: a different act, with a different name.

### Erasure

```bash
curl -H "$AUTH" -X POST https://<register>/api/v1/retention/erase \
  -d '{"object_id":"owner-…","policy_id":"P01",
       "reason":"Request received 2026-08-01; retention period expired."}'
```

Erasure destroys the subject's data-encryption key, both wraps. It
requires a policy that permits it and a class with a per-subject key —
erasing a person whose key is shared with others would erase the
others, and the register refuses rather than doing it.

Publish the figure your backup rotation implies. Live storage is
covered the moment the key is destroyed; a backup taken before the
request holds ciphertext whose key no longer exists anywhere, which is
the same practical outcome, and saying which of the two you mean is
part of being able to answer the question.

## Monitoring

`GET /api/v1/status` is the one call that answers "is this register
healthy and is its evidence current":

| Field | Watch for |
| --- | --- |
| `pending_transactions` | Should be 0. A persistent non-zero means replay is failing. |
| `last_checkpoint` | Older than the configured cadence, on a register that is committing, means checkpoint issuance is failing. |
| `ledger_version`, `root` | Should advance with activity, never go backwards. |
| `commitment_key_source` | Should be what you configured. |
| `pending_tasks` | Proposals nobody has decided. |

Logs are structured JSON on standard output, one line per request,
without bodies: a register's request bodies are the register's data.

## Upgrading

An upgrade changes the measurement, so the app owner approves the new
one before the sealed volume's key is released to it. Until that
approval the new build cannot read the data — which is the guarantee
working, not a fault. The register's own key material lives on that
volume, so its checkpoint signing key survives the upgrade and the
checkpoint chain continues across it. Each checkpoint records the
measurement that signed it, so the chain shows where the build changed.

If a pack changes which properties are queryable, the first start after
the upgrade drops and rebuilds those query tables from the record
versions they derive from, and registers a new schema version. Record
data is not touched.
