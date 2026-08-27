# The vehicle register

The generic core is only proved when a real register runs on it. This
is the one that does: a country's register of vehicles, owners, plates,
ownership links and liens, shipped as
[`packs/car-register/pack.json`](../packs/car-register/pack.json) and
driven end to end by
[`internal/register/register_test.go`](../internal/register/register_test.go).

Nothing about it is special-cased in the core. Anything below that the
core could not express cleanly would be a defect in the core, not in
the pack.

## What it holds

| Class | Natural key | Statuses | Personal data |
| --- | --- | --- | --- |
| `vehicle` | `vin` | registered, stolen, exported, scrapped | none |
| `owner` | `reference` | active, closed | name, address, email, telephone, date of birth — under a **per-subject** key |
| `plate` | `number` | issued, retired | none |
| `ownership` | — | open, closed | none |
| `lien` | — | open, discharged | none |

The owner's party reference is deliberately not the person's name: it
identifies a file rather than a person, which is what an index may hold
in the clear. Ownership history is the ledger's history — a transfer
never edits the previous owner away, it closes one link and opens
another.

## Who may do what

| Role | |
| --- | --- |
| `registrar` | Approves, corrects, reads everything, sees personal data. Cannot also be a clerk. |
| `clerk` | Proposes only. Cannot also be a registrar. |
| `police` | Reads, and runs the stolen-vehicle flag from proposal to decision. |
| `insurer` | A purpose-scoped read credential: vehicles, plates and liens. No owners, no personal data, no transaction log. |
| `auditor` | Reads everything structural, the log, proofs and checkpoints. **Not** cleared for personal data. |
| `dpo` | Retention and erasure, and the reads needed to run them. |
| `citizen` | Proposes a transfer of their own vehicle; accepts one as the buyer. |
| `operator` | Runs the service: export, standby, checkpoints, retention. |

Registrar and clerk are declared incompatible. A caller who somehow
holds both identity-provider roles is refused outright rather than
acting under the stronger one.

## The procedures

**First registration.** A clerk or registrar submits the vehicle with
the digest of a certificate of conformity; the registrar reviews and
approves. The approval writes the vehicle and issues the plate in the
same write set. Two conditions refuse the proposal outright: a VIN
already registered, and a plate already in use. Independence applies —
a registrar who proposed cannot also decide, and the test proves a
second registrar can.

**Ownership transfer.** The seller proposes, naming the buyer. The
proposal waits for the buyer, and only the buyer: another party's
acceptance is refused whatever roles they hold. Once accepted, the
transfer settles **under policy** if the vehicle is registered and no
lien is open, and the log records the approval as authored by `policy`
rather than pretending a person took it. An open lien routes the same
proposal to a registrar instead, with the lien named in the proposal's
blocker list. The approval closes the open ownership link with a
to-date and opens a new one.

**Correction.** A wrong colour was recorded. The corrected record is
proposed with supporting evidence and approved; the committed
transaction carries `corrects:` pointing at the record, and both
versions survive with the change visible in the diff.

**Scrappage and export.** A status change with evidence. The plate is
retired, the ownership link is closed, and the vehicle's record stays
provable for ever: the test fetches a proof of version 1 after the
vehicle has been scrapped.

**Stolen.** The police propose and the flag settles under policy. No
registrar is in the path, which is the point: the procedure is
different because the urgency is.

**Erasure.** A former owner asks for erasure after the retention
period. The data protection officer runs it under policy P01, which is
the only policy that permits erasure, and only because the owner class
uses a per-subject key. The owner's personal fields become unreadable;
the party reference, the ownership links and the vehicles' technical
history remain, and the ledger entry is byte-for-byte what it was, so
everything that ever proved still proves. A registrar cannot run an
erasure, and a second erasure of the same subject is refused rather
than quietly repeated.

## The questions it answers

Saved queries, each gated by role:

| Query | |
| --- | --- |
| `vehicles_by_status` | Counts by state. |
| `transfers_since` | Ownership links opened since a date, joined to the vehicle. |
| `vehicles_by_make_and_year` | Filter and sort over projected columns. |
| `vehicles_ever_owned_by` | The history walk: every vehicle a party has held, open and closed links alike. |
| `open_liens` | Undischarged security interests, joined to the vehicle. |
| `stolen_vehicles` | Currently flagged. |

And the two that are the point of the whole exercise:

```bash
# court-grade lookup: the plate, and the proof it is what the register says
curl -H "$AUTH" .../api/v1/proofs/natural-keys/vehicle/WVWZZZ1JZXW000001

# and the other direction
curl -H "$AUTH" .../api/v1/proofs/natural-keys/vehicle/WVWZZZ1JZXW999999
# → present: false, with an absence proof.
#   "This vehicle was never registered here" is a statement, not a silence.
```

Both verify offline with `register-verify`, and in the browser in the
explorer's proof view.

## What it validated in the core

Everything in Part A of the design, and two things that changed because
of it. Building the plate-issuing effect showed that a reference must
resolve against records created earlier in the *same* write set, not
only against the store; and building the transfer showed that a link
needs to close with both a field change and a status change in one act,
which is why `close_link` carries a status.

## Retention

| Policy | Class | Window | Scope | Erasure |
| --- | --- | --- | --- | --- |
| P01 | owner | 3650 days | personal data | yes |
| P02 | vehicle | 3650 days | all | no |
| P03 | ownership | 3650 days | all | no |

A prune under P02 removes the content of superseded vehicle versions
past the horizon and leaves the current one alone: retention removes
history, not the present. A read of a pruned version answers "pruned
per policy P02", which is a different statement from "no such version",
and the register can still prove the version existed.
