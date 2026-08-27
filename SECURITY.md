# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately to
**security@privasys.org**. Do not open public issues for security
reports. We aim to acknowledge reports within 48 hours and to keep you
informed of progress; coordinated disclosure timelines are agreed per
report.

Please include what you can: affected commit or image digest, the
schema pack in use, whether the commitment key was delivered or
derived, the acting role of the caller, reproduction steps, and an
impact assessment.

## Scope

The register makes a small number of claims. A way to break any of
them is what we most want to hear about.

- **Every change carries a reason.** A path that commits state without
  a validated envelope, or with an author or acting role the caller
  does not hold.
- **Nothing can be covertly altered or deleted.** A path that changes
  or removes register state without a signed, logged transaction, or
  that makes a pruned or erased record indistinguishable from one that
  never existed.
- **Evidence means what it says.** An inclusion or absence proof that
  is accepted for a statement false at that root; an evidence bundle
  that verifies after being edited; a checkpoint accepted from a key
  that did not sign it; two checkpoints for the same version with
  different roots.
- **Roles are enforced.** Reading a class, proposing, deciding,
  pruning, erasing or enrolling keys without the permission for it;
  approving one's own proposal where the workflow declares
  independence; holding two roles the pack declares incompatible.
- **Personal data stays behind its key.** Personal fields readable by a
  role without clearance, appearing in a query projection, surviving an
  erasure, or leaking through a diff, a log line, an error message or a
  saved query.
- **Statement construction.** Any input that reaches SQL other than
  through the literal encoder, including through a pack's saved
  queries, workflow conditions or filter parameters.
- **The configure gate.** Reaching a state-changing path before the
  register has been configured, or configuring it without the platform
  authorisation the gate requires.

Also in scope: the SQL layer serving row content from the derived index
keyspace rather than through the ledger, and any divergence between the
leaf position the register computes and the one the ledger commits to.

Out of scope: denial of service through resource exhaustion, and the
documented restart-replay residual of the storage engine (replaying a
complete old store together with its matching internal checkpoint),
which is what the customer-held root checkpoints exist to close.

## What this project does not claim

The register is not certified. It has not been independently audited.
The confidentiality of data at rest is the confidential VM's encrypted
volume, not this application; the guarantees here are about integrity,
attribution, and the evidence a reader can check for themselves.

## Supported versions

The `main` branch and the most recent tagged release.
