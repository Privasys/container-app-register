# Screenshots

Generated, not drawn. `npm run screenshots` in [`e2e/`](../../e2e)
builds the register, starts it on a fresh volume with the car-register
pack, puts real work through the workflows — a first registration, a
correction, a lien — and photographs the result through the same API
everything else uses. Re-run it after a change to the explorer rather
than editing these by hand.

| File | |
| --- | --- |
| `history.png` | The transaction log. Seed, proposal, approval, correction, lien, each with its author and the role they acted under. |
| `transaction.png` | One transaction in full: the reason, the roots either side, the typed references, the write set. |
| `record.png` | A vehicle with its timeline, and the diff a correction produced. |
| `redaction.png` | The same register seen by an auditor, who is cleared to read owners but not their personal data. |
| `proof.png` | An evidence bundle verified in the page: proof, signature, anchor. |
| `proof-absence.png` | The other answer, with a proof: this key is not registered here. |
| `proof-tampered.png` | The same bundle after a byte was changed on its way to the page. |
| `checkpoints.png` | The chain, and the key to verify it with. |
| `retention.png` | Per-policy horizons: what is eligible for pruning, and what has been. |
| `health.png` | Root, ledger version, counts, last checkpoint. |
| `*-dark.png` | The explorer follows the reader's colour scheme. |

The content is the pack's demonstration data. Names are fictional
specimens and the vehicle identification numbers are not real.
