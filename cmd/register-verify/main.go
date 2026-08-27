// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Command register-verify checks a register's evidence offline.
//
// It never contacts the register. Everything it needs is in the files
// it is given: a signed evidence bundle or checkpoint, and the
// register's published verification key. That is deliberate. Evidence
// whose verification depends on asking the system that produced it is
// not evidence; the point of holding checkpoints externally is that
// they can be checked when the register is unavailable, uncooperative,
// or being disputed.
//
//	register-verify bundle     evidence.json --key key.txt [--checkpoint cp.json]
//	register-verify checkpoint checkpoint.json --key key.txt
//	register-verify chain      checkpoints.json --key key.txt
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Privasys/container-app-register/internal/checkpoint"
	"github.com/Privasys/container-app-register/internal/model"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	command := os.Args[1]
	fs := flag.NewFlagSet(command, flag.ExitOnError)
	keyRef := fs.String("key", "", "the register's verification key: base64, or a file containing it")
	anchorPath := fs.String("checkpoint", "", "a checkpoint you hold, to anchor a bundle against")
	quiet := fs.Bool("quiet", false, "print nothing; report the verdict in the exit status")

	// Parse repeatedly so flags may appear on either side of the file
	// name. `register-verify bundle evidence.json --key k` is how anyone
	// would type it, and the flag package stops at the first
	// non-flag argument.
	var positional []string
	for rest := os.Args[2:]; ; {
		_ = fs.Parse(rest)
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	if len(positional) != 1 {
		usage()
		os.Exit(2)
	}
	out := &report{quiet: *quiet}

	var err error
	switch command {
	case "bundle":
		err = verifyBundle(out, positional[0], *keyRef, *anchorPath)
	case "checkpoint":
		err = verifyCheckpoint(out, positional[0], *keyRef)
	case "chain":
		err = verifyChain(out, positional[0], *keyRef)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "register-verify: %v\n", err)
		os.Exit(2)
	}
	out.finish()
}

func usage() {
	fmt.Fprint(os.Stderr, `register-verify checks a Privasys register's evidence offline.

  register-verify bundle     <evidence.json>   --key <key> [--checkpoint <cp.json>]
  register-verify checkpoint <checkpoint.json> --key <key>
  register-verify chain      <checkpoints.json> --key <key>

The key is the register's Ed25519 verification key, base64 encoded, either
inline or in a file. Fetch it once from GET /api/v1/checkpoints/key and keep
it; it is what makes every later check independent of the register.

Exit status is 0 when every check passed, 1 when one did not.
`)
}

// -- commands --------------------------------------------------------------

func verifyBundle(out *report, path, keyRef, anchorPath string) error {
	pub, err := loadKey(keyRef)
	if err != nil {
		return err
	}
	var bundle model.EvidenceBundle
	if err := readJSON(path, &bundle); err != nil {
		return err
	}

	out.headline(bundle.Statement)
	out.check("Merkle proof", checkpoint.VerifyBundleProof(&bundle),
		fmt.Sprintf("the proof folds to root %s and shows the entry %s",
			shorten(bundle.Root), presence(bundle.Present)))
	out.check("Register signature", checkpoint.VerifyBundleSignature(pub, &bundle),
		fmt.Sprintf("signed by key %s", shorten(bundle.KeyID)))

	anchor := bundle.Checkpoint
	if anchorPath != "" {
		var held model.SignedCheckpoint
		if err := readJSON(anchorPath, &held); err != nil {
			return err
		}
		anchor = &held
		out.check("Held checkpoint", checkpoint.VerifyCheckpoint(pub, anchor),
			fmt.Sprintf("your checkpoint for version %d is genuine", anchor.Checkpoint.Version))
	}
	if anchor == nil {
		out.unknown("Anchor", "the bundle carries no checkpoint, and none was supplied")
	} else {
		out.check("Anchor", checkpoint.VerifyBundleAgainstCheckpoint(&bundle, &anchor.Checkpoint),
			fmt.Sprintf("the state this was read at is the state checkpoint %d attests",
				anchor.Checkpoint.Version))
		if anchorPath == "" {
			out.check("Bundled checkpoint", checkpoint.VerifyCheckpoint(pub, anchor),
				"the bundled checkpoint is genuine")
			out.note("The checkpoint came with the bundle. Anchoring against one you already " +
				"held is what rules out a register replaying an older state.")
		}
	}
	if bundle.Row != nil {
		out.detail("Row", bundle.Row)
	}
	return nil
}

func verifyCheckpoint(out *report, path, keyRef string) error {
	pub, err := loadKey(keyRef)
	if err != nil {
		return err
	}
	var sc model.SignedCheckpoint
	if err := readJSON(path, &sc); err != nil {
		return err
	}
	out.headline(fmt.Sprintf("Checkpoint %d of register %q", sc.Checkpoint.Version, sc.Checkpoint.Register))
	out.check("Signature", checkpoint.VerifyCheckpoint(pub, &sc),
		fmt.Sprintf("root %s at ledger version %d", shorten(sc.Checkpoint.Root), sc.Checkpoint.Version))
	out.detail("Checkpoint", sc.Checkpoint)
	return nil
}

// verifyChain checks a list of checkpoints: each signed, versions
// strictly increasing, and no two checkpoints claiming different roots
// for the same version. That last check is the one that catches a fork:
// a register that served two different histories has to sign both.
func verifyChain(out *report, path, keyRef string) error {
	pub, err := loadKey(keyRef)
	if err != nil {
		return err
	}
	var list []model.SignedCheckpoint
	if err := readJSON(path, &list); err != nil {
		var wrapper struct {
			Checkpoints []model.SignedCheckpoint `json:"checkpoints"`
		}
		if err2 := readJSON(path, &wrapper); err2 != nil {
			return err
		}
		list = wrapper.Checkpoints
	}
	if len(list) == 0 {
		return fmt.Errorf("no checkpoints in %s", path)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].Checkpoint.Version < list[j].Checkpoint.Version
	})
	out.headline(fmt.Sprintf("Checkpoint chain of register %q, %d entries",
		list[0].Checkpoint.Register, len(list)))

	seen := map[uint64]string{}
	signatures := true
	for i := range list {
		if err := checkpoint.VerifyCheckpoint(pub, &list[i]); err != nil {
			out.check(fmt.Sprintf("Checkpoint %d", list[i].Checkpoint.Version), err, "")
			signatures = false
		}
		cp := list[i].Checkpoint
		if root, ok := seen[cp.Version]; ok && root != cp.Root {
			out.check(fmt.Sprintf("Version %d", cp.Version),
				fmt.Errorf("two checkpoints claim different roots for the same version: %s and %s",
					shorten(root), shorten(cp.Root)), "")
			signatures = false
		}
		seen[cp.Version] = cp.Root
	}
	if signatures {
		out.check("Signatures", nil, fmt.Sprintf("all %d checkpoints are genuine", len(list)))
		out.check("Consistency", nil, "no version is claimed with two different roots")
	}
	first, last := list[0].Checkpoint, list[len(list)-1].Checkpoint
	out.note(fmt.Sprintf("Covers ledger versions %d to %d.", first.Version, last.Version))
	return nil
}

// -- reporting -------------------------------------------------------------

type report struct {
	quiet  bool
	failed bool
}

func (r *report) headline(text string) {
	if !r.quiet {
		fmt.Printf("%s\n\n", text)
	}
}

func (r *report) check(name string, err error, success string) {
	if err != nil {
		r.failed = true
		if !r.quiet {
			fmt.Printf("  ✗ %-22s %s\n", name, err)
		}
		return
	}
	if !r.quiet {
		fmt.Printf("  ✓ %-22s %s\n", name, success)
	}
}

func (r *report) unknown(name, why string) {
	if !r.quiet {
		fmt.Printf("  ? %-22s %s\n", name, why)
	}
}

func (r *report) note(text string) {
	if !r.quiet {
		fmt.Printf("\n%s\n", wrap(text, 74))
	}
}

func (r *report) detail(title string, value any) {
	if r.quiet {
		return
	}
	encoded, err := json.MarshalIndent(value, "  ", "  ")
	if err != nil {
		return
	}
	fmt.Printf("\n%s\n  %s\n", title, encoded)
}

func (r *report) finish() {
	if r.failed {
		if !r.quiet {
			fmt.Println("\nVerification FAILED.")
		}
		os.Exit(1)
	}
	if !r.quiet {
		fmt.Println("\nVerified.")
	}
}

// -- helpers ---------------------------------------------------------------

func readJSON(path string, into any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func loadKey(ref string) (ed25519PublicKey, error) {
	if ref == "" {
		return nil, fmt.Errorf("--key is required")
	}
	encoded := ref
	if raw, err := os.ReadFile(ref); err == nil {
		encoded = strings.TrimSpace(string(raw))
		// A key file may be the JSON the API serves rather than the bare
		// value; accept either.
		var doc struct {
			PublicKey string `json:"public_key"`
		}
		if json.Unmarshal(raw, &doc) == nil && doc.PublicKey != "" {
			encoded = doc.PublicKey
		}
	}
	return checkpoint.ParsePublicKey(encoded)
}

type ed25519PublicKey = []byte

func shorten(hash string) string {
	if len(hash) <= 16 {
		return hash
	}
	return hash[:16] + "…"
}

func presence(present bool) string {
	if present {
		return "present"
	}
	return "absent"
}

func wrap(text string, width int) string {
	var out strings.Builder
	line := 0
	for _, word := range strings.Fields(text) {
		if line > 0 && line+len(word)+1 > width {
			out.WriteByte('\n')
			line = 0
		} else if line > 0 {
			out.WriteByte(' ')
			line++
		}
		out.WriteString(word)
		line += len(word)
	}
	return out.String()
}
