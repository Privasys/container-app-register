// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package register

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Privasys/container-app-register/internal/model"
	"github.com/Privasys/container-app-register/internal/pack"
	"github.com/Privasys/container-app-register/internal/store"
)

// crockford is Crockford's Base32 alphabet: no I, L, O or U.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// Check97 computes ISO/IEC 7064 MOD 97-10 check digits over the letters and
// digits of s, letters counting A = 10 to Z = 35, as for an IBAN or an LEI.
func Check97(s string) string {
	var digits strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch {
		case r >= '0' && r <= '9':
			digits.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			digits.WriteString(strconv.Itoa(int(r-'A') + 10))
		}
	}
	digits.WriteString("00")
	n, _ := new(big.Int).SetString(digits.String(), 10)
	rem := new(big.Int).Mod(n, big.NewInt(97)).Int64()
	return fmt.Sprintf("%02d", 98-rem)
}

// Valid97 says whether an identifier's trailing two digits are the MOD
// 97-10 check digits of what comes before them.
func Valid97(s string) bool {
	clean := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToUpper(r)
		}
		return -1
	}, s)
	if len(clean) < 3 {
		return false
	}
	return Check97(clean[:len(clean)-2]) == clean[len(clean)-2:]
}

// permute turns a counter into a serial of `bits` bits with a balanced
// Feistel network keyed by the register: one-to-one, so serials never
// repeat within a year, and unpredictable without the key.
func permute(key []byte, scope string, counter uint64, bits int) uint64 {
	half := bits / 2
	mask := uint64(1)<<half - 1
	left, right := (counter>>half)&mask, counter&mask
	for round := byte(0); round < 4; round++ {
		mac := hmac.New(sha256.New, key)
		var buf [9]byte
		buf[0] = round
		binary.BigEndian.PutUint64(buf[1:], right)
		mac.Write([]byte(scope))
		mac.Write(buf[:])
		f := binary.BigEndian.Uint64(mac.Sum(nil)[:8]) & mask
		left, right = right, left^f
	}
	return left<<half | right
}

func base32Crockford(v uint64, chars int) string {
	out := make([]byte, chars)
	for i := chars - 1; i >= 0; i-- {
		out[i] = crockford[v&31]
		v >>= 5
	}
	return string(out)
}

// identifierKey is the key of an identifier's permutation, derived from the
// register's sealed master secret, so it never leaves the register and is
// in every backup of it.
func (r *Register) identifierKey(class *pack.Class, id *pack.Identifier) []byte {
	mac := hmac.New(sha256.New, r.mat.Master[:])
	mac.Write([]byte("identifier\x00" + class.Name + "\x00" + id.Property))
	return mac.Sum(nil)
}

// format renders an identifier for a year and a serial.
func formatIdentifier(id *pack.Identifier, year int, serial string) string {
	var b strings.Builder
	for _, part := range id.Parts() {
		switch {
		case part == "{year}":
			b.WriteString(strconv.Itoa(year))
		case strings.HasPrefix(part, "{serial:"):
			b.WriteString(serial)
		case part == "{check}":
			b.WriteString(Check97(b.String()))
		default:
			b.WriteString(part)
		}
	}
	return b.String()
}

// mintIdentifiers fills each identifier property the payload leaves empty,
// and returns the writes that advance the counters.
func (r *Register) mintIdentifiers(tx *store.Tx, w *writeCtx, class *pack.Class, payload map[string]any) ([]model.WriteOp, error) {
	var ops []model.WriteOp
	for i := range class.Identifiers {
		id := &class.Identifiers[i]
		if v, ok := payload[id.Property]; ok && v != nil && v != "" {
			continue
		}
		year := time.Unix(w.at, 0).In(id.Location()).Year()
		counterKey := fmt.Sprintf("identifier:%s:%s:%d", class.Name, id.Property, year)
		held, err := r.registryValue(tx, counterKey)
		if err != nil {
			return nil, err
		}
		counter, _ := strconv.ParseUint(held, 10, 64)
		chars := id.SerialLength()
		space := uint64(1) << (5 * chars)
		key := r.identifierKey(class, id)
		var value string
		for attempts := 0; ; attempts++ {
			if counter >= space || attempts > 64 {
				return nil, fmt.Errorf("no %s left to assign in %d", id.Property, year)
			}
			serial := base32Crockford(permute(key, strconv.Itoa(year), counter, 5*chars), chars)
			counter++
			value = formatIdentifier(id, year, serial)
			// A changed key would change the permutation; never reuse what
			// is already recorded, whatever produced it.
			if class.NaturalKey == id.Property {
				row, err := tx.QueryOne("SELECT id FROM `objects` WHERE tenant = " + store.Lit(w.tenant) +
					" AND class = " + store.Lit(class.Name) + " AND natural_key = " + store.Lit(value))
				if err != nil {
					return nil, err
				}
				if row != nil {
					continue
				}
			}
			break
		}
		payload[id.Property] = value
		ops = append(ops, model.WriteOp{
			Table: "registry", Key: map[string]any{"k": counterKey},
			Values: map[string]any{"v": model.Binary([]byte(strconv.FormatUint(counter, 10))), "updated_at": w.at},
		})
	}
	return ops, nil
}

// withPlaceholders returns a copy of a payload with each unassigned
// identifier given a well-formed placeholder, so a proposal is checked
// against the class schema before the register has assigned anything.
func withPlaceholders(class *pack.Class, payload map[string]any) map[string]any {
	if len(class.Identifiers) == 0 {
		return payload
	}
	out := make(map[string]any, len(payload)+len(class.Identifiers))
	for k, v := range payload {
		out[k] = v
	}
	for i := range class.Identifiers {
		id := &class.Identifiers[i]
		if v, ok := out[id.Property]; !ok || v == nil || v == "" {
			out[id.Property] = formatIdentifier(id, 2000, strings.Repeat("0", id.SerialLength()))
		}
	}
	return out
}

// Permute exposes the serial permutation to tests.
func Permute(key []byte, scope string, counter uint64, bits int) uint64 {
	return permute(key, scope, counter, bits)
}
