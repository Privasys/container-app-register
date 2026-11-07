// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package pack

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Identifier is a property the register assigns when it creates a record,
// never the person proposing it: a registration number, for instance.
//
// Format is literal text with three kinds of field:
//
//	{year}       the year of creation, in the identifier's time zone
//	{serial:N}   N characters of Crockford Base32 (N even, 4 to 12): a
//	             counter for the year, turned by a keyed permutation into
//	             a serial that looks random, never repeats and cannot be
//	             predicted without the register's key
//	{check}      two check digits, ISO/IEC 7064 MOD 97-10, over the
//	             letters and digits written before it
//
// "IM-DAR-{year}-{serial:6}-{check}" gives IM-DAR-2027-7K3QX9-63.
type Identifier struct {
	Property string `json:"property"`
	Format   string `json:"format"`
	// TimeZone decides the year, as an IANA name; UTC when empty.
	TimeZone string `json:"time_zone,omitempty"`
}

var identifierField = regexp.MustCompile(`\{(year|serial:[0-9]+|check)\}`)

// Parts splits the format into literal text and fields.
func (id *Identifier) Parts() []string {
	var out []string
	rest := id.Format
	for {
		loc := identifierField.FindStringIndex(rest)
		if loc == nil {
			if rest != "" {
				out = append(out, rest)
			}
			return out
		}
		if loc[0] > 0 {
			out = append(out, rest[:loc[0]])
		}
		out = append(out, rest[loc[0]:loc[1]])
		rest = rest[loc[1]:]
	}
}

// SerialLength is the number of serial characters, 0 when there is none.
func (id *Identifier) SerialLength() int {
	for _, part := range id.Parts() {
		if strings.HasPrefix(part, "{serial:") {
			n, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(part, "{serial:"), "}"))
			return n
		}
	}
	return 0
}

// Location is the time zone the year is read in.
func (id *Identifier) Location() *time.Location {
	if id.TimeZone == "" {
		return time.UTC
	}
	loc, err := time.LoadLocation(id.TimeZone)
	if err != nil {
		return time.UTC
	}
	return loc
}

func validateIdentifier(class *Class, id *Identifier) error {
	props, err := classProperties(class)
	if err != nil {
		return err
	}
	if _, ok := props[id.Property]; !ok {
		return fmt.Errorf("class %s: identifier %q is not a property", class.Name, id.Property)
	}
	serials, checks := 0, 0
	for _, part := range id.Parts() {
		switch {
		case strings.HasPrefix(part, "{serial:"):
			serials++
			n := id.SerialLength()
			if n < 4 || n > 12 || n%2 != 0 {
				return fmt.Errorf("class %s: identifier serial length must be even, 4 to 12", class.Name)
			}
		case part == "{check}":
			checks++
		case strings.HasPrefix(part, "{") && identifierField.MatchString(part):
		case strings.ContainsAny(part, "{}"):
			return fmt.Errorf("class %s: identifier format %q has an unknown field", class.Name, id.Format)
		}
	}
	if serials != 1 {
		return fmt.Errorf("class %s: an identifier has exactly one serial", class.Name)
	}
	if checks > 1 {
		return fmt.Errorf("class %s: an identifier has at most one check", class.Name)
	}
	if id.TimeZone != "" {
		if _, err := time.LoadLocation(id.TimeZone); err != nil {
			return fmt.Errorf("class %s: identifier time zone: %w", class.Name, err)
		}
	}
	return nil
}
