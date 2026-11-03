package config

import "testing"

func TestAppIDHex(t *testing.T) {
	for raw, want := range map[string]string{
		"bf8c3811-703b-4f5c-8560-7486c31154b7": "bf8c3811703b4f5c85607486c31154b7",
		"BF8C3811703B4F5C85607486C31154B7":     "bf8c3811703b4f5c85607486c31154b7",
		"":                                     "",
		"not-an-id":                            "",
	} {
		if got := AppIDHex(raw); got != want {
			t.Errorf("AppIDHex(%q) = %q, want %q", raw, got, want)
		}
	}
}
