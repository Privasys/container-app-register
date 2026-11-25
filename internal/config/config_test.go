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

func platform(t *testing.T) {
	t.Setenv("PORT", "8080")
	t.Setenv("PRIVASYS_CONTAINER_NAME", "register")
	t.Setenv("PRIVASYS_CONTAINER_TOKEN", "token")
	t.Setenv("PRIVASYS_MANAGER_URL", "http://manager")
}

func TestOnThePlatformTheAppIsItsOwnAudience(t *testing.T) {
	platform(t)
	t.Setenv("PRIVASYS_APP_ID", "BF8C3811-703B-4F5C-8560-7486C31154B7")
	c, err := Load()
	if err != nil || c.Audience != "app:bf8c3811703b4f5c85607486c31154b7" {
		t.Fatalf("audience %q, %v", c.Audience, err)
	}
	t.Setenv("REGISTER_OIDC_AUDIENCE", "named")
	if c, err := Load(); err != nil || c.Audience != "named" {
		t.Errorf("a named audience: %q, %v", c.Audience, err)
	}
}

func TestNoAudienceRefusesToStart(t *testing.T) {
	platform(t)
	t.Setenv("PRIVASYS_APP_ID", "")
	if _, err := Load(); err == nil {
		t.Error("started on the platform with no app id")
	}
	t.Setenv("PRIVASYS_CONTAINER_TOKEN", "")
	t.Setenv("PRIVASYS_APP_ID", "bf8c3811703b4f5c85607486c31154b7")
	if _, err := Load(); err == nil {
		t.Error("started off the platform with no audience")
	}
	t.Setenv("REGISTER_DEV_AUTH", "1")
	if _, err := Load(); err != nil {
		t.Errorf("development: %v", err)
	}
}
