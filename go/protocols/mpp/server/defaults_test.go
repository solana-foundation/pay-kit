package server

import (
	"strings"
	"testing"
)

const testRealmRecipient = "8aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890aBcDeF"

func TestDetectRealmPriority(t *testing.T) {
	envVars := []string{
		"MPP_REALM", "FLY_APP_NAME", "HEROKU_APP_NAME",
		"RAILWAY_SERVICE_NAME", "RENDER_SERVICE_NAME",
		"K_SERVICE", "HOSTNAME",
	}
	// Clear all env vars first.
	for _, key := range envVars {
		t.Setenv(key, "")
	}

	want := deriveDefaultRealm(testRealmRecipient)
	if got := DetectRealm(testRealmRecipient); got != want {
		t.Fatalf("expected derived realm %q, got %q", want, got)
	}

	// HOSTNAME should be used when it's the only one set.
	t.Setenv("HOSTNAME", "my-host")
	if got := DetectRealm(testRealmRecipient); got != "my-host" {
		t.Fatalf("expected HOSTNAME, got %q", got)
	}

	// FLY_APP_NAME takes priority over HOSTNAME.
	t.Setenv("FLY_APP_NAME", "my-fly-app")
	if got := DetectRealm(testRealmRecipient); got != "my-fly-app" {
		t.Fatalf("expected FLY_APP_NAME, got %q", got)
	}

	// MPP_REALM takes highest priority.
	t.Setenv("MPP_REALM", "custom-realm")
	if got := DetectRealm(testRealmRecipient); got != "custom-realm" {
		t.Fatalf("expected MPP_REALM, got %q", got)
	}
}

func TestDetectRealmFallback(t *testing.T) {
	envVars := []string{
		"MPP_REALM", "FLY_APP_NAME", "HEROKU_APP_NAME",
		"RAILWAY_SERVICE_NAME", "RENDER_SERVICE_NAME",
		"K_SERVICE", "HOSTNAME",
	}
	for _, key := range envVars {
		t.Setenv(key, "")
	}

	want := deriveDefaultRealm(testRealmRecipient)
	if got := DetectRealm(testRealmRecipient); got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestDeriveDefaultRealm(t *testing.T) {
	realm := deriveDefaultRealm(testRealmRecipient)
	if !strings.HasPrefix(realm, "App Id - #") {
		t.Fatalf("expected derived realm to start with %q, got %q", "App Id - #", realm)
	}
	// Deterministic for the same recipient (restart-safe).
	if again := deriveDefaultRealm(testRealmRecipient); again != realm {
		t.Fatalf("derive not deterministic: %q != %q", realm, again)
	}
	// Differs across recipients (closes the cross-service replay threat).
	other := deriveDefaultRealm("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
	if other == realm {
		t.Fatalf("expected distinct realms for distinct recipients, both %q", realm)
	}
}

func TestDetectSecretKey(t *testing.T) {
	t.Setenv(secretKeyEnvVar, "")
	if got := DetectSecretKey(); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}

	t.Setenv(secretKeyEnvVar, "my-secret")
	if got := DetectSecretKey(); got != "my-secret" {
		t.Fatalf("expected my-secret, got %q", got)
	}
}
