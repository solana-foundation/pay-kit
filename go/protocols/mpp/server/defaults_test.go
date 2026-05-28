package server

import "testing"

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

	if got := DetectRealm(); got != defaultRealm {
		t.Fatalf("expected default realm %q, got %q", defaultRealm, got)
	}

	// HOSTNAME should be used when it's the only one set.
	t.Setenv("HOSTNAME", "my-host")
	if got := DetectRealm(); got != "my-host" {
		t.Fatalf("expected HOSTNAME, got %q", got)
	}

	// FLY_APP_NAME takes priority over HOSTNAME.
	t.Setenv("FLY_APP_NAME", "my-fly-app")
	if got := DetectRealm(); got != "my-fly-app" {
		t.Fatalf("expected FLY_APP_NAME, got %q", got)
	}

	// MPP_REALM takes highest priority.
	t.Setenv("MPP_REALM", "custom-realm")
	if got := DetectRealm(); got != "custom-realm" {
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

	if got := DetectRealm(); got != defaultRealm {
		t.Fatalf("expected %q, got %q", defaultRealm, got)
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
