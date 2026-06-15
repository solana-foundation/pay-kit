package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// vectorsDir locates the seeded conformance vectors relative to the module.
// The runner lives in go/cmd/conformance; the vectors live in
// harness/vectors at the repo root.
func vectorsDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "harness", "vectors")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("harness vectors not present at %s: %v", dir, err)
	}
	return dir
}

// TestSeededVectorsConform drives every seeded vector through runVector and
// asserts the runner outcome matches the vector's expect block, plus the
// exact bytes for canonical-bytes vectors. This is the Go-side mirror of the
// harness conformance driver so the runner stays green in Go CI without the
// TypeScript harness.
func TestSeededVectorsConform(t *testing.T) {
	dir := vectorsDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read vectors dir: %v", err)
	}

	type expectBlock struct {
		Outcome    string `json:"outcome"`
		ExactBytes *struct {
			CanonicalJSON string `json:"canonicalJson"`
			Base64URL     string `json:"base64Url"`
			Bytes         []int  `json:"bytes"`
		} `json:"exactBytes"`
	}

	total := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		var vectors []Vector
		if err := json.Unmarshal(raw, &vectors); err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		// Re-parse expect blocks alongside the vectors for assertions.
		var rawVectors []struct {
			ID     string      `json:"id"`
			Expect expectBlock `json:"expect"`
		}
		if err := json.Unmarshal(raw, &rawVectors); err != nil {
			t.Fatalf("parse expect in %s: %v", entry.Name(), err)
		}

		for i, vector := range vectors {
			expect := rawVectors[i].Expect
			t.Run(vector.ID, func(t *testing.T) {
				result := runVector(vector)
				if result.Outcome != expect.Outcome {
					t.Fatalf("%s: outcome = %q, want %q (error: %s)",
						vector.ID, result.Outcome, expect.Outcome, result.Error)
				}
				if expect.Outcome != "accept" {
					return
				}
				if expect.ExactBytes != nil {
					if result.ExactBytes == nil {
						t.Fatalf("%s: expected exactBytes, got none", vector.ID)
					}
					if want := expect.ExactBytes.CanonicalJSON; want != "" && result.ExactBytes.CanonicalJSON != want {
						t.Errorf("%s: canonicalJson = %q, want %q", vector.ID, result.ExactBytes.CanonicalJSON, want)
					}
					if want := expect.ExactBytes.Base64URL; want != "" && result.ExactBytes.Base64URL != want {
						t.Errorf("%s: base64Url = %q, want %q", vector.ID, result.ExactBytes.Base64URL, want)
					}
					if want := expect.ExactBytes.Bytes; want != nil {
						if len(result.ExactBytes.Bytes) != len(want) {
							t.Errorf("%s: bytes len = %d, want %d", vector.ID, len(result.ExactBytes.Bytes), len(want))
						} else {
							for j := range want {
								if result.ExactBytes.Bytes[j] != want[j] {
									t.Errorf("%s: bytes[%d] = %d, want %d", vector.ID, j, result.ExactBytes.Bytes[j], want[j])
									break
								}
							}
						}
					}
				}
			})
			total++
		}
	}

	if total < 13 {
		t.Fatalf("expected at least 13 seeded vectors, ran %d", total)
	}
}
