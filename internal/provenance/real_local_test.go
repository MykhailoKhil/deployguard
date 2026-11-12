package provenance

import (
	"os"
	"testing"
)

// Local-only check against the real file from `gh attestation trusted-root`; skipped unless the
// path is provided, so it never needs the network in CI.
func TestLoadsTheRealGhTrustedRoot(t *testing.T) {
	path := os.Getenv("DEPLOYGUARD_TEST_TRUSTED_ROOT")
	if path == "" {
		t.Skip("set DEPLOYGUARD_TEST_TRUSTED_ROOT to a file made by `gh attestation trusted-root`")
	}
	trusted, err := LoadTrustedRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewVerifier(trusted); err != nil {
		t.Fatal(err)
	}
}
