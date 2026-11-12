package provenance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/testing/ca"

	gh "github.com/deployguard/deployguard/internal/github"
)

const (
	repo     = "acme/app"
	workflow = "deployguard-plan.yml"
	pr       = 12
)

var planBytes = []byte(`{"format_version":"1.2","resource_changes":[]}`)

func identityFor(repository, file string, number int) string {
	return fmt.Sprintf("https://github.com/%s/.github/workflows/%s@refs/pull/%d/merge", repository, file, number)
}

func statement(digestHex, predicate string) []byte {
	return []byte(fmt.Sprintf(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"tfplan.json","digest":{"sha256":%q}}],"predicateType":%q,"predicate":{}}`, digestHex, predicate))
}

func newVerifier(t *testing.T) (*Verifier, *ca.VirtualSigstore) {
	t.Helper()
	virtual, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(virtual)
	if err != nil {
		t.Fatal(err)
	}
	return verifier, virtual
}

func digestOf(data []byte) ([]byte, string) {
	sum := sha256.Sum256(data)
	return sum[:], hex.EncodeToString(sum[:])
}

var expectation = Expectation{Repository: repo, WorkflowFile: workflow, PullRequest: pr}

// These tests run real Sigstore verification (certificate chain, signature, timestamps and
// transparency evidence) against an in-memory test CA.

func TestVerifiesAnAttestationFromTheExpectedWorkflow(t *testing.T) {
	verifier, virtual := newVerifier(t)
	digest, digestHex := digestOf(planBytes)
	entity, err := virtual.Attest(identityFor(repo, workflow, pr), githubActionsIssuer, statement(digestHex, "https://slsa.dev/provenance/v1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.verifyEntity(entity, digest, expectation); err != nil {
		t.Fatalf("a genuine attestation was rejected: %v", err)
	}
}

func TestRejectsEveryWayAnAttestationCanBeWrong(t *testing.T) {
	verifier, virtual := newVerifier(t)
	digest, digestHex := digestOf(planBytes)
	_, otherHex := digestOf([]byte("a different plan"))
	slsa := "https://slsa.dev/provenance/v1"
	cases := map[string]struct {
		identity, issuer string
		body             []byte
	}{
		"other workflow file":    {identityFor(repo, "evil.yml", pr), githubActionsIssuer, statement(digestHex, slsa)},
		"other repository":       {identityFor("attacker/app", workflow, pr), githubActionsIssuer, statement(digestHex, slsa)},
		"other pull request":     {identityFor(repo, workflow, pr+1), githubActionsIssuer, statement(digestHex, slsa)},
		"main branch, not PR":    {"https://github.com/acme/app/.github/workflows/deployguard-plan.yml@refs/heads/main", githubActionsIssuer, statement(digestHex, slsa)},
		"prefix/suffix tricks":   {identityFor(repo, workflow, pr) + "/extra", githubActionsIssuer, statement(digestHex, slsa)},
		"wrong OIDC issuer":      {identityFor(repo, workflow, pr), "https://accounts.example.com", statement(digestHex, slsa)},
		"different plan content": {identityFor(repo, workflow, pr), githubActionsIssuer, statement(otherHex, slsa)},
		"not SLSA provenance":    {identityFor(repo, workflow, pr), githubActionsIssuer, statement(digestHex, "https://example.com/other/v1")},
	}
	for name, tc := range cases {
		entity, err := virtual.Attest(tc.identity, tc.issuer, tc.body)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := verifier.verifyEntity(entity, digest, expectation); err == nil {
			t.Errorf("%s: a bad attestation was accepted", name)
		}
	}
}

func TestRejectsAnAttestationFromAnUntrustedCA(t *testing.T) {
	verifier, _ := newVerifier(t)
	stranger, err := ca.NewVirtualSigstore() // a different CA the verifier does not trust
	if err != nil {
		t.Fatal(err)
	}
	digest, digestHex := digestOf(planBytes)
	entity, _ := stranger.Attest(identityFor(repo, workflow, pr), githubActionsIssuer, statement(digestHex, "https://slsa.dev/provenance/v1"))
	if err := verifier.verifyEntity(entity, digest, expectation); err == nil {
		t.Fatal("an attestation signed under an untrusted root must not verify")
	}
}

func TestVerifyBundleRejectsGarbageAndBadExpectations(t *testing.T) {
	verifier, _ := newVerifier(t)
	digest, _ := digestOf(planBytes)
	if err := verifier.VerifyBundle([]byte(`not json`), digest, expectation); err == nil {
		t.Error("garbage must be rejected")
	}
	if err := verifier.VerifyBundle([]byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`), digest, expectation); err == nil {
		t.Error("an empty bundle must be rejected")
	}
	for name, bad := range map[string]Expectation{
		"repo injection":     {Repository: "a/b)(.*", WorkflowFile: workflow, PullRequest: pr},
		"workflow with path": {Repository: repo, WorkflowFile: "../x.yml", PullRequest: pr},
		"pr zero":            {Repository: repo, WorkflowFile: workflow, PullRequest: 0},
	} {
		if err := bad.validate(); err == nil {
			t.Errorf("%s: expectation accepted", name)
		}
	}
	if err := verifier.verifyEntity(nil, []byte("short"), expectation); err == nil {
		t.Error("a non-SHA-256 digest must be rejected")
	}
}

func TestIdentityPatternQuotesTheInputs(t *testing.T) {
	pattern := Expectation{Repository: "acme/app.v2", WorkflowFile: "plan.yml", PullRequest: 5}.identityPattern()
	if !strings.Contains(pattern, `acme/app\.v2`) || !strings.Contains(pattern, `plan\.yml`) || !strings.HasSuffix(pattern, `@refs/pull/5/merge$`) {
		t.Errorf("pattern %s", pattern)
	}
}

type fakeSource struct {
	bundles [][]byte
	err     error
	digest  string
}

func (f *fakeSource) FetchAttestations(_ context.Context, _ gh.VerifiedReview, digestHex string) ([][]byte, error) {
	f.digest = digestHex
	return f.bundles, f.err
}

func reviewFor() gh.VerifiedReview {
	return gh.VerifiedReview{Repository: gh.Repository{ID: 7, FullName: repo}, PullRequest: gh.PullRequest{Number: pr}, InstallationID: 42}
}

func TestCheckerReportsEachOutcomeWithFixedText(t *testing.T) {
	verifier, _ := newVerifier(t)
	_, digestHex := digestOf(planBytes)
	for name, tc := range map[string]struct {
		source       *fakeSource
		wantVerified bool
		wantDetail   string
	}{
		"fetch failure": {&fakeSource{err: errors.New("secret-token-leak")}, false, "could not be retrieved"},
		"none":          {&fakeSource{}, false, "no attestation exists"},
		"unmatched":     {&fakeSource{bundles: [][]byte{[]byte("garbage")}}, false, "matched the expected workflow"},
	} {
		checker := &Checker{Source: tc.source, Verifier: verifier, WorkflowFile: ".github/workflows/" + workflow}
		got := checker.Check(context.Background(), reviewFor(), planBytes)
		if !got.Checked || got.Verified != tc.wantVerified || !strings.Contains(got.Detail, tc.wantDetail) {
			t.Errorf("%s: %+v", name, got)
		}
		if strings.Contains(got.Detail, "secret-token-leak") {
			t.Errorf("%s: error text must not reach the detail", name)
		}
		if tc.source.digest != digestHex {
			t.Errorf("%s: looked up digest %s, want the plan's SHA-256 %s", name, tc.source.digest, digestHex)
		}
	}
	bad := &Checker{Source: &fakeSource{}, Verifier: verifier, WorkflowFile: "../x"}
	if got := bad.Check(context.Background(), reviewFor(), planBytes); got.Verified || !strings.Contains(got.Detail, "could not be checked") {
		t.Errorf("a bad workflow name must not verify: %+v", got)
	}
}

func TestLoadTrustedRootAcceptsSingleAndMultiRootFilesOnly(t *testing.T) {
	// public-good.json is Sigstore's public trust root, copied from sigstore-go's test data (Apache-2.0).
	for _, file := range []string{"testdata/public-good.json", "testdata/two-roots.jsonl"} {
		if trusted, err := LoadTrustedRoot(file); err != nil || trusted == nil {
			t.Errorf("%s: %v", file, err)
		} else if _, err := NewVerifier(trusted); err != nil {
			t.Errorf("%s: cannot build a verifier from it: %v", file, err)
		}
	}
	dir := t.TempDir()
	for name, content := range map[string]string{"empty.json": "\n  \n", "garbage.json": "not json\n", "partly-bad.jsonl": "{}\nnope\n"} {
		path := dir + "/" + name
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadTrustedRoot(path); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := LoadTrustedRoot(dir + "/missing.json"); err == nil {
		t.Error("a missing file must be an error")
	}
}
