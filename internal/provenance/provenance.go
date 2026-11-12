// Package provenance checks that a Terraform plan file was produced by the expected CI workflow,
// using GitHub artifact attestations (Sigstore). A plan is "verified" only when a valid attestation
// exists for the SHA-256 of the exact bytes being analyzed AND its signing identity is the
// configured workflow file, in the same repository, for the same pull request.
package provenance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/deployguard/deployguard/internal/domain"
	gh "github.com/deployguard/deployguard/internal/github"
)

// githubActionsIssuer is the OIDC issuer GitHub Actions certificates carry.
const githubActionsIssuer = "https://token.actions.githubusercontent.com"

// Statement types we accept: SLSA build provenance, which actions/attest-build-provenance writes.
var acceptedPredicates = map[string]bool{
	"https://slsa.dev/provenance/v1":   true,
	"https://slsa.dev/provenance/v0.2": true,
}

var (
	repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	workflowPattern   = regexp.MustCompile(`^[A-Za-z0-9_.-]+\.ya?ml$`)
)

// Expectation is what a valid attestation must say about where the plan came from.
type Expectation struct {
	Repository   string // "owner/name"
	WorkflowFile string // for example "deployguard-plan.yml"
	PullRequest  int
}

func (e Expectation) validate() error {
	if !repositoryPattern.MatchString(e.Repository) || !workflowPattern.MatchString(e.WorkflowFile) || e.PullRequest <= 0 {
		return errors.New("invalid provenance expectation")
	}
	return nil
}

// identityPattern matches the certificate's workflow identity exactly:
// https://github.com/<repo>/.github/workflows/<file>@refs/pull/<N>/merge
func (e Expectation) identityPattern() string {
	return fmt.Sprintf(`^https://github\.com/%s/\.github/workflows/%s@refs/pull/%d/merge$`,
		regexp.QuoteMeta(e.Repository), regexp.QuoteMeta(e.WorkflowFile), e.PullRequest)
}

// Verifier verifies Sigstore bundles against a trusted root.
type Verifier struct {
	verifier *verify.Verifier
}

// LoadTrustedRoot reads Sigstore trust roots from a file with one JSON root per line (JSONL), as
// written by `gh attestation trusted-root`, which covers both public-good Sigstore and GitHub's
// own instance. A plain single-root trusted_root.json works too. Every root in the file is trusted.
func LoadTrustedRoot(path string) (root.TrustedMaterial, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("cannot read the Sigstore trusted root file")
	}
	if single, err := root.NewTrustedRootFromJSON(raw); err == nil { // one (possibly pretty-printed) root
		return single, nil
	}
	var roots root.TrustedMaterialCollection
	for _, line := range bytes.Split(raw, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		trusted, err := root.NewTrustedRootFromJSON(line)
		if err != nil {
			return nil, errors.New("the Sigstore trusted root file is not valid (expected one JSON trust root per line)")
		}
		roots = append(roots, trusted)
	}
	if len(roots) == 0 {
		return nil, errors.New("the Sigstore trusted root file is empty")
	}
	return roots, nil
}

// NewVerifier builds a verifier. A transparency-log entry or a signed timestamp must prove when the
// certificate was used (GitHub's private instance has no transparency log, only timestamps).
func NewVerifier(trusted root.TrustedMaterial) (*Verifier, error) {
	verifier, err := verify.NewVerifier(trusted, verify.WithObserverTimestamps(1))
	if err != nil {
		return nil, err
	}
	return &Verifier{verifier: verifier}, nil
}

// VerifyBundle checks one attestation bundle (JSON) for the plan digest and expectation.
func (v *Verifier) VerifyBundle(bundleJSON []byte, planDigest []byte, expect Expectation) error {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return errors.New("attestation bundle is malformed")
	}
	return v.verifyEntity(&b, planDigest, expect)
}

func (v *Verifier) verifyEntity(entity verify.SignedEntity, planDigest []byte, expect Expectation) error {
	if err := expect.validate(); err != nil {
		return err
	}
	if len(planDigest) != sha256.Size {
		return errors.New("plan digest must be a SHA-256")
	}
	identity, err := verify.NewShortCertificateIdentity(githubActionsIssuer, "", "", expect.identityPattern())
	if err != nil {
		return err
	}
	result, err := v.verifier.Verify(entity, verify.NewPolicy(
		verify.WithArtifactDigest("sha256", planDigest),
		verify.WithCertificateIdentity(identity),
	))
	if err != nil {
		return errors.New("attestation did not verify")
	}
	if result.Statement == nil || !acceptedPredicates[result.Statement.PredicateType] {
		return errors.New("attestation is not SLSA build provenance")
	}
	return nil
}

// AttestationSource fetches the attestation bundles stored for a plan digest.
type AttestationSource interface {
	FetchAttestations(ctx context.Context, review gh.VerifiedReview, digestHex string) ([][]byte, error)
}

// Checker ties a source and a verifier to the configured plan workflow.
type Checker struct {
	Source       AttestationSource
	Verifier     *Verifier
	WorkflowFile string
}

// Check hashes the plan, looks up its attestations, and reports whether any proves it came from the
// expected workflow for this pull request. Detail is fixed text, never attestation content.
func (c *Checker) Check(ctx context.Context, review gh.VerifiedReview, plan []byte) domain.Provenance {
	digest := sha256.Sum256(plan)
	expect := Expectation{Repository: review.Repository.FullName, WorkflowFile: strings.TrimPrefix(c.WorkflowFile, ".github/workflows/"), PullRequest: review.PullRequest.Number}
	if err := expect.validate(); err != nil {
		return domain.Provenance{Checked: true, Detail: "provenance could not be checked for this repository or workflow name"}
	}
	bundles, err := c.Source.FetchAttestations(ctx, review, hex.EncodeToString(digest[:]))
	if err != nil {
		return domain.Provenance{Checked: true, Detail: "attestations could not be retrieved from GitHub"}
	}
	if len(bundles) == 0 {
		return domain.Provenance{Checked: true, Detail: "no attestation exists for this exact plan file"}
	}
	for _, raw := range bundles {
		if c.Verifier.VerifyBundle(raw, digest[:], expect) == nil {
			return domain.Provenance{Checked: true, Verified: true,
				Detail: fmt.Sprintf("signed by workflow %s in %s for pull request #%d", expect.WorkflowFile, expect.Repository, expect.PullRequest)}
		}
	}
	return domain.Provenance{Checked: true, Detail: "no attestation for this plan matched the expected workflow, repository and pull request"}
}
