package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const (
	maxAttestations   = 20
	maxBundleBytes    = 1 << 20
	attestationsLimit = 30
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// FetchAttestations returns the attestation bundles (JSON) GitHub stores for a plan whose SHA-256 is
// digestHex. It needs the App permission "Attestations: read". Having no attestations is not an
// error: it returns an empty list. The bundles are untrusted until verified.
func (c *ReviewClient) FetchAttestations(ctx context.Context, review VerifiedReview, digestHex string) ([][]byte, error) {
	if !digestPattern.MatchString(digestHex) {
		return nil, errors.New("digest must be 64 lowercase hex characters")
	}
	repositoryPath := pathRepository(review.Repository.FullName)
	if repositoryPath == "" || review.Repository.ID <= 0 || review.InstallationID <= 0 || strings.ContainsAny(review.Repository.FullName, "?#\\") {
		return nil, errors.New("verified review is required")
	}
	token, err := c.app.InstallationTokenForRepository(ctx, review.InstallationID, review.Repository.ID)
	if err != nil {
		return nil, errors.New("authenticate GitHub attestation request")
	}
	endpoint := c.apiURL(fmt.Sprintf("/repos/%s/attestations/sha256:%s?per_page=%d", repositoryPath, digestHex, attestationsLimit))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, errors.New("create GitHub attestation request")
	}
	setGitHubHeaders(request, token.Token)
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, errors.New("load GitHub attestations")
	}
	if response.StatusCode == http.StatusNotFound {
		response.Body.Close()
		return nil, nil
	}
	var payload struct {
		Attestations []struct {
			Bundle    json.RawMessage `json:"bundle"`
			BundleURL string          `json:"bundle_url"`
		} `json:"attestations"`
	}
	if err := decodeGitHubResponse(response, http.StatusOK, &payload); err != nil {
		return nil, errors.New("load GitHub attestations")
	}
	var bundles [][]byte
	for _, item := range payload.Attestations {
		if len(bundles) == maxAttestations {
			break
		}
		switch {
		case len(item.Bundle) > 2 && string(item.Bundle) != "null" && len(item.Bundle) <= maxBundleBytes: // an inline bundle, not null or {}
			bundles = append(bundles, []byte(item.Bundle))
		case item.BundleURL != "":
			if raw, err := c.downloadBundle(ctx, item.BundleURL); err == nil {
				bundles = append(bundles, raw)
			}
		}
	}
	return bundles, nil
}

// downloadBundle fetches a bundle from the URL GitHub returned. The installation token is NOT sent:
// the URL points at storage, not the GitHub API.
func (c *ReviewClient) downloadBundle(ctx context.Context, rawURL string) ([]byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return nil, errors.New("bundle URL must be HTTPS")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, errors.New("download attestation bundle")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("download attestation bundle")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxBundleBytes+1))
	if err != nil || len(raw) > maxBundleBytes {
		return nil, errors.New("attestation bundle is too large")
	}
	return raw, nil
}
