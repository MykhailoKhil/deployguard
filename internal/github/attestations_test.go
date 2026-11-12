package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"strings"
	"testing"
)

func newAttestationClient(t *testing.T, handler func(*http.Request) *http.Response) *ReviewClient {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/app/installations/42/access_tokens" {
			return response(http.StatusCreated, `{"token":"installation-token","expires_at":"2030-01-01T00:00:00Z"}`), nil
		}
		return handler(r), nil
	})}
	app, err := NewAppAuthenticator(AppAuthenticatorConfig{AppID: 9, PrivateKeyPEM: privateKeyPEM(key), APIBaseURL: "https://api.github.test", HTTPClient: httpClient})
	if err != nil {
		t.Fatal(err)
	}
	reviews, err := NewReviewClient(ReviewClientConfig{APIBaseURL: "https://api.github.test", App: app, HTTPClient: httpClient})
	if err != nil {
		t.Fatal(err)
	}
	return reviews
}

var attestedReview = VerifiedReview{Repository: Repository{ID: 7, Name: "repo", FullName: "acme/repo"}, PullRequest: PullRequest{Number: 3, HeadSHA: "abc1234"}, InstallationID: 42}

const goodDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestFetchAttestationsReturnsInlineAndLinkedBundles(t *testing.T) {
	var linkedAuth string
	reviews := newAttestationClient(t, func(r *http.Request) *http.Response {
		switch r.URL.Host + r.URL.Path {
		case "api.github.test/repos/acme/repo/attestations/sha256:" + goodDigest:
			if r.URL.Query().Get("per_page") == "" || r.Header.Get("Authorization") != "Bearer installation-token" {
				t.Errorf("lookup request wrong: %s %v", r.URL, r.Header)
			}
			return response(http.StatusOK, `{"attestations":[
				{"bundle":{"mediaType":"inline"}},
				{"bundle_url":"https://blobs.example.test/b1"},
				{"bundle_url":"http://insecure.example.test/b2"},
				{"bundle":null}]}`)
		case "blobs.example.test/b1":
			linkedAuth = r.Header.Get("Authorization")
			return response(http.StatusOK, `{"mediaType":"linked"}`)
		}
		t.Errorf("unexpected request %s%s", r.URL.Host, r.URL.Path)
		return response(http.StatusNotFound, "")
	})
	bundles, err := reviews.FetchAttestations(context.Background(), attestedReview, goodDigest)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundles) != 2 || !strings.Contains(string(bundles[0]), "inline") || !strings.Contains(string(bundles[1]), "linked") {
		t.Fatalf("bundles = %q; want the inline and the HTTPS-linked one, not the HTTP or null ones", bundles)
	}
	if linkedAuth != "" {
		t.Error("the installation token must not be sent to the bundle storage host")
	}
}

func TestFetchAttestationsTreatsNotFoundAsNone(t *testing.T) {
	reviews := newAttestationClient(t, func(*http.Request) *http.Response { return response(http.StatusNotFound, `{}`) })
	bundles, err := reviews.FetchAttestations(context.Background(), attestedReview, goodDigest)
	if err != nil || len(bundles) != 0 {
		t.Fatalf("404 must mean no attestations, got %v, %v", bundles, err)
	}
}

func TestFetchAttestationsReportsAPIFailuresAndRejectsBadInput(t *testing.T) {
	failing := newAttestationClient(t, func(*http.Request) *http.Response { return response(http.StatusForbidden, `{}`) })
	if _, err := failing.FetchAttestations(context.Background(), attestedReview, goodDigest); err == nil {
		t.Error("a 403 (for example a missing permission) must be an error, not silence")
	}
	unused := newAttestationClient(t, func(*http.Request) *http.Response {
		t.Error("no request expected")
		return response(http.StatusInternalServerError, "")
	})
	for name, digest := range map[string]string{"short": "abc", "uppercase": strings.ToUpper(goodDigest), "path trick": "../" + goodDigest[3:]} {
		if _, err := unused.FetchAttestations(context.Background(), attestedReview, digest); err == nil {
			t.Errorf("%s digest accepted", name)
		}
	}
	bad := attestedReview
	bad.Repository.FullName = "nope?x=1"
	if _, err := unused.FetchAttestations(context.Background(), bad, goodDigest); err == nil {
		t.Error("a malformed repository name must be rejected")
	}
}
