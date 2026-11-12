package github

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestExtractPlanJSONAcceptsOnlyTheExpectedSingleEntry(t *testing.T) {
	archive := makeZip(t, "tfplan.json")
	plan, err := extractPlanJSON(archive, "tfplan.json")
	if err != nil {
		t.Fatalf("extractPlanJSON() error = %v", err)
	}
	if string(plan) != `{"format_version":"1.2"}` {
		t.Fatalf("plan = %q", plan)
	}
}

func TestExtractPlanJSONRejectsUnexpectedArchiveEntries(t *testing.T) {
	tests := []struct {
		name  string
		files []string
	}{
		{name: "unexpected filename", files: []string{"plan.json"}},
		{name: "extra file", files: []string{"tfplan.json", "README.txt"}},
		{name: "traversal path", files: []string{"../tfplan.json"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			archive := makeZip(t, test.files...)
			if _, err := extractPlanJSON(archive, "tfplan.json"); err == nil {
				t.Fatal("extractPlanJSON() accepted an unexpected archive")
			}
		})
	}
}

func TestVerifyReviewChecksUserAccessInstallationAndPullRequest(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/repositories/7":
			if request.Header.Get("Authorization") != "Bearer user-token" {
				t.Errorf("repository request authorization = %q", request.Header.Get("Authorization"))
			}
			return response(http.StatusOK, `{"id":7,"name":"repo","full_name":"acme/repo"}`), nil
		case "/repos/acme/repo/installation":
			if !strings.HasPrefix(request.Header.Get("Authorization"), "Bearer ") {
				t.Errorf("installation request authorization missing")
			}
			return response(http.StatusOK, `{"id":42}`), nil
		case "/app/installations/42/access_tokens":
			body, err := io.ReadAll(request.Body)
			if err != nil || string(body) != `{"repository_ids":[7]}` {
				t.Errorf("installation token request body = %q, err=%v", body, err)
			}
			return response(http.StatusCreated, `{"token":"installation-token","expires_at":"2030-01-01T00:00:00Z"}`), nil
		case "/repos/acme/repo/pulls/3":
			if request.Header.Get("Authorization") != "Bearer user-token" {
				t.Errorf("pull request authorization = %q", request.Header.Get("Authorization"))
			}
			return response(http.StatusOK, `{"number":3,"title":"update","state":"open","head":{"sha":"abc123","repo":{"id":7}},"base":{"repo":{"id":7}}}`), nil
		default:
			t.Errorf("unexpected GitHub request %s", request.URL)
			return response(http.StatusNotFound, ""), nil
		}
	})}
	app, err := NewAppAuthenticator(AppAuthenticatorConfig{AppID: 9, PrivateKeyPEM: privateKeyPEM(key), APIBaseURL: "https://api.github.test", HTTPClient: client})
	if err != nil {
		t.Fatalf("NewAppAuthenticator() error = %v", err)
	}
	reviews, err := NewReviewClient(ReviewClientConfig{APIBaseURL: "https://api.github.test", App: app, HTTPClient: client})
	if err != nil {
		t.Fatalf("NewReviewClient() error = %v", err)
	}
	review, err := reviews.VerifyReview(context.Background(), "user-token", 7, 3)
	if err != nil {
		t.Fatalf("VerifyReview() error = %v", err)
	}
	if review.Repository.FullName != "acme/repo" || review.PullRequest.HeadSHA != "abc123" || review.InstallationID != 42 {
		t.Fatalf("VerifyReview() = %#v", review)
	}
}

func TestVerifyReviewIdentifiesForkPullRequests(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/repositories/7":
			return response(http.StatusOK, `{"id":7,"name":"repo","full_name":"acme/repo"}`), nil
		case "/repos/acme/repo/installation":
			return response(http.StatusOK, `{"id":42}`), nil
		case "/app/installations/42/access_tokens":
			return response(http.StatusCreated, `{"token":"installation-token","expires_at":"2030-01-01T00:00:00Z"}`), nil
		case "/repos/acme/repo/pulls/3":
			return response(http.StatusOK, `{"number":3,"title":"update","state":"open","head":{"sha":"abc123","repo":{"id":8}},"base":{"repo":{"id":7}}}`), nil
		default:
			return response(http.StatusNotFound, ""), nil
		}
	})}
	app, err := NewAppAuthenticator(AppAuthenticatorConfig{AppID: 9, PrivateKeyPEM: privateKeyPEM(key), APIBaseURL: "https://api.github.test", HTTPClient: client})
	if err != nil {
		t.Fatalf("NewAppAuthenticator() error = %v", err)
	}
	reviews, err := NewReviewClient(ReviewClientConfig{APIBaseURL: "https://api.github.test", App: app, HTTPClient: client})
	if err != nil {
		t.Fatalf("NewReviewClient() error = %v", err)
	}
	review, err := reviews.VerifyReview(context.Background(), "user-token", 7, 3)
	if err != nil {
		t.Fatalf("VerifyReview() error = %v", err)
	}
	if !review.PullRequest.Fork {
		t.Fatal("VerifyReview() did not preserve the fork PR status")
	}
	if _, err := reviews.DownloadPlanArtifact(context.Background(), review, PlanArtifactConfig{WorkflowFilename: "deployguard.yml", ArtifactName: "plan"}); !errors.Is(err, ErrGitHubAccessDenied) {
		t.Fatalf("DownloadPlanArtifact() error = %v, want fork access denied", err)
	}
}

func TestWorkflowPathMatchesConfiguredWorkflowOnly(t *testing.T) {
	tests := []struct {
		actual, configured string
		want               bool
	}{
		{actual: ".github/workflows/deployguard.yml", configured: "deployguard.yml", want: true},
		{actual: ".github/workflows/deployguard.yml@refs/heads/main", configured: ".github/workflows/deployguard.yml", want: true},
		{actual: ".github/workflows/other.yml", configured: "deployguard.yml", want: false},
	}
	for _, test := range tests {
		if got := workflowPathMatches(test.actual, test.configured); got != test.want {
			t.Errorf("workflowPathMatches(%q, %q) = %v, want %v", test.actual, test.configured, got, test.want)
		}
	}
}

func TestDownloadArtifactRejectsURLsOutsideConfiguredOrigin(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	app, err := NewAppAuthenticator(AppAuthenticatorConfig{AppID: 9, PrivateKeyPEM: privateKeyPEM(key), APIBaseURL: "https://api.github.test"})
	if err != nil {
		t.Fatalf("NewAppAuthenticator() error = %v", err)
	}
	reviews, err := NewReviewClient(ReviewClientConfig{APIBaseURL: "https://api.github.test", App: app})
	if err != nil {
		t.Fatalf("NewReviewClient() error = %v", err)
	}
	for _, target := range []string{"https://attacker.example/file", "http://api.github.test/file", "https://api.github.test.evil.example/file", "https://api.github.test@attacker.example/file"} {
		if _, err := reviews.download(context.Background(), "secret-token", target, 1024); err == nil {
			t.Errorf("download(%q) unexpectedly accepted an external URL", target)
		}
	}
}

func makeZip(t *testing.T, names ...string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, name := range names {
		file, err := writer.Create(name)
		if err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		if _, err := file.Write([]byte(`{"format_version":"1.2"}`)); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	return buffer.Bytes()
}

func newArtifactTestClient(t *testing.T, headRepositoryID int64, downloads *int) *ReviewClient {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	archive := makeZip(t, "tfplan.json")
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/app/installations/42/access_tokens":
			return response(http.StatusCreated, `{"token":"installation-token","expires_at":"2030-01-01T00:00:00Z"}`), nil
		case "/repos/acme/repo/actions/workflows/plan.yml/runs":
			return response(http.StatusOK, fmt.Sprintf(`{"total_count":1,"workflow_runs":[{"id":5,"status":"completed","conclusion":"success","event":"pull_request","head_sha":"sha1","path":".github/workflows/plan.yml","head_repository":{"id":%d},"created_at":"2026-01-01T00:00:00Z","pull_requests":[{"number":3}]}]}`, headRepositoryID)), nil
		case "/repos/acme/repo/actions/runs/5/artifacts":
			return response(http.StatusOK, `{"artifacts":[{"name":"deployguard-plan","expired":false,"size_in_bytes":100,"id":9}]}`), nil
		case "/repos/acme/repo/actions/artifacts/9/zip":
			*downloads++
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(archive)), ContentLength: int64(len(archive)), Header: http.Header{}}, nil
		}
		t.Errorf("unexpected request %s", request.URL.Path)
		return response(http.StatusNotFound, `{}`), nil
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

func TestDownloadPlanArtifactRequiresRunFromTheSameRepository(t *testing.T) {
	review := VerifiedReview{
		Repository:     Repository{ID: 7, Name: "repo", FullName: "acme/repo"},
		PullRequest:    PullRequest{Number: 3, HeadSHA: "sha1"},
		InstallationID: 42,
	}
	config := PlanArtifactConfig{WorkflowFilename: "plan.yml", ArtifactName: "deployguard-plan", PlanFilename: "tfplan.json"}

	downloads := 0
	if _, err := newArtifactTestClient(t, 99, &downloads).DownloadPlanArtifact(context.Background(), review, config); err == nil || downloads != 0 {
		t.Fatalf("run from another repository was accepted: err=%v downloads=%d", err, downloads)
	}
	if content, err := newArtifactTestClient(t, 7, &downloads).DownloadPlanArtifact(context.Background(), review, config); err != nil || len(content) == 0 || downloads != 1 {
		t.Fatalf("same-repository run rejected: err=%v downloads=%d", err, downloads)
	}
}

func newUserTokenClient(t *testing.T, handler func(*http.Request) *http.Response) *ReviewClient {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer user-token" {
			t.Errorf("request %s used authorization %q, want the user's token", r.URL, r.Header.Get("Authorization"))
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

func TestListRepositoriesUsesTheUserTokenEndpointsAcrossInstallationsAndPages(t *testing.T) {
	var paths []string
	reviews := newUserTokenClient(t, func(r *http.Request) *http.Response {
		paths = append(paths, r.URL.RequestURI())
		switch r.URL.Path {
		case "/user/installations":
			return response(http.StatusOK, `{"total_count":3,"installations":[
				{"id":10,"suspended_at":null},{"id":20,"suspended_at":"2026-01-01T00:00:00Z"},{"id":30}]}`)
		case "/user/installations/10/repositories":
			if r.URL.Query().Get("page") == "2" {
				return response(http.StatusOK, `{"repositories":[{"id":3,"name":"c","full_name":"acme/c"}]}`)
			}
			resp := response(http.StatusOK, `{"repositories":[{"id":2,"name":"b","full_name":"acme/b"},{"id":1,"name":"a","full_name":"acme/a"}]}`)
			resp.Header.Set("Link", `<https://api.github.test/user/installations/10/repositories?per_page=100&page=2>; rel="next"`)
			return resp
		case "/user/installations/30/repositories":
			return response(http.StatusOK, `{"repositories":[{"id":2,"name":"b","full_name":"acme/b"},{"id":4,"name":"d","full_name":"other/d"}]}`)
		}
		t.Errorf("unexpected request %s", r.URL)
		return response(http.StatusNotFound, `{}`)
	})
	repositories, err := reviews.ListRepositories(context.Background(), "user-token")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, repository := range repositories {
		names = append(names, repository.FullName)
	}
	if got := strings.Join(names, ","); got != "acme/a,acme/b,acme/c,other/d" {
		t.Fatalf("repositories = %s; want all four, deduplicated, sorted by name", got)
	}
	for _, path := range paths {
		if strings.Contains(path, "/installations/20/") || strings.Contains(path, "/user/repos") {
			t.Errorf("a suspended installation or the old /user/repos endpoint was used: %s", path)
		}
	}
}

func TestListRepositoriesWithoutInstallationsIsEmptyNotAnError(t *testing.T) {
	reviews := newUserTokenClient(t, func(*http.Request) *http.Response {
		return response(http.StatusOK, `{"total_count":0,"installations":[]}`)
	})
	repositories, err := reviews.ListRepositories(context.Background(), "user-token")
	if err != nil || len(repositories) != 0 {
		t.Fatalf("got %v, %v", repositories, err)
	}
}

func TestListRepositoriesFailsLoudlyAndNeverFollowsAForeignPaginationURL(t *testing.T) {
	denied := newUserTokenClient(t, func(*http.Request) *http.Response { return response(http.StatusForbidden, `{}`) })
	if _, err := denied.ListRepositories(context.Background(), "user-token"); err == nil {
		t.Error("a 403 must be an error, not an empty list that looks like 'nothing installed'")
	}
	if _, err := denied.ListRepositories(context.Background(), "  "); err == nil {
		t.Error("a blank token must be rejected without a request")
	}
	hostile := newUserTokenClient(t, func(r *http.Request) *http.Response {
		if r.URL.Host != "api.github.test" {
			t.Errorf("the user's token was sent to %s", r.URL.Host)
		}
		resp := response(http.StatusOK, `{"installations":[{"id":10}]}`)
		resp.Header.Set("Link", `<https://evil.example/steal?page=2>; rel="next"`)
		return resp
	})
	if _, err := hostile.ListRepositories(context.Background(), "user-token"); err == nil {
		t.Error("a pagination URL on another host must stop the listing")
	}
}
