package web

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	gh "github.com/deployguard/deployguard/internal/github"
	"github.com/deployguard/deployguard/internal/risk"
)

func TestReviewHomeRedirectsWithoutSession(t *testing.T) {
	handler := newTestHandler(t, &testGitHub{}, &testAuthenticator{})
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/auth/github" {
		t.Fatalf("response = %d, Location %q", response.Code, response.Header().Get("Location"))
	}
}

func assertThemePage(t *testing.T, body string) {
	t.Helper()
	for _, expected := range []string{`<script src="/assets/theme.js"></script>`, `class="theme-toggle"`, `aria-label="Switch to light theme"`, ` hidden>`} {
		if !strings.Contains(body, expected) {
			t.Errorf("page missing %q", expected)
		}
	}
}

func TestThemeScriptServedInBothModes(t *testing.T) {
	for _, test := range []struct {
		name    string
		handler http.Handler
		url     string
	}{
		{"local", NewLocalHandler("127.0.0.1:8080", nil), "http://127.0.0.1:8080/assets/theme.js"},
		{"github", newTestHandler(t, &testGitHub{}, &testAuthenticator{}), "https://deployguard.example/assets/theme.js"},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			test.handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.url, nil))
			if response.Code != http.StatusOK || response.Body.String() != themeJS {
				t.Fatalf("unexpected asset response: %d", response.Code)
			}
			if got := response.Header().Get("Content-Type"); got != "text/javascript; charset=utf-8" {
				t.Errorf("content type = %q", got)
			}
			if got := response.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options = %q", got)
			}
		})
	}
}

func TestGitHubPagesIncludeThemeSwitch(t *testing.T) {
	handler := newTestHandler(t, &testGitHub{}, &testAuthenticator{})
	sessionID := createTestSession(t, handler)
	for _, path := range []string{"/", "/repositories/1/pull-requests"} {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, path, nil)
			request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d", response.Code)
			}
			assertThemePage(t, response.Body.String())
		})
	}
}

func TestSignInBindsOAuthStateToSecureCookie(t *testing.T) {
	handler := newTestHandler(t, &testGitHub{}, &testAuthenticator{})
	request := httptest.NewRequest(http.MethodGet, "/auth/github", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusFound || response.Header().Get("Location") == "" {
		t.Fatalf("response = %d, Location %q", response.Code, response.Header().Get("Location"))
	}
	var stateCookie *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == oauthStateCookieName {
			stateCookie = cookie
		}
	}
	if stateCookie == nil || !stateCookie.Secure || !stateCookie.HttpOnly || stateCookie.SameSite != http.SameSiteLaxMode || len(stateCookie.Value) != 64 {
		t.Fatalf("OAuth state cookie = %#v", stateCookie)
	}
}

func TestSignInCallbackRejectsMissingStateCookie(t *testing.T) {
	handler := newTestHandler(t, &testGitHub{}, &testAuthenticator{})
	request := httptest.NewRequest(http.MethodGet, "/auth/github/callback?code=code&state="+strings.Repeat("a", 64), nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("response = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestLogoutRequiresCSRFAndRevokesSession(t *testing.T) {
	handler := newTestHandler(t, &testGitHub{}, &testAuthenticator{})
	sessionID := createTestSession(t, handler)
	csrfToken := testCSRFToken(t, handler, sessionID)
	request := httptest.NewRequest(http.MethodPost, "/auth/logout", strings.NewReader("csrf_token="+url.QueryEscape(csrfToken)))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "https://deployguard.example")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("response = %d, body = %q", response.Code, response.Body.String())
	}
	if _, ok := handler.sessions.Get(sessionID); ok {
		t.Fatal("logout did not revoke session")
	}
}

func TestReviewUploadAnalyzesVerifiedPullRequest(t *testing.T) {
	github := &testGitHub{}
	handler := newTestHandler(t, github, &testAuthenticator{})
	sessionID := createTestSession(t, handler)
	csrfToken := testCSRFToken(t, handler, sessionID)
	body, contentType := uploadBody(t, csrfToken, validPlanJSON)
	request := httptest.NewRequest(http.MethodPost, "/reviews", body)
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Origin", "https://deployguard.example")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Analysis") {
		t.Fatalf("response = %d, body = %q", response.Code, response.Body.String())
	}
	assertThemePage(t, response.Body.String())
	if github.verifyCalls != 2 {
		t.Fatalf("VerifyReview calls = %d, want initial and final head checks", github.verifyCalls)
	}
}

func TestReviewUploadRejectsBinaryPlanAndInvalidCSRF(t *testing.T) {
	tests := []struct {
		name       string
		plan       string
		csrf       string
		wantStatus int
	}{
		{name: "binary plan", plan: "binary-tfplan", csrf: "csrf-token", wantStatus: http.StatusUnprocessableEntity},
		{name: "invalid csrf", plan: validPlanJSON, csrf: "wrong-token", wantStatus: http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := newTestHandler(t, &testGitHub{}, &testAuthenticator{})
			sessionID := createTestSession(t, handler)
			csrfToken := testCSRFToken(t, handler, sessionID)
			if test.csrf == "csrf-token" {
				test.csrf = csrfToken
			}
			body, contentType := uploadBody(t, test.csrf, test.plan)
			request := httptest.NewRequest(http.MethodPost, "/reviews", body)
			request.Header.Set("Content-Type", contentType)
			request.Header.Set("Origin", "https://deployguard.example")
			request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("response = %d, want %d: %s", response.Code, test.wantStatus, response.Body.String())
			}
		})
	}
}

func TestReviewUploadRejectsOversizedRequest(t *testing.T) {
	handler := newTestHandler(t, &testGitHub{}, &testAuthenticator{})
	handler.maxRequestBytes = 512
	sessionID := createTestSession(t, handler)
	csrfToken := testCSRFToken(t, handler, sessionID)
	body, contentType := uploadBody(t, csrfToken, validPlanJSON)
	request := httptest.NewRequest(http.MethodPost, "/reviews", body)
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Origin", "https://deployguard.example")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("response = %d, want %d", response.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestReviewUploadPropagatesPlanSizeLimit(t *testing.T) {
	handler := newTestHandler(t, &testGitHub{}, &testAuthenticator{})
	handler.maxPlanBytes = 16
	sessionID := createTestSession(t, handler)
	csrfToken := testCSRFToken(t, handler, sessionID)
	body, contentType := uploadBody(t, csrfToken, validPlanJSON)
	request := httptest.NewRequest(http.MethodPost, "/reviews", body)
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Origin", "https://deployguard.example")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("response = %d, want %d", response.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestReviewUploadRejectsChangedPullRequestHead(t *testing.T) {
	github := &testGitHub{changeHeadAfterFirstVerification: true}
	handler := newTestHandler(t, github, &testAuthenticator{})
	sessionID := createTestSession(t, handler)
	csrfToken := testCSRFToken(t, handler, sessionID)
	body, contentType := uploadBody(t, csrfToken, validPlanJSON)
	request := httptest.NewRequest(http.MethodPost, "/reviews", body)
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Origin", "https://deployguard.example")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("response = %d, want %d: %s", response.Code, http.StatusConflict, response.Body.String())
	}
}

func TestReviewFormShowsDirectUploadAndOptionalActionsSeparately(t *testing.T) {
	handler := newTestHandler(t, &testGitHub{}, &testAuthenticator{})
	sessionID := createTestSession(t, handler)
	request := httptest.NewRequest(http.MethodGet, "/repositories/1/pull-requests", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Upload existing Terraform JSON plan") || strings.Contains(response.Body.String(), "Use GitHub Actions plan") {
		t.Fatalf("unconfigured Actions page response = %d, body = %q", response.Code, response.Body.String())
	}

	handler.workflowFilename = "deployguard.yml"
	handler.artifactName = "deployguard-plan"
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Use GitHub Actions plan") {
		t.Fatalf("configured Actions page response = %d, body = %q", response.Code, response.Body.String())
	}
}

const validPlanJSON = `{"format_version":"1.2","resource_changes":[]}`

type testAuthenticator struct{}

func (*testAuthenticator) BeginAuthorization() (string, string, error) {
	return "https://github.com/login/oauth/authorize", strings.Repeat("a", 64), nil
}
func (*testAuthenticator) ConsumeState(state string) bool { return len(state) == 64 }
func (*testAuthenticator) CompleteAuthorization(context.Context, string, string) (gh.GitHubUser, string, error) {
	return gh.GitHubUser{ID: 1, Login: "user"}, "user-token", nil
}

type testGitHub struct {
	verifyCalls                      int
	changeHeadAfterFirstVerification bool
}

func (*testGitHub) ListRepositories(context.Context, string) ([]gh.Repository, error) {
	return []gh.Repository{{ID: 1, Name: "repo", FullName: "acme/repo"}}, nil
}
func (*testGitHub) ListPullRequests(context.Context, string, int64) (gh.Repository, []gh.PullRequest, error) {
	return gh.Repository{ID: 1, Name: "repo", FullName: "acme/repo"}, []gh.PullRequest{{Number: 2, Title: "change", HeadSHA: "head-sha"}}, nil
}
func (g *testGitHub) VerifyReview(context.Context, string, int64, int) (gh.VerifiedReview, error) {
	g.verifyCalls++
	headSHA := "head-sha"
	if g.changeHeadAfterFirstVerification && g.verifyCalls > 1 {
		headSHA = "changed-head"
	}
	return gh.VerifiedReview{
		Repository:     gh.Repository{ID: 1, Name: "repo", FullName: "acme/repo"},
		PullRequest:    gh.PullRequest{Number: 2, Title: "change", HeadSHA: headSHA},
		InstallationID: 3,
	}, nil
}
func (*testGitHub) DownloadPlanArtifact(context.Context, gh.VerifiedReview, gh.PlanArtifactConfig) ([]byte, error) {
	return []byte(validPlanJSON), nil
}

func newTestHandler(t *testing.T, client GitHubClient, authenticator GitHubAuthenticator) *Handler {
	t.Helper()
	handler, err := NewHandler(Config{
		PublicOrigin: "https://deployguard.example",
		Auth:         authenticator,
		GitHub:       client,
		Sessions:     gh.NewSessionStore(0),
		RiskEngine:   risk.NewEngine(risk.Config{}),
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	return handler
}

func createTestSession(t *testing.T, handler *Handler) string {
	t.Helper()
	sessionID, err := handler.sessions.Create(gh.GitHubUser{ID: 1, Login: "user"}, "user-token")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	return sessionID
}

func testCSRFToken(t *testing.T, handler *Handler, sessionID string) string {
	t.Helper()
	session, ok := handler.sessions.Get(sessionID)
	if !ok {
		t.Fatal("created session is not available")
	}
	return session.CSRFToken
}

func uploadBody(t *testing.T, csrf, plan string) (io.Reader, string) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for key, value := range map[string]string{
		"source": "upload", "csrf_token": csrf,
		"repository_id": "1", "pull_request_number": "2",
	} {
		if err := writer.WriteField(key, value); err != nil {
			t.Fatalf("WriteField(%q) error = %v", key, err)
		}
	}
	file, err := writer.CreateFormFile("plan", "tfplan.json")
	if err != nil {
		t.Fatalf("CreateFormFile() error = %v", err)
	}
	if _, err := io.Copy(file, strings.NewReader(plan)); err != nil {
		t.Fatalf("write upload = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	return bytes.NewReader(body.Bytes()), writer.FormDataContentType()
}
