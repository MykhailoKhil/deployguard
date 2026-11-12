package web

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deployguard/deployguard/internal/domain"
	gh "github.com/deployguard/deployguard/internal/github"
	"github.com/deployguard/deployguard/internal/store"
)

// ---------- GitHub mode ----------

// historyGitHub is the shared fake with a configurable repository list.
type historyGitHub struct {
	testGitHub
	repos []gh.Repository
}

func (g *historyGitHub) ListRepositories(context.Context, string) ([]gh.Repository, error) {
	return g.repos, nil
}

type failingVerdicts struct{ store.Store }

func (failingVerdicts) RecordAnalysis(context.Context, store.Analysis) error {
	return errors.New("database down")
}
func (failingVerdicts) ListAnalysesForRepositories(context.Context, int64, []int64, int) ([]store.Analysis, error) {
	return nil, errors.New("database down")
}

func seed(t *testing.T, s store.Store, installation, repository int64, name string, pr int, at time.Time) {
	t.Helper()
	err := s.RecordAnalysis(context.Background(), store.Analysis{
		InstallationID: installation, RepositoryID: repository, RepositoryFullName: name, PullRequest: pr, HeadSHA: "abcdef1234567",
		Recommendation: "BLOCK", Level: "CRITICAL", Score: 75, CreatedAt: at,
		Findings: []store.FindingSummary{{RuleID: "rds-public-access", Severity: "CRITICAL"}},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func historyPage(t *testing.T, handler *Handler, sessionID string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/history", nil)
	if sessionID != "" {
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestHistoryListsOnlyVerdictsOfRepositoriesTheUserCanAccess(t *testing.T) {
	now := time.Now()
	verdicts := store.NewMemory()
	seed(t, verdicts, 3, 1, "acme/app", 2, now.Add(-2*time.Hour))
	seed(t, verdicts, 4, 20, "acme/other", 7, now.Add(-1*time.Hour))
	seed(t, verdicts, 3, 9, "acme/secret-repo", 5, now)   // same installation, a repository this user cannot access
	seed(t, verdicts, 77, 30, "elsewhere/hidden", 1, now) // an installation the user has no access to
	github := &historyGitHub{repos: []gh.Repository{
		{ID: 1, Name: "app", FullName: "acme/app", InstallationID: 3},
		{ID: 20, Name: "other", FullName: "acme/other", InstallationID: 4},
	}}
	handler := newTestHandler(t, github, &testAuthenticator{})
	handler.verdicts = verdicts
	response := historyPage(t, handler, createTestSession(t, handler))
	body := response.Body.String()
	if response.Code != http.StatusOK {
		t.Fatalf("status %d", response.Code)
	}
	for _, want := range []string{"acme/app #2", "acme/other #7", "/repositories/1/pull-requests", "rds-public-access (CRITICAL)", "abcdef1", "BLOCK", "75/100"} {
		if !strings.Contains(body, want) {
			t.Errorf("history page missing %q", want)
		}
	}
	for _, hidden := range []string{"secret-repo", "elsewhere/hidden"} {
		if strings.Contains(body, hidden) {
			t.Errorf("history page leaked %q, a repository or installation the user cannot access", hidden)
		}
	}
	if strings.Index(body, "acme/other #7") > strings.Index(body, "acme/app #2") {
		t.Error("newest verdict must come first")
	}
	assertThemePage(t, body)
}

func TestHistoryNeedsASignedInUser(t *testing.T) {
	handler := newTestHandler(t, &historyGitHub{}, &testAuthenticator{})
	handler.verdicts = store.NewMemory()
	anonymous := historyPage(t, handler, "")
	home := httptest.NewRecorder()
	handler.ServeHTTP(home, httptest.NewRequest(http.MethodGet, "/", nil))
	if anonymous.Code == http.StatusOK || anonymous.Code != home.Code || strings.Contains(anonymous.Body.String(), "Verdict history") {
		t.Fatalf("history for an anonymous visitor: %d (home gives %d)", anonymous.Code, home.Code)
	}
}

func TestHistoryExplainsWhenItIsOffOrEmpty(t *testing.T) {
	handler := newTestHandler(t, &historyGitHub{}, &testAuthenticator{})
	session := createTestSession(t, handler)
	if off := historyPage(t, handler, session); off.Code != http.StatusOK || !strings.Contains(off.Body.String(), "History is off") || !strings.Contains(off.Body.String(), "DEPLOYGUARD_DATABASE_URL") {
		t.Errorf("no database: %d %s", off.Code, off.Body.String())
	}
	handler.verdicts = store.NewMemory()
	handler.github = &historyGitHub{repos: []gh.Repository{{ID: 1, FullName: "acme/app", InstallationID: 3}}}
	if empty := historyPage(t, handler, session); empty.Code != http.StatusOK || !strings.Contains(empty.Body.String(), "No verdicts yet") {
		t.Errorf("empty history: %d", empty.Code)
	}
}

func TestHistoryEscapesRepositoryNamesAndReportsStoreFailures(t *testing.T) {
	verdicts := store.NewMemory()
	seed(t, verdicts, 3, 1, `evil/<img src=x onerror=alert(1)>`, 2, time.Now())
	handler := newTestHandler(t, &historyGitHub{repos: []gh.Repository{{ID: 1, FullName: "evil/x", InstallationID: 3}}}, &testAuthenticator{})
	handler.verdicts = verdicts
	session := createTestSession(t, handler)
	if body := historyPage(t, handler, session).Body.String(); strings.Contains(body, "<img src=x") || !strings.Contains(body, "&lt;img") {
		t.Error("a repository name must be HTML-escaped")
	}
	handler.verdicts = failingVerdicts{}
	if response := historyPage(t, handler, session); response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "database down") {
		t.Errorf("a store failure is a 500 without internals: %d %s", response.Code, response.Body.String())
	}
}

func uploadReview(t *testing.T, handler *Handler, sessionID string) *httptest.ResponseRecorder {
	t.Helper()
	body, contentType := uploadBody(t, testCSRFToken(t, handler, sessionID), validPlanJSON)
	request := httptest.NewRequest(http.MethodPost, "/reviews", body)
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Origin", "https://deployguard.example")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestReviewsStartedOnTheSiteAreRecordedOncePerCommit(t *testing.T) {
	verdicts := store.NewMemory()
	handler := newTestHandler(t, &testGitHub{}, &testAuthenticator{})
	handler.verdicts = verdicts
	session := createTestSession(t, handler)
	for i := 0; i < 2; i++ {
		if response := uploadReview(t, handler, session); response.Code != http.StatusOK {
			t.Fatalf("review %d: %d", i, response.Code)
		}
	}
	rows, err := verdicts.ListAnalyses(context.Background(), 3, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %+v err %v; the same commit analyzed twice is one row", rows, err)
	}
	row := rows[0]
	if row.RepositoryID != 1 || row.RepositoryFullName != "acme/repo" || row.PullRequest != 2 || row.HeadSHA != "head-sha" || row.Recommendation != "SAFE" {
		t.Errorf("recorded row %+v", row)
	}
}

func TestAStorageFailureNeverBreaksAReview(t *testing.T) {
	handler := newTestHandler(t, &testGitHub{}, &testAuthenticator{})
	handler.verdicts = failingVerdicts{}
	response := uploadReview(t, handler, createTestSession(t, handler))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Analysis") {
		t.Fatalf("the review must still be shown: %d", response.Code)
	}
}

// ---------- local mode ----------

func localUpload(t *testing.T, handler http.Handler, file string) *httptest.ResponseRecorder {
	t.Helper()
	plan, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	part, _ := form.CreateFormFile("plan", "tfplan.json")
	_, _ = io.Copy(part, bytes.NewReader(plan))
	_ = form.Close()
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/analyze", &body)
	request.Header.Set("Content-Type", form.FormDataContentType())
	request.Header.Set("Origin", "http://127.0.0.1:8080")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func newLocalWithHistory(t *testing.T) (http.Handler, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "deployguard", "history.jsonl")
	history, err := store.OpenFileHistory(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	return NewLocalHandlerWithHistory("127.0.0.1:8080", nil, history), path
}

func TestLocalUploadsAreRecordedAndListedWithoutThePlan(t *testing.T) {
	handler, path := newLocalWithHistory(t)
	for _, file := range []string{"../../examples/tfplan.json", "../plan/testdata/redacted-plan.json"} {
		if response := localUpload(t, handler, file); response.Code != http.StatusOK {
			t.Fatalf("upload %s: %d", file, response.Code)
		}
	}
	page := get(handler, "http://127.0.0.1:8080/history")
	body := page.Body.String()
	if page.Code != http.StatusOK || strings.Count(body, "Local upload") != 2 || !strings.Contains(body, "rds-public-access (CRITICAL)") || !strings.Contains(body, "BLOCK") {
		t.Fatalf("history page: %d\n%s", page.Code, body)
	}
	newest, older := strings.Index(body, "75/100"), strings.Index(body, "100/100")
	if newest < 0 || older < 0 || newest > older {
		t.Errorf("the redacted fixture (75/100) was uploaded last, so it must be listed before the example (100/100): %d, %d", newest, older)
	}
	assertThemePage(t, body)
	raw, _ := os.ReadFile(path)
	for _, secret := range []string{"example_database", "aws_security_group", "prod-db", "cidr_blocks", "resource_changes"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("the history file must hold only the verdict, but contains %q", secret)
		}
	}
	if !strings.Contains(string(raw), "plan_sha256") || !strings.Contains(string(raw), "rds-public-access") {
		t.Errorf("history file should hold the plan fingerprint and rule IDs: %s", raw)
	}
}

func TestLocalHistoryIsOffWithoutAStoreAndTheServerStillWorks(t *testing.T) {
	handler := NewLocalHandler("127.0.0.1:8080", nil)
	if response := localUpload(t, handler, "../../examples/tfplan.json"); response.Code != http.StatusOK {
		t.Fatalf("upload without history: %d", response.Code)
	}
	page := get(handler, "http://127.0.0.1:8080/history")
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "History is off") {
		t.Errorf("history page without a store: %d", page.Code)
	}
}

type brokenHistory struct{}

func (brokenHistory) Add(store.LocalVerdict) error           { return errors.New("disk full") }
func (brokenHistory) List(int) ([]store.LocalVerdict, error) { return nil, errors.New("disk full") }

func TestLocalHistoryFailuresNeverBreakAnAnalysis(t *testing.T) {
	handler := NewLocalHandlerWithHistory("127.0.0.1:8080", nil, brokenHistory{})
	if response := localUpload(t, handler, "../../examples/tfplan.json"); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "BLOCK") {
		t.Fatalf("the analysis must still be shown: %d", response.Code)
	}
	page := get(handler, "http://127.0.0.1:8080/history")
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "could not be read") || strings.Contains(page.Body.String(), "disk full") {
		t.Errorf("an unreadable history is explained without internals: %d %s", page.Code, page.Body.String())
	}
}

func TestLocalHistoryKeepsTheHostAndOriginProtections(t *testing.T) {
	handler, _ := newLocalWithHistory(t)
	if response := get(handler, "http://evil.example:8080/history"); response.Code != http.StatusForbidden {
		t.Errorf("a wrong Host must be refused, got %d", response.Code)
	}
	post := httptest.NewRecorder()
	handler.ServeHTTP(post, httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/history", nil))
	if post.Code == http.StatusOK {
		t.Error("history is read-only")
	}
}

func TestHistoryPagesAreReachableFromTheNavigation(t *testing.T) {
	local, _ := newLocalWithHistory(t)
	if !strings.Contains(get(local, "http://127.0.0.1:8080/").Body.String(), `href="/history"`) {
		t.Error("the local home page must link to the history page")
	}
	handler := newTestHandler(t, &testGitHub{}, &testAuthenticator{})
	session := createTestSession(t, handler)
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if !strings.Contains(response.Body.String(), `href="/history"`) {
		t.Error("the repository page must link to the history page")
	}
}

var _ = domain.RecommendationSafe
