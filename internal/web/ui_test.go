package web

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/deployguard/deployguard/internal/domain"
	gh "github.com/deployguard/deployguard/internal/github"
)

func TestResponsesCarrySecurityHeaders(t *testing.T) {
	handler := newTestHandler(t, &testGitHub{}, &testAuthenticator{})
	for _, path := range []string{"/", "/missing", "/signed-out"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		for header, want := range map[string]string{
			"X-Content-Type-Options": "nosniff",
			"X-Frame-Options":        "DENY",
			"Referrer-Policy":        "same-origin",
		} {
			if got := response.Header().Get(header); got != want {
				t.Errorf("%s %s = %q, want %q", path, header, got, want)
			}
		}
		policy := response.Header().Get("Content-Security-Policy")
		if !strings.Contains(policy, "frame-ancestors 'none'") || strings.Contains(policy, "'unsafe-inline'") {
			t.Errorf("%s unexpected content security policy %q", path, policy)
		}
	}
}

func TestErrorsRenderAsStyledPages(t *testing.T) {
	handler := newTestHandler(t, &testGitHub{}, &testAuthenticator{})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/missing", nil))
	body := response.Body.String()
	if response.Code != http.StatusNotFound || !strings.Contains(body, "Page not found") || !strings.Contains(body, `href="/"`) {
		t.Fatalf("response = %d, body = %q", response.Code, body)
	}
	assertThemePage(t, body)
	if !strings.Contains(response.Header().Get("Content-Type"), "text/html") {
		t.Errorf("content type = %q", response.Header().Get("Content-Type"))
	}
}

func TestLogoutLandsOnSignedOutPage(t *testing.T) {
	handler := newTestHandler(t, &testGitHub{}, &testAuthenticator{})
	sessionID := createTestSession(t, handler)
	csrfToken := testCSRFToken(t, handler, sessionID)
	request := httptest.NewRequest(http.MethodPost, "/auth/logout", strings.NewReader("csrf_token="+url.QueryEscape(csrfToken)))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "https://deployguard.example")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Header().Get("Location") != "/signed-out" {
		t.Fatalf("Location = %q", response.Header().Get("Location"))
	}
	page := httptest.NewRecorder()
	handler.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/signed-out", nil))
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "signed out") {
		t.Fatalf("signed-out page = %d %q", page.Code, page.Body.String())
	}
}

func TestSignInIsRateLimitedPerClient(t *testing.T) {
	handler := newTestHandler(t, &testGitHub{}, &testAuthenticator{})
	var last int
	for i := 0; i < 40; i++ {
		request := httptest.NewRequest(http.MethodGet, "/auth/github", nil)
		request.RemoteAddr = "203.0.113.5:4000"
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		last = response.Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("status after burst = %d, want 429", last)
	}
	other := httptest.NewRequest(http.MethodGet, "/auth/github", nil)
	other.RemoteAddr = "203.0.113.6:4000"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, other)
	if response.Code != http.StatusFound {
		t.Fatalf("a different client was limited: %d", response.Code)
	}
}

func TestForwardedHeaderIsIgnoredUnlessConfigured(t *testing.T) {
	handler := newTestHandler(t, &testGitHub{}, &testAuthenticator{})
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "198.51.100.1:1000"
	request.Header.Set("X-Forwarded-For", "10.0.0.1")
	if got := handler.clientIP(request); got != "198.51.100.1" {
		t.Fatalf("clientIP() = %q, forged header must be ignored by default", got)
	}
	handler.trustedProxyHeader = "X-Forwarded-For"
	request.Header.Set("X-Forwarded-For", "10.9.9.9, 192.0.2.77")
	if got := handler.clientIP(request); got != "192.0.2.77" {
		t.Fatalf("clientIP() = %q, want the right-most (proxy-appended) address", got)
	}
	request.Header.Set("X-Forwarded-For", "not-an-ip")
	if got := handler.clientIP(request); got != "198.51.100.1" {
		t.Fatalf("clientIP() = %q, want fallback to the peer address", got)
	}
}

func TestReviewRejectsWhenAllAnalysisSlotsAreBusy(t *testing.T) {
	handler := newTestHandler(t, &testGitHub{}, &testAuthenticator{})
	sessionID := createTestSession(t, handler)
	csrfToken := testCSRFToken(t, handler, sessionID)
	for i := 0; i < cap(handler.reviewSlots); i++ {
		handler.reviewSlots <- struct{}{}
	}
	body, contentType := uploadBody(t, csrfToken, validPlanJSON)
	request := httptest.NewRequest(http.MethodPost, "/reviews", body)
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Origin", "https://deployguard.example")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") == "" {
		t.Fatalf("response = %d, Retry-After %q", response.Code, response.Header().Get("Retry-After"))
	}
}

type forkGitHub struct{ testGitHub }

func (*forkGitHub) ListPullRequests(context.Context, string, int64) (gh.Repository, []gh.PullRequest, error) {
	return gh.Repository{ID: 1, Name: "repo", FullName: "acme/repo"}, []gh.PullRequest{{Number: 2, Title: "from a fork", HeadSHA: "0123456789abcdef0123456789abcdef01234567", Fork: true}}, nil
}

func TestPullRequestPageShowsShortSHAAndForkLimits(t *testing.T) {
	handler := newTestHandler(t, &forkGitHub{}, &testAuthenticator{})
	handler.workflowFilename, handler.artifactName = "plan.yml", "plan"
	sessionID := createTestSession(t, handler)
	request := httptest.NewRequest(http.MethodGet, "/repositories/1/pull-requests", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	body := response.Body.String()
	for _, want := range []string{">0123456<", "Fork · upload only", `data-busy-label=`} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
	if strings.Contains(body, "Use GitHub Actions plan") {
		t.Error("fork pull requests must not offer an Actions plan")
	}
}

func TestResultPageNoticeDependsOnPlanSource(t *testing.T) {
	handler := newTestHandler(t, &testGitHub{}, &testAuthenticator{})
	for source, want := range map[string]string{"upload": "not cryptographically attested", "actions": "pull request author can edit that workflow"} {
		var buffer bytes.Buffer
		data := pageData{User: "user", PlanSource: source, Analysis: &domain.Analysis{Recommendation: domain.RecommendationSafe, Level: domain.RiskLow}}
		if err := handler.templates.ExecuteTemplate(&buffer, "result", data); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buffer.String(), want) {
			t.Errorf("%s result page missing %q", source, want)
		}
	}
}

func TestAnalysisTemplateLeadsWithVerdictAndSortsFindingsBySeverity(t *testing.T) {
	handler := newTestHandler(t, &testGitHub{}, &testAuthenticator{})
	analysis := domain.Analysis{
		Score: 72, Level: domain.RiskHigh, Recommendation: domain.RecommendationBlock, Explanation: "Two findings.",
		Findings: []domain.Finding{
			{Severity: domain.SeverityLow, Summary: "minor tag drift", Remediation: "tag it"},
			{Severity: domain.SeverityCritical, Summary: "database deleted", Remediation: "keep it"},
		},
	}
	var buffer bytes.Buffer
	if err := handler.templates.ExecuteTemplate(&buffer, "analysis", &analysis); err != nil {
		t.Fatal(err)
	}
	html := buffer.String()
	if !strings.Contains(html, "verdict-BLOCK") || !strings.Contains(html, "Do not apply yet") {
		t.Errorf("verdict banner missing: %s", html)
	}
	if strings.Index(html, "database deleted") > strings.Index(html, "minor tag drift") {
		t.Error("critical finding must be listed before the low finding")
	}
	if !strings.Contains(html, "1 CRITICAL") || !strings.Contains(html, "1 LOW") {
		t.Error("severity count chips missing")
	}
	if analysis.Findings[0].Severity != domain.SeverityLow {
		t.Error("rendering must not reorder the caller's findings")
	}
}

func TestNextStepsRenderWithAndWithoutAI(t *testing.T) {
	handler := newTestHandler(t, &testGitHub{}, &testAuthenticator{})
	render := func(aiText string) string {
		analysis := domain.Analysis{
			Score: 72, Level: domain.RiskHigh, Recommendation: domain.RecommendationBlock, Explanation: "Two findings.", AIExplanation: aiText,
			Findings: []domain.Finding{
				{Severity: domain.SeverityLow, Summary: "minor tag drift", Remediation: "tag it"},
				{Severity: domain.SeverityCritical, Summary: "database deleted", Remediation: "keep it"},
			},
		}
		var buffer bytes.Buffer
		if err := handler.templates.ExecuteTemplate(&buffer, "analysis", &analysis); err != nil {
			t.Fatal(err)
		}
		return buffer.String()
	}
	plain := render("")
	if strings.Contains(plain, "ai-note") || strings.Count(plain, "Next step:") != 2 {
		t.Errorf("non-AI page must show both deterministic next steps and no AI block: %s", plain)
	}
	withAI := render("Database at risk.\nNext step: keep it.\n<script>alert(1)</script>")
	if strings.Count(withAI, `<p class="next-step"><strong>Next step:</strong>`) != 2 || !strings.Contains(withAI, "ai-note") {
		t.Error("AI mode must keep deterministic next steps and add the AI block")
	}
	if !strings.Contains(withAI, "Next step: keep it.") || strings.Contains(withAI, "<script>alert(1)</script>") {
		t.Error("AI text must be shown with its line structure and HTML-escaped")
	}
}

func TestResultPageShowsProvenanceAndDropsTheGenericUnattestedNotice(t *testing.T) {
	handler := newTestHandler(t, &testGitHub{}, &testAuthenticator{})
	render := func(p domain.Provenance, source string) string {
		var buffer bytes.Buffer
		data := pageData{User: "user", PlanSource: source, Analysis: &domain.Analysis{
			Recommendation: domain.RecommendationSafe, Level: domain.RiskLow, Explanation: "ok", Provenance: p,
		}}
		if err := handler.templates.ExecuteTemplate(&buffer, "result", data); err != nil {
			t.Fatal(err)
		}
		return buffer.String()
	}
	verified := render(domain.Provenance{Checked: true, Verified: true, Detail: "signed by workflow plan.yml"}, "upload")
	if !strings.Contains(verified, "Plan provenance verified.") || !strings.Contains(verified, "signed by workflow plan.yml") || strings.Contains(verified, "Plan provenance matters") {
		t.Errorf("verified page wrong: the unattested warning must go away")
	}
	unverified := render(domain.Provenance{Checked: true, Detail: "no attestation exists"}, "upload")
	if !strings.Contains(unverified, "Plan provenance not verified.") || !strings.Contains(unverified, "Plan provenance matters") {
		t.Error("an unverified plan keeps the warning and says it failed")
	}
	off := render(domain.Provenance{}, "actions")
	if strings.Contains(off, "Plan provenance verified") || strings.Contains(off, "Plan provenance not verified") || !strings.Contains(off, "Plan from your CI workflow") {
		t.Error("with checking off the page is unchanged")
	}
}
