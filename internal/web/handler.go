package web

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"html/template"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/deployguard/deployguard/internal/ai"
	"github.com/deployguard/deployguard/internal/domain"
	gh "github.com/deployguard/deployguard/internal/github"
	"github.com/deployguard/deployguard/internal/plan"
	"github.com/deployguard/deployguard/internal/risk"
)

const (
	sessionCookieName    = "deployguard_session"
	oauthStateCookieName = "deployguard_oauth_state"
	maxRequestBytes      = 12 << 20
	maxPlanBytes         = 10 << 20
	maxMultipartMemory   = 1 << 20
	defaultSessionTTL    = 30 * time.Minute
	maxConcurrentReviews = 4
)

// GitHubAuthenticator is the sign-in surface the handler needs. *github.UserAuthenticator
// implements it; tests use a fake.
type GitHubAuthenticator interface {
	BeginAuthorization() (string, string, error)
	ConsumeState(string) bool
	CompleteAuthorization(context.Context, string, string) (gh.GitHubUser, string, error)
}

// GitHubClient is the GitHub surface the handler needs. *github.ReviewClient implements it;
// tests use a fake.
type GitHubClient interface {
	ListRepositories(context.Context, string) ([]gh.Repository, error)
	ListPullRequests(context.Context, string, int64) (gh.Repository, []gh.PullRequest, error)
	VerifyReview(context.Context, string, int64, int) (gh.VerifiedReview, error)
	DownloadPlanArtifact(context.Context, gh.VerifiedReview, gh.PlanArtifactConfig) ([]byte, error)
}

// ProvenanceChecker proves where a plan file came from (see internal/provenance).
type ProvenanceChecker interface {
	Check(ctx context.Context, review gh.VerifiedReview, plan []byte) domain.Provenance
}

// Config configures the GitHub-mode web handler.
type Config struct {
	PublicOrigin     string
	Auth             GitHubAuthenticator
	GitHub           GitHubClient
	Sessions         *gh.SessionStore
	RiskEngine       risk.Engine
	WorkflowFilename string
	ArtifactName     string
	PlanFilename     string
	MaxRequestBytes  int64
	MaxPlanBytes     int64
	SessionTTL       time.Duration
	// TrustedProxyHeader names a header (for example X-Forwarded-For) set by
	// your own reverse proxy. When empty, rate limits use the TCP peer address.
	TrustedProxyHeader string
	// Explainer is optional; nil disables AI narration.
	Explainer *ai.Explainer
	// Provenance is optional; nil leaves plans unattested.
	Provenance ProvenanceChecker
	// Verdicts is optional. When set, reviews started here are recorded and /history lists them.
	Verdicts VerdictStore
}

// Handler serves the GitHub-mode web UI: sign-in, repository and pull request pages, and plan review.
type Handler struct {
	publicOrigin     *url.URL
	auth             GitHubAuthenticator
	github           GitHubClient
	sessions         *gh.SessionStore
	engine           risk.Engine
	explainer        *ai.Explainer
	provenance       ProvenanceChecker
	verdicts         VerdictStore
	workflowFilename string
	artifactName     string
	planFilename     string
	sessionTTL       time.Duration
	maxRequestBytes  int64
	maxPlanBytes     int64
	templates        *template.Template

	authLimiter        *gh.MemoryRateLimiter
	reviewLimiter      *gh.MemoryRateLimiter
	reviewSlots        chan struct{}
	trustedProxyHeader string
}

// NewHandler validates the configuration and builds the handler. PublicOrigin must be an HTTPS origin.
func NewHandler(config Config) (*Handler, error) {
	if config.Auth == nil || config.GitHub == nil || config.Sessions == nil {
		return nil, errors.New("GitHub auth, review client, and session store are required")
	}
	origin, err := url.Parse(config.PublicOrigin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return nil, errors.New("public origin must be an HTTPS origin")
	}
	if config.MaxRequestBytes <= 0 || config.MaxRequestBytes > maxRequestBytes {
		config.MaxRequestBytes = maxRequestBytes
	}
	if config.MaxPlanBytes <= 0 || config.MaxPlanBytes > maxPlanBytes {
		config.MaxPlanBytes = maxPlanBytes
	}
	if config.SessionTTL <= 0 {
		config.SessionTTL = defaultSessionTTL
	}
	templates, err := template.New("pages").Funcs(templateFuncs).Parse(sharedTemplates + pageTemplates + resultTemplate + historyTemplate)
	if err != nil {
		return nil, errors.New("parse web page templates")
	}
	return &Handler{
		publicOrigin: origin, auth: config.Auth, github: config.GitHub,
		sessions: config.Sessions, engine: config.RiskEngine, explainer: config.Explainer, provenance: config.Provenance, verdicts: config.Verdicts,
		workflowFilename: config.WorkflowFilename, artifactName: config.ArtifactName,
		planFilename: config.PlanFilename, sessionTTL: config.SessionTTL,
		maxRequestBytes: config.MaxRequestBytes, maxPlanBytes: config.MaxPlanBytes,
		templates:          templates,
		authLimiter:        gh.NewMemoryRateLimiter(30, time.Minute),
		reviewLimiter:      gh.NewMemoryRateLimiter(20, time.Minute),
		reviewSlots:        make(chan struct{}, maxConcurrentReviews),
		trustedProxyHeader: strings.TrimSpace(config.TrustedProxyHeader),
	}, nil
}

// ServeHTTP routes requests and applies the security headers.
func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	setSecurityHeaders(writer)
	h.route(writer, request)
}

func (h *Handler) route(writer http.ResponseWriter, request *http.Request) {
	switch {
	case serveSiteAsset(writer, request):
		// brand images and /favicon.ico
	case request.URL.Path == "/assets/app.css" && request.Method == http.MethodGet:
		serveStyles(writer)
	case request.URL.Path == "/assets/theme.js" && request.Method == http.MethodGet:
		serveThemeScript(writer)
	case request.URL.Path == "/auth/github" && request.Method == http.MethodGet:
		h.beginSignIn(writer, request)
	case request.URL.Path == "/auth/github/callback" && request.Method == http.MethodGet:
		h.completeSignIn(writer, request)
	case request.URL.Path == "/auth/logout" && request.Method == http.MethodPost:
		h.logout(writer, request)
	case request.URL.Path == "/signed-out" && request.Method == http.MethodGet:
		h.render(writer, "signed-out", pageData{})
	case request.URL.Path == "/" && request.Method == http.MethodGet:
		h.home(writer, request)
	case request.URL.Path == "/history" && request.Method == http.MethodGet:
		h.history(writer, request)
	case strings.HasPrefix(request.URL.Path, "/repositories/") && strings.HasSuffix(request.URL.Path, "/pull-requests") && request.Method == http.MethodGet:
		h.pullRequests(writer, request)
	case request.URL.Path == "/reviews" && request.Method == http.MethodPost:
		h.review(writer, request)
	default:
		h.fail(writer, "That page does not exist.", http.StatusNotFound)
	}
}

func (h *Handler) beginSignIn(writer http.ResponseWriter, request *http.Request) {
	if h.limited(h.authLimiter, writer, request) {
		return
	}
	authorizationURL, state, err := h.auth.BeginAuthorization()
	if err != nil {
		h.fail(writer, "GitHub sign-in is unavailable", http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(writer, &http.Cookie{
		Name: oauthStateCookieName, Value: state, Path: "/auth/github/callback",
		MaxAge: int((10 * time.Minute).Seconds()), Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(writer, request, authorizationURL, http.StatusFound)
}

func (h *Handler) completeSignIn(writer http.ResponseWriter, request *http.Request) {
	if h.limited(h.authLimiter, writer, request) {
		return
	}
	code, state := request.URL.Query().Get("code"), request.URL.Query().Get("state")
	stateCookie, cookieErr := request.Cookie(oauthStateCookieName)
	http.SetCookie(writer, &http.Cookie{Name: oauthStateCookieName, Value: "", Path: "/auth/github/callback", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	if code == "" || state == "" || len(state) != 64 || cookieErr != nil || !equalTokens(stateCookie.Value, state) {
		h.fail(writer, "invalid GitHub authorization response", http.StatusBadRequest)
		return
	}
	user, token, err := h.auth.CompleteAuthorization(request.Context(), code, state)
	if err != nil {
		if errors.Is(err, gh.ErrInvalidOAuthState) {
			h.fail(writer, "invalid GitHub authorization response", http.StatusBadRequest)
			return
		}
		h.fail(writer, "GitHub sign-in could not be completed", http.StatusBadGateway)
		return
	}
	sessionID, err := h.sessions.Create(user, token)
	if err != nil {
		h.fail(writer, "GitHub sign-in is unavailable", http.StatusServiceUnavailable)
		return
	}
	h.setSessionCookie(writer, sessionID, h.sessionMaxAge())
	http.Redirect(writer, request, "/", http.StatusSeeOther)
}

func (h *Handler) logout(writer http.ResponseWriter, request *http.Request) {
	session, sessionID, ok := h.session(writer, request)
	if !ok {
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 4096)
	if err := request.ParseForm(); err != nil || !h.validOrigin(request) || !equalTokens(request.Form.Get("csrf_token"), session.CSRFToken) {
		h.fail(writer, "invalid request", http.StatusForbidden)
		return
	}
	h.sessions.Revoke(sessionID)
	h.setSessionCookie(writer, "", -1)
	http.Redirect(writer, request, "/signed-out", http.StatusSeeOther)
}

func (h *Handler) home(writer http.ResponseWriter, request *http.Request) {
	session, _, ok := h.session(writer, request)
	if !ok {
		return
	}
	repositories, err := h.github.ListRepositories(request.Context(), session.AccessToken)
	if err != nil {
		h.fail(writer, "GitHub repositories could not be loaded", http.StatusBadGateway)
		return
	}
	h.render(writer, "home", pageData{User: session.User.Login, CSRFToken: session.CSRFToken, Repositories: repositories})
}

func (h *Handler) pullRequests(writer http.ResponseWriter, request *http.Request) {
	session, _, ok := h.session(writer, request)
	if !ok {
		return
	}
	parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	if len(parts) != 3 || parts[0] != "repositories" || parts[2] != "pull-requests" {
		h.fail(writer, "That page does not exist.", http.StatusNotFound)
		return
	}
	repositoryID, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || repositoryID <= 0 {
		h.fail(writer, "invalid repository", http.StatusBadRequest)
		return
	}
	repository, pullRequests, err := h.github.ListPullRequests(request.Context(), session.AccessToken, repositoryID)
	if err != nil {
		if errors.Is(err, gh.ErrGitHubAccessDenied) {
			h.fail(writer, "repository is not available", http.StatusForbidden)
			return
		}
		h.fail(writer, "GitHub pull requests could not be loaded", http.StatusBadGateway)
		return
	}
	h.render(writer, "pull-requests", pageData{
		User: session.User.Login, CSRFToken: session.CSRFToken,
		Repository: repository, PullRequests: pullRequests,
		ActionsEnabled: h.workflowFilename != "" && h.artifactName != "",
	})
}

func (h *Handler) review(writer http.ResponseWriter, request *http.Request) {
	session, _, ok := h.session(writer, request)
	if !ok {
		return
	}
	if !h.validOrigin(request) {
		h.fail(writer, "invalid request origin", http.StatusForbidden)
		return
	}
	if h.limited(h.reviewLimiter, writer, request) {
		return
	}
	select {
	case h.reviewSlots <- struct{}{}:
		defer func() { <-h.reviewSlots }()
	default:
		writer.Header().Set("Retry-After", "5")
		h.fail(writer, "DeployGuard is busy analyzing other plans. Try again in a few seconds.", http.StatusServiceUnavailable)
		return
	}
	if request.ContentLength > h.maxRequestBytes {
		h.fail(writer, "request exceeds the size limit", http.StatusRequestEntityTooLarge)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, h.maxRequestBytes)
	parseErr := request.ParseMultipartForm(maxMultipartMemory)
	if request.MultipartForm != nil {
		defer request.MultipartForm.RemoveAll()
	}
	if parseErr != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(parseErr, &maxBytesError) || errors.Is(parseErr, multipart.ErrMessageTooLarge) {
			h.fail(writer, "request exceeds the size limit", http.StatusRequestEntityTooLarge)
		} else {
			h.fail(writer, "invalid multipart request", http.StatusBadRequest)
		}
		return
	}
	if request.ContentLength < 0 {
		if _, err := io.Copy(io.Discard, io.LimitReader(request.Body, 1)); err != nil {
			var maxBytesError *http.MaxBytesError
			if errors.As(err, &maxBytesError) {
				h.fail(writer, "request exceeds the size limit", http.StatusRequestEntityTooLarge)
				return
			}
			h.fail(writer, "request could not be read", http.StatusBadRequest)
			return
		}
	}
	if err := validateMultipartShape(request.MultipartForm); err != nil {
		h.fail(writer, "invalid review fields", http.StatusBadRequest)
		return
	}
	if !equalTokens(request.Form.Get("csrf_token"), session.CSRFToken) {
		h.fail(writer, "invalid request", http.StatusForbidden)
		return
	}
	repositoryID, err := positiveInt64(request.Form.Get("repository_id"))
	if err != nil {
		h.fail(writer, "invalid repository or pull request", http.StatusBadRequest)
		return
	}
	pullRequestNumber, err := strconv.Atoi(request.Form.Get("pull_request_number"))
	if err != nil || pullRequestNumber <= 0 {
		h.fail(writer, "invalid repository or pull request", http.StatusBadRequest)
		return
	}
	verified, err := h.github.VerifyReview(request.Context(), session.AccessToken, repositoryID, pullRequestNumber)
	if err != nil {
		h.fail(writer, "selected pull request is not available", http.StatusForbidden)
		return
	}
	var planBytes []byte
	switch request.Form.Get("source") {
	case "upload":
		planBytes, err = h.readPlanUpload(request)
	case "actions":
		if h.workflowFilename == "" || h.artifactName == "" {
			h.fail(writer, "Actions plan retrieval is not configured", http.StatusServiceUnavailable)
			return
		}
		var runID int64
		if len(request.Form["run_id"]) > 0 {
			runID, err = positiveInt64(request.Form.Get("run_id"))
			if err != nil {
				h.fail(writer, "invalid workflow run", http.StatusBadRequest)
				return
			}
		}
		planBytes, err = h.github.DownloadPlanArtifact(request.Context(), verified, gh.PlanArtifactConfig{
			WorkflowFilename: h.workflowFilename, ArtifactName: h.artifactName, PlanFilename: h.planFilename, RunID: runID,
		})
	default:
		h.fail(writer, "unsupported plan source", http.StatusBadRequest)
		return
	}
	if request.Form.Get("source") == "upload" && len(request.Form["run_id"]) != 0 {
		clear(planBytes)
		h.fail(writer, "run_id is only valid for Actions plans", http.StatusBadRequest)
		return
	}
	defer clear(planBytes)
	if err != nil {
		if errors.Is(err, errPlanTooLarge) {
			h.fail(writer, "plan exceeds the size limit", http.StatusRequestEntityTooLarge)
		} else if errors.Is(err, errUnsupportedPlanType) {
			h.fail(writer, "upload a Terraform JSON plan, not a binary tfplan", http.StatusUnsupportedMediaType)
		} else if errors.Is(err, errMissingPlan) {
			h.fail(writer, "Terraform JSON plan is required", http.StatusBadRequest)
		} else if errors.Is(err, errInvalidPlanUpload) {
			h.fail(writer, "plan upload could not be read", http.StatusBadRequest)
		} else if request.Form.Get("source") == "actions" {
			if errors.Is(err, gh.ErrArtifactTooLarge) {
				h.fail(writer, "plan artifact exceeds the size limit", http.StatusRequestEntityTooLarge)
			} else {
				h.fail(writer, "plan could not be loaded", http.StatusUnprocessableEntity)
			}
		} else {
			h.fail(writer, "plan could not be loaded", http.StatusUnprocessableEntity)
		}
		return
	}
	parsedPlan, err := plan.Parse(bytes.NewReader(planBytes))
	if err != nil {
		h.fail(writer, "invalid Terraform plan JSON", http.StatusUnprocessableEntity)
		return
	}
	analysis, err := h.engine.Analyze(parsedPlan)
	if err != nil {
		h.fail(writer, "plan analysis failed", http.StatusUnprocessableEntity)
		return
	}
	latest, err := h.github.VerifyReview(request.Context(), session.AccessToken, repositoryID, pullRequestNumber)
	if err != nil || latest.PullRequest.HeadSHA != verified.PullRequest.HeadSHA {
		h.fail(writer, "pull request changed during analysis; refresh and try again", http.StatusConflict)
		return
	}
	if h.provenance != nil {
		analysis.Provenance = h.provenance.Check(request.Context(), verified, planBytes)
	}
	h.recordReview(request.Context(), verified, analysis)
	analysis.AIExplanation = h.explainer.Explain(request.Context(), analysis)
	h.render(writer, "result", pageData{User: session.User.Login, Repository: verified.Repository, PullRequest: verified.PullRequest, Analysis: &analysis, PlanSource: request.Form.Get("source")})
}

var (
	errMissingPlan         = errors.New("Terraform JSON plan is required")
	errPlanTooLarge        = errors.New("plan exceeds limit")
	errUnsupportedPlanType = errors.New("unsupported plan content type")
	errInvalidPlanUpload   = errors.New("plan upload could not be read")
)

func (h *Handler) readPlanUpload(request *http.Request) ([]byte, error) {
	file, header, err := request.FormFile("plan")
	if err != nil {
		return nil, errMissingPlan
	}
	defer file.Close()
	if header.Size > h.maxPlanBytes {
		return nil, errPlanTooLarge
	}
	mediaType, _, err := mime.ParseMediaType(header.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/json" && mediaType != "application/octet-stream") {
		return nil, errUnsupportedPlanType
	}
	content, err := io.ReadAll(io.LimitReader(file, h.maxPlanBytes+1))
	if err != nil {
		return nil, errInvalidPlanUpload
	}
	if int64(len(content)) > h.maxPlanBytes {
		clear(content)
		return nil, errPlanTooLarge
	}
	return content, nil
}

func (h *Handler) session(writer http.ResponseWriter, request *http.Request) (gh.UserSession, string, bool) {
	cookie, err := request.Cookie(sessionCookieName)
	if err != nil {
		http.Redirect(writer, request, "/auth/github", http.StatusSeeOther)
		return gh.UserSession{}, "", false
	}
	session, ok := h.sessions.Get(cookie.Value)
	if !ok {
		h.setSessionCookie(writer, "", -1)
		http.Redirect(writer, request, "/auth/github", http.StatusSeeOther)
		return gh.UserSession{}, "", false
	}
	return session, cookie.Value, true
}

func (h *Handler) validOrigin(request *http.Request) bool {
	origin, err := url.Parse(request.Header.Get("Origin"))
	return err == nil && origin.Scheme == h.publicOrigin.Scheme && strings.EqualFold(origin.Host, h.publicOrigin.Host) && origin.User == nil && origin.Path == "" && origin.RawQuery == "" && origin.Fragment == ""
}

func (h *Handler) setSessionCookie(writer http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(writer, &http.Cookie{
		Name: sessionCookieName, Value: value, Path: "/", MaxAge: maxAge,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func (h *Handler) sessionMaxAge() int {
	return int(h.sessionTTL.Seconds())
}

func (h *Handler) render(writer http.ResponseWriter, name string, data pageData) {
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	if err := h.templates.ExecuteTemplate(writer, name, data); err != nil {
		http.Error(writer, "could not render page", http.StatusInternalServerError)
	}
}

func positiveInt64(value string) (int64, error) {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("invalid positive integer")
	}
	return parsed, nil
}

func validateMultipartShape(form *multipart.Form) error {
	if form == nil {
		return errors.New("multipart form is required")
	}
	allowed := map[string]bool{
		"source": true, "csrf_token": true, "repository_id": true,
		"pull_request_number": true, "run_id": true,
	}
	for key, values := range form.Value {
		if !allowed[key] || len(values) != 1 {
			return errors.New("unexpected or repeated form field")
		}
	}
	for _, key := range []string{"source", "csrf_token", "repository_id", "pull_request_number"} {
		if len(form.Value[key]) != 1 {
			return errors.New("required form field is missing")
		}
	}
	for key, files := range form.File {
		if key != "plan" || len(files) != 1 {
			return errors.New("unexpected or repeated uploaded file")
		}
	}
	if form.Value["source"][0] == "upload" && len(form.File["plan"]) != 1 {
		return errors.New("upload source requires one plan file")
	}
	if form.Value["source"][0] == "actions" && len(form.File) != 0 {
		return errors.New("actions source cannot include an uploaded file")
	}
	return nil
}

type pageData struct {
	User           string
	CSRFToken      string
	Repositories   []gh.Repository
	Repository     gh.Repository
	PullRequests   []gh.PullRequest
	PullRequest    gh.PullRequest
	Analysis       *domain.Analysis
	ActionsEnabled bool
	PlanSource     string
	// History page (both modes).
	History      []historyRow
	HistoryNote  string
	LocalHistory bool
}

func setSecurityHeaders(writer http.ResponseWriter) {
	header := writer.Header()
	header.Set("Content-Security-Policy", contentSecurityPolicy)
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	// Intentionally "same-origin", NOT "no-referrer": no-referrer makes browsers
	// send "Origin: null" on our own forms, so validOrigin rejects every POST.
	// same-origin sends no referrer cross-site and a real Origin same-site.
	header.Set("Referrer-Policy", "same-origin")
	header.Set("Cache-Control", "no-store")
}

func equalTokens(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// clientIP identifies the caller for rate limiting. A forwarding header is
// honored only when the operator names one, because any client can forge it
// when DeployGuard is reachable without a trusted proxy in front.
func (h *Handler) clientIP(request *http.Request) string {
	if h.trustedProxyHeader != "" {
		values := strings.Split(request.Header.Get(h.trustedProxyHeader), ",")
		// The right-most entry is the one appended by the trusted proxy.
		if candidate := strings.TrimSpace(values[len(values)-1]); net.ParseIP(candidate) != nil {
			return candidate
		}
	}
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return request.RemoteAddr
	}
	return host
}

func (h *Handler) limited(limiter *gh.MemoryRateLimiter, writer http.ResponseWriter, request *http.Request) bool {
	if limiter.Allow(h.clientIP(request)) {
		return false
	}
	writer.Header().Set("Retry-After", "60")
	h.fail(writer, "Too many requests. Wait a minute and try again.", http.StatusTooManyRequests)
	return true
}

// fail renders a styled error page instead of a bare text response.
func (h *Handler) fail(writer http.ResponseWriter, message string, status int) {
	writeError(writer, h.templates, errorData{
		Status: status, Message: sentence(message), BackHref: "/", BackLabel: "Back to repositories", Mode: "GITHUB MODE",
	})
}
