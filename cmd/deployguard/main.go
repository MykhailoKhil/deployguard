package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/deployguard/deployguard/internal/ai"
	"github.com/deployguard/deployguard/internal/domain"
	gh "github.com/deployguard/deployguard/internal/github"
	"github.com/deployguard/deployguard/internal/provenance"
	"github.com/deployguard/deployguard/internal/review"
	"github.com/deployguard/deployguard/internal/risk"
	"github.com/deployguard/deployguard/internal/store"
	"github.com/deployguard/deployguard/internal/web"
)

func main() {
	if err := run(); err != nil {
		slog.Error("deployguard startup or server error", "error", err.Error())
		os.Exit(1)
	}
}

func run() error {
	logger, err := newLogger(os.Getenv, os.Stderr)
	if err != nil {
		return err
	}
	slog.SetDefault(logger)
	config, err := loadConfig(os.Getenv)
	if err != nil {
		return err
	}
	if config.explainer, err = loadExplainer(os.Getenv); err != nil {
		return err
	}
	if config.databaseURL != "" {
		pg, err := store.Open(context.Background(), config.databaseURL)
		if err != nil {
			return fmt.Errorf("database: %w", err)
		}
		defer pg.Close()
		config.recorder = pg
		config.verdicts = pg
		retention, stopRetention := context.WithCancel(context.Background())
		defer stopRetention()
		go purgeLoop(retention, pg, time.Duration(config.retentionDays)*24*time.Hour, logger)
	}
	var handler http.Handler
	waitForWork := func() {}
	checkPermissionsLater := func(context.Context) {}
	if config.localOnly {
		var history web.LocalHistory // stays nil (history off) unless the file can be opened
		if config.historyFile != "" {
			if file, err := store.OpenFileHistory(config.historyFile, localHistoryEntries); err != nil {
				logger.Warn("upload history is off", "error", err.Error())
			} else {
				history = file
			}
		}
		handler = web.NewLocalHandlerWithHistory(config.listenAddress, config.explainer, history)
	} else {
		var stack githubStack
		stack, err = newGitHubHandler(config, logger)
		if err != nil {
			return err
		}
		handler, waitForWork = stack.Handler, stack.Wait
		checkPermissionsLater = stack.CheckPermissions
	}
	server := &http.Server{
		Addr: config.listenAddress, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second,
	}
	// Bind before announcing, so a busy port is reported instead of "listening".
	listener, err := net.Listen("tcp", config.listenAddress)
	if err != nil {
		return listenError(config.listenAddress, err)
	}
	attrs := []any{"mode", "github", "address", config.listenAddress, "ai_enabled", config.explainer != nil, "webhook_enabled", config.webhookSecret != ""}
	if config.localOnly {
		history := config.historyFile
		if history == "" {
			history = "off"
		}
		attrs = []any{"mode", "local", "address", config.listenAddress, "ai_enabled", config.explainer != nil, "history", history, "open", "http://" + config.listenAddress}
	}
	logger.Info("DeployGuard listening", attrs...)
	if !config.localOnly {
		// Off the startup path: a slow or unreachable GitHub must not delay serving.
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			checkPermissionsLater(ctx)
		}()
	}

	// Stop on SIGINT/SIGTERM (Docker sends SIGTERM): finish in-flight requests
	// and queued check-run analyses before exiting.
	stop, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	select {
	case err := <-serveErr:
		return err
	case <-stop.Done():
	}
	logger.Info("shutting down")
	shutdown, done := context.WithTimeout(context.Background(), 30*time.Second)
	defer done()
	if err := server.Shutdown(shutdown); err != nil {
		return err
	}
	waitForWork()
	return nil
}

// githubStack is the GitHub-mode server pieces run() needs.
type githubStack struct {
	Handler http.Handler
	// Wait blocks until queued analyses finish (graceful shutdown).
	Wait func()
	// CheckPermissions logs any App permission an enabled feature needs but the App lacks.
	CheckPermissions func(context.Context)
}

func newGitHubHandler(config serverConfig, logger *slog.Logger) (githubStack, error) {
	app, err := gh.NewAppAuthenticator(gh.AppAuthenticatorConfig{
		AppID: config.appID, PrivateKeyPEM: []byte(config.privateKey), APIBaseURL: config.apiBaseURL,
	})
	if err != nil {
		return githubStack{}, errors.New("invalid GitHub App configuration")
	}
	userAuth, err := gh.NewUserAuthenticator(gh.UserAuthenticatorConfig{
		ClientID: config.oauthClientID, ClientSecret: config.oauthClientSecret,
		RedirectURL: config.oauthRedirectURL, APIBaseURL: config.apiBaseURL, WebBaseURL: config.webBaseURL,
	})
	if err != nil {
		return githubStack{}, errors.New("invalid GitHub OAuth configuration")
	}
	reviewClient, err := gh.NewReviewClient(gh.ReviewClientConfig{APIBaseURL: config.apiBaseURL, App: app})
	if err != nil {
		return githubStack{}, errors.New("invalid GitHub review client configuration")
	}
	var checker *provenance.Checker
	if config.provenanceRoot != "" {
		trusted, err := provenance.LoadTrustedRoot(config.provenanceRoot)
		if err != nil {
			return githubStack{}, err
		}
		verifier, err := provenance.NewVerifier(trusted)
		if err != nil {
			return githubStack{}, errors.New("invalid provenance configuration")
		}
		checker = &provenance.Checker{Source: reviewClient, Verifier: verifier, WorkflowFile: config.workflowFilename}
	}
	var webProvenance web.ProvenanceChecker
	var hookProvenance review.ProvenanceChecker
	if checker != nil {
		webProvenance, hookProvenance = checker, checker
	}
	handler, err := web.NewHandler(web.Config{
		PublicOrigin: config.publicOrigin, Auth: userAuth, GitHub: reviewClient, Provenance: webProvenance,
		Sessions: gh.NewSessionStore(config.sessionTTL), RiskEngine: risk.NewEngine(risk.Config{}),
		WorkflowFilename: config.workflowFilename, ArtifactName: config.artifactName,
		PlanFilename: config.planFilename, SessionTTL: config.sessionTTL, Verdicts: config.verdicts,
		TrustedProxyHeader: config.trustedProxyHeader, Explainer: config.explainer,
	})
	if err != nil {
		return githubStack{}, errors.New("invalid web handler configuration")
	}
	check := func(ctx context.Context) { checkPermissions(ctx, app, config, logger) }
	if config.webhookSecret == "" {
		return githubStack{Handler: handler, Wait: func() {}, CheckPermissions: check}, nil
	}
	mounted, wait, err := mountWebhook(config, logger, app, reviewClient, hookProvenance, handler)
	if err != nil {
		return githubStack{}, err
	}
	return githubStack{Handler: mounted, Wait: wait, CheckPermissions: check}, nil
}

// mountWebhook adds the signed webhook endpoint and /healthz in front of the web UI. It also
// returns a function that waits for queued analyses, used for graceful shutdown.
func mountWebhook(config serverConfig, logger *slog.Logger, app *gh.AppAuthenticator, artifacts review.ArtifactSource, proof review.ProvenanceChecker, ui http.Handler) (http.Handler, func(), error) {
	checks, err := gh.NewChecksClient(app)
	if err != nil {
		return nil, nil, errors.New("invalid GitHub checks configuration")
	}
	var explain func(context.Context, domain.Analysis) string
	if config.explainer != nil {
		explain = config.explainer.Explain
	}
	var comments review.CommentPublisher
	if config.prComments {
		commentsClient, err := gh.NewCommentsClient(app)
		if err != nil {
			return nil, nil, errors.New("invalid GitHub comments configuration")
		}
		comments = commentsClient
	}
	processor, err := review.New(review.Config{
		Artifacts: artifacts, Checks: checks, Comments: comments, Recorder: config.recorder, Provenance: proof, Engine: risk.NewEngine(risk.Config{}), Explain: explain, Logger: logger,
		Plan: gh.PlanArtifactConfig{WorkflowFilename: config.workflowFilename, ArtifactName: config.artifactName, PlanFilename: config.planFilename},
	})
	if err != nil {
		return nil, nil, errors.New("invalid review processor configuration")
	}
	webhook, err := gh.NewWebhookHandler(gh.WebhookConfig{
		WebhookSecret: []byte(config.webhookSecret), Verifier: app, Processor: processor, Auditor: slogAuditor{logger: logger},
	})
	if err != nil {
		return nil, nil, errors.New("invalid webhook configuration")
	}
	mux := http.NewServeMux()
	mux.Handle("/webhooks/github", webhook)
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) { _, _ = writer.Write([]byte("ok")) })
	mux.Handle("/", ui)
	return mux, processor.Wait, nil
}

type serverConfig struct {
	localOnly          bool
	listenAddress      string
	publicOrigin       string
	apiBaseURL         string
	webBaseURL         string
	appID              int64
	privateKey         string
	oauthClientID      string
	oauthClientSecret  string
	oauthRedirectURL   string
	sessionTTL         time.Duration
	workflowFilename   string
	artifactName       string
	planFilename       string
	trustedProxyHeader string
	explainer          *ai.Explainer
	webhookSecret      string
	prComments         bool
	provenanceRoot     string // path to a Sigstore trusted_root.json; empty disables provenance checks
	databaseURL        string
	retentionDays      int
	recorder           review.AnalysisRecorder // set by run() once the database is open
	verdicts           web.VerdictStore        // the same database, for the History page
	historyFile        string                  // local mode: where upload verdicts are kept; "" turns history off
}

func loadConfig(getenv func(string) string) (serverConfig, error) {
	githubSettings := []string{
		"DEPLOYGUARD_GITHUB_APP_ID", "DEPLOYGUARD_GITHUB_PRIVATE_KEY_PEM",
		"DEPLOYGUARD_GITHUB_OAUTH_CLIENT_ID", "DEPLOYGUARD_GITHUB_OAUTH_CLIENT_SECRET",
		"DEPLOYGUARD_GITHUB_OAUTH_REDIRECT_URL", "DEPLOYGUARD_PUBLIC_ORIGIN",
		"DEPLOYGUARD_GITHUB_API_BASE_URL", "DEPLOYGUARD_GITHUB_WEB_BASE_URL", "DEPLOYGUARD_GITHUB_WEBHOOK_SECRET", "DEPLOYGUARD_PR_COMMENTS", "DEPLOYGUARD_PROVENANCE_TRUSTED_ROOT", "DEPLOYGUARD_DATABASE_URL", "DEPLOYGUARD_RETENTION_DAYS",
		"DEPLOYGUARD_PLAN_WORKFLOW_FILENAME", "DEPLOYGUARD_PLAN_ARTIFACT_NAME",
		"DEPLOYGUARD_PLAN_JSON_FILENAME", "DEPLOYGUARD_SESSION_TTL", "DEPLOYGUARD_TRUSTED_PROXY_HEADER",
	}
	var githubSet []string // the variables that selected GitHub mode
	for _, name := range githubSettings {
		if getenv(name) != "" {
			githubSet = append(githubSet, name)
		}
	}
	if len(githubSet) == 0 {
		address := getenv("DEPLOYGUARD_LISTEN_ADDRESS")
		if address == "" {
			address = "127.0.0.1:8080"
		}
		host, port, err := net.SplitHostPort(address)
		ip := net.ParseIP(host)
		portNumber, portErr := strconv.Atoi(port)
		if err != nil || ip == nil || !ip.IsLoopback() || portErr != nil || portNumber < 1 || portNumber > 65535 {
			return serverConfig{}, errors.New("local mode requires a loopback IP listen address and valid port, for example 127.0.0.1:8080")
		}
		return serverConfig{localOnly: true, listenAddress: address, historyFile: historyPath(getenv)}, nil
	}
	var missing []string
	for _, name := range requiredGitHubSettings {
		if getenv(name) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		// Names only, never values, so this is safe to log.
		return serverConfig{}, fmt.Errorf("GitHub mode is on because these variables are set: %s. It also requires: %s. To use local mode instead, unset all DEPLOYGUARD_* variables (unset $(env | grep -o '^DEPLOYGUARD_[A-Z_]*'))",
			strings.Join(githubSet, ", "), strings.Join(missing, ", "))
	}
	appID, err := strconv.ParseInt(strings.TrimSpace(getenv("DEPLOYGUARD_GITHUB_APP_ID")), 10, 64)
	if err != nil || appID <= 0 {
		return serverConfig{}, errors.New("DEPLOYGUARD_GITHUB_APP_ID must be a positive integer")
	}
	privateKey := getenv("DEPLOYGUARD_GITHUB_PRIVATE_KEY_PEM")
	if err := validatePrivateKey(privateKey); err != nil {
		return serverConfig{}, errors.New("DEPLOYGUARD_GITHUB_PRIVATE_KEY_PEM must contain a valid RSA PEM key")
	}
	config := serverConfig{
		listenAddress: getenv("DEPLOYGUARD_LISTEN_ADDRESS"),
		publicOrigin:  getenv("DEPLOYGUARD_PUBLIC_ORIGIN"),
		apiBaseURL:    getenv("DEPLOYGUARD_GITHUB_API_BASE_URL"),
		webBaseURL:    getenv("DEPLOYGUARD_GITHUB_WEB_BASE_URL"),
		appID:         appID, privateKey: privateKey,
		oauthClientID:      getenv("DEPLOYGUARD_GITHUB_OAUTH_CLIENT_ID"),
		oauthClientSecret:  getenv("DEPLOYGUARD_GITHUB_OAUTH_CLIENT_SECRET"),
		oauthRedirectURL:   getenv("DEPLOYGUARD_GITHUB_OAUTH_REDIRECT_URL"),
		workflowFilename:   getenv("DEPLOYGUARD_PLAN_WORKFLOW_FILENAME"),
		artifactName:       getenv("DEPLOYGUARD_PLAN_ARTIFACT_NAME"),
		planFilename:       getenv("DEPLOYGUARD_PLAN_JSON_FILENAME"),
		trustedProxyHeader: strings.TrimSpace(getenv("DEPLOYGUARD_TRUSTED_PROXY_HEADER")),
		webhookSecret:      getenv("DEPLOYGUARD_GITHUB_WEBHOOK_SECRET"),
		sessionTTL:         30 * time.Minute,
	}
	if config.listenAddress == "" {
		config.listenAddress = ":8080"
	}
	if config.apiBaseURL == "" {
		config.apiBaseURL = "https://api.github.com"
	}
	if config.webBaseURL == "" {
		config.webBaseURL = "https://github.com"
	}
	if config.planFilename == "" {
		config.planFilename = "tfplan.json"
	}
	if config.oauthClientID == "" || config.oauthClientSecret == "" || config.oauthRedirectURL == "" || config.publicOrigin == "" {
		return serverConfig{}, errors.New("public origin and GitHub OAuth client ID, secret, and callback URL are required")
	}
	if (config.workflowFilename == "") != (config.artifactName == "") {
		return serverConfig{}, errors.New("configure both plan workflow filename and artifact name, or leave both unset")
	}
	if strings.Contains(config.planFilename, "..") || strings.ContainsAny(config.planFilename, "/\\") {
		return serverConfig{}, errors.New("plan JSON filename must be a basename")
	}
	if rawTTL := getenv("DEPLOYGUARD_SESSION_TTL"); rawTTL != "" {
		config.sessionTTL, err = time.ParseDuration(rawTTL)
		if err != nil {
			return serverConfig{}, errors.New("DEPLOYGUARD_SESSION_TTL must be a valid duration")
		}
	}
	if config.sessionTTL < 5*time.Minute || config.sessionTTL > 24*time.Hour {
		return serverConfig{}, errors.New("DEPLOYGUARD_SESSION_TTL must be between 5m and 24h")
	}
	apiURL, err := url.Parse(config.apiBaseURL)
	if err != nil || apiURL.Scheme != "https" || apiURL.Host == "" || apiURL.User != nil || apiURL.RawQuery != "" || apiURL.Fragment != "" {
		return serverConfig{}, errors.New("DEPLOYGUARD_GITHUB_API_BASE_URL must be an HTTPS URL")
	}
	webURL, err := url.Parse(config.webBaseURL)
	if err != nil || webURL.Scheme != "https" || webURL.Host == "" || webURL.User != nil || webURL.RawQuery != "" || webURL.Fragment != "" {
		return serverConfig{}, errors.New("DEPLOYGUARD_GITHUB_WEB_BASE_URL must be an HTTPS URL")
	}
	if strings.Contains(config.workflowFilename, "..") || strings.ContainsAny(config.workflowFilename, "/\\?#") || strings.TrimSpace(config.artifactName) != config.artifactName || strings.ContainsAny(config.artifactName, "/\\?#") {
		return serverConfig{}, errors.New("plan workflow and artifact names are invalid")
	}
	if header := config.trustedProxyHeader; header != "" && !validHeaderName(header) {
		return serverConfig{}, errors.New("DEPLOYGUARD_TRUSTED_PROXY_HEADER must be a valid HTTP header name")
	}
	config.provenanceRoot = strings.TrimSpace(getenv("DEPLOYGUARD_PROVENANCE_TRUSTED_ROOT"))
	if config.provenanceRoot != "" && config.workflowFilename == "" {
		return serverConfig{}, errors.New("plan provenance checks need the plan workflow filename and artifact name (DEPLOYGUARD_PLAN_WORKFLOW_FILENAME)")
	}
	config.databaseURL = getenv("DEPLOYGUARD_DATABASE_URL")
	config.retentionDays = defaultRetentionDays
	if raw := strings.TrimSpace(getenv("DEPLOYGUARD_RETENTION_DAYS")); raw != "" {
		days, err := strconv.Atoi(raw)
		if err != nil || days < 1 || days > 3650 {
			return serverConfig{}, errors.New("DEPLOYGUARD_RETENTION_DAYS must be a whole number from 1 to 3650")
		}
		config.retentionDays = days
	}
	if config.databaseURL != "" {
		if err := store.ValidateURL(config.databaseURL); err != nil {
			return serverConfig{}, fmt.Errorf("DEPLOYGUARD_DATABASE_URL: %w", err)
		}
	}
	if raw := strings.TrimSpace(getenv("DEPLOYGUARD_PR_COMMENTS")); raw != "" {
		enabled, err := strconv.ParseBool(raw)
		if err != nil {
			return serverConfig{}, errors.New("DEPLOYGUARD_PR_COMMENTS must be true or false")
		}
		if enabled && config.webhookSecret == "" {
			return serverConfig{}, errors.New("DEPLOYGUARD_PR_COMMENTS needs the webhook (set DEPLOYGUARD_GITHUB_WEBHOOK_SECRET)")
		}
		config.prComments = enabled
	}
	if config.webhookSecret != "" {
		if len(config.webhookSecret) < minWebhookSecretLength {
			return serverConfig{}, fmt.Errorf("DEPLOYGUARD_GITHUB_WEBHOOK_SECRET must be at least %d characters", minWebhookSecretLength)
		}
		if config.workflowFilename == "" {
			return serverConfig{}, errors.New("the webhook needs the plan workflow filename and artifact name to fetch plans")
		}
	}
	return config, nil
}

// localHistoryEntries is how many local-upload verdicts are kept.
const localHistoryEntries = 500

// historyPath returns where local-mode verdicts are kept: DEPLOYGUARD_HISTORY_FILE (an absolute path,
// or "off"), else history.jsonl in the user's config folder. "" means history is off.
func historyPath(getenv func(string) string) string {
	value := strings.TrimSpace(getenv("DEPLOYGUARD_HISTORY_FILE"))
	switch strings.ToLower(value) {
	case "off", "none", "false", "0":
		return ""
	case "":
		dir, err := os.UserConfigDir()
		if err != nil {
			return ""
		}
		return filepath.Join(dir, "deployguard", "history.jsonl")
	}
	if !filepath.IsAbs(value) {
		return "" // a relative path would depend on where the server was started
	}
	return value
}

// defaultRetentionDays is how long stored verdicts are kept.
const defaultRetentionDays = 90

// purgeLoop deletes verdicts older than the retention period, now and every six hours.
func purgeLoop(ctx context.Context, s store.Store, keep time.Duration, logger *slog.Logger) {
	purge := func() {
		removed, err := s.PurgeAnalysesBefore(ctx, time.Now().Add(-keep))
		if err != nil {
			logger.Warn("retention purge failed", "error", err.Error())
			return
		}
		if removed > 0 {
			logger.Info("retention purge", "removed", removed)
		}
	}
	purge()
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			purge()
		}
	}
}

// requiredGitHubSettings must all be set together in GitHub mode.
var requiredGitHubSettings = []string{
	"DEPLOYGUARD_GITHUB_APP_ID", "DEPLOYGUARD_GITHUB_PRIVATE_KEY_PEM", "DEPLOYGUARD_GITHUB_OAUTH_CLIENT_ID",
	"DEPLOYGUARD_GITHUB_OAUTH_CLIENT_SECRET", "DEPLOYGUARD_GITHUB_OAUTH_REDIRECT_URL", "DEPLOYGUARD_PUBLIC_ORIGIN",
}

// listenError turns the common "port busy" failure into an actionable message.
func listenError(address string, err error) error {
	if errors.Is(err, syscall.EADDRINUSE) {
		return fmt.Errorf("%s is already in use by another program; pick another address, for example DEPLOYGUARD_LISTEN_ADDRESS=127.0.0.1:8090", address)
	}
	return fmt.Errorf("listen on %s: %w", address, err)
}

// minWebhookSecretLength rejects guessable webhook secrets; GitHub accepts any.
const minWebhookSecretLength = 20

// validHeaderName accepts RFC 7230 token characters only.
func validHeaderName(name string) bool {
	for _, character := range name {
		switch {
		case character >= 'a' && character <= 'z', character >= 'A' && character <= 'Z', character >= '0' && character <= '9', character == '-':
		default:
			return false
		}
	}
	return name != ""
}

func validatePrivateKey(value string) error {
	block, _ := pem.Decode([]byte(value))
	if block == nil {
		return errors.New("missing PEM block")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key.Validate()
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return errors.New("key is not RSA")
	}
	return key.Validate()
}

// loadExplainer enables AI narration only when DEPLOYGUARD_AI_PROVIDER or DEPLOYGUARD_AI_BASE_URL
// is set; with neither, AI stays off. The provider defaults to anthropic and the base URL to the
// provider's public API. It deliberately ignores ANTHROPIC_* so a developer's Claude Code settings
// cannot silently send analysis data to a third party.
func loadExplainer(getenv func(string) string) (*ai.Explainer, error) {
	provider, baseURL := getenv("DEPLOYGUARD_AI_PROVIDER"), getenv("DEPLOYGUARD_AI_BASE_URL")
	if provider == "" && baseURL == "" {
		return nil, nil
	}
	explainer, err := ai.NewFromConfig(ai.Config{
		Provider: provider, BaseURL: baseURL, APIKey: getenv("DEPLOYGUARD_AI_API_KEY"), Model: getenv("DEPLOYGUARD_AI_MODEL"),
	})
	if err != nil {
		return nil, fmt.Errorf("DEPLOYGUARD_AI_*: %w", err)
	}
	return explainer, nil
}
