package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gh "github.com/deployguard/deployguard/internal/github"
	"github.com/deployguard/deployguard/internal/store"
)

func TestLoadConfigRejectsInvalidOrSecretLeakingConfiguration(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	privateKey := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	base := map[string]string{
		"DEPLOYGUARD_GITHUB_APP_ID":              "123",
		"DEPLOYGUARD_GITHUB_PRIVATE_KEY_PEM":     privateKey,
		"DEPLOYGUARD_GITHUB_OAUTH_CLIENT_ID":     "client-id",
		"DEPLOYGUARD_GITHUB_OAUTH_CLIENT_SECRET": "sensitive-oauth-secret",
		"DEPLOYGUARD_GITHUB_OAUTH_REDIRECT_URL":  "https://deployguard.example/auth/github/callback",
		"DEPLOYGUARD_PUBLIC_ORIGIN":              "https://deployguard.example",
	}
	getenv := func(values map[string]string) func(string) string {
		return func(name string) string { return values[name] }
	}
	if _, err := loadConfig(getenv(base)); err != nil {
		t.Fatalf("loadConfig(valid) error = %v", err)
	}

	invalid := make(map[string]string, len(base)+1)
	for key, value := range base {
		invalid[key] = value
	}
	invalid["DEPLOYGUARD_SESSION_TTL"] = "not-a-duration"
	_, err = loadConfig(getenv(invalid))
	if err == nil || strings.Contains(err.Error(), "sensitive-oauth-secret") || strings.Contains(err.Error(), privateKey) {
		t.Fatalf("loadConfig(invalid) error = %v", err)
	}
}

func TestLoadConfigUsesLocalModeWhenGitHubIsUnconfigured(t *testing.T) {
	config, err := loadConfig(func(string) string { return "" })
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if !config.localOnly {
		t.Fatal("loadConfig() localOnly = false, want true")
	}
	if config.listenAddress != "127.0.0.1:8080" {
		t.Fatalf("listenAddress = %q, want loopback default", config.listenAddress)
	}
}

func TestLoadConfigRejectsNonLoopbackAddressInLocalMode(t *testing.T) {
	_, err := loadConfig(func(name string) string {
		if name == "DEPLOYGUARD_LISTEN_ADDRESS" {
			return ":8080"
		}
		return ""
	})
	if err == nil {
		t.Fatal("loadConfig() accepted a non-loopback address in local mode")
	}
}

func TestLoadConfigRejectsPartialGitHubConfiguration(t *testing.T) {
	for _, key := range []string{"DEPLOYGUARD_GITHUB_APP_ID", "DEPLOYGUARD_GITHUB_OAUTH_CLIENT_ID", "DEPLOYGUARD_PUBLIC_ORIGIN", "DEPLOYGUARD_GITHUB_API_BASE_URL", "DEPLOYGUARD_PLAN_ARTIFACT_NAME"} {
		t.Run(key, func(t *testing.T) {
			_, err := loadConfig(func(name string) string {
				if name == key {
					return "configured"
				}
				return ""
			})
			if err == nil {
				t.Fatalf("loadConfig() accepted partial configuration %s", key)
			}
		})
	}
}

func TestLoadConfigLocalAddressValidation(t *testing.T) {
	for address, valid := range map[string]bool{"127.0.0.1:8081": true, "[::1]:8081": true, "localhost:8080": false, "0.0.0.0:8080": false, "127.0.0.1:notaport": false} {
		t.Run(address, func(t *testing.T) {
			_, err := loadConfig(func(name string) string {
				if name == "DEPLOYGUARD_LISTEN_ADDRESS" {
					return address
				}
				return ""
			})
			if (err == nil) != valid {
				t.Fatalf("loadConfig(%q) error = %v", address, err)
			}
		})
	}
}

func TestLoadConfigValidatesPlanNamesAndGitHubURLs(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	base := map[string]string{
		"DEPLOYGUARD_GITHUB_APP_ID":              "123",
		"DEPLOYGUARD_GITHUB_PRIVATE_KEY_PEM":     string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
		"DEPLOYGUARD_GITHUB_OAUTH_CLIENT_ID":     "client-id",
		"DEPLOYGUARD_GITHUB_OAUTH_CLIENT_SECRET": "secret",
		"DEPLOYGUARD_GITHUB_OAUTH_REDIRECT_URL":  "https://deployguard.example/auth/github/callback",
		"DEPLOYGUARD_PUBLIC_ORIGIN":              "https://deployguard.example",
	}
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "workflow path", key: "DEPLOYGUARD_PLAN_WORKFLOW_FILENAME", value: "../deployguard.yml"},
		{name: "artifact traversal", key: "DEPLOYGUARD_PLAN_ARTIFACT_NAME", value: "../artifact"},
		{name: "insecure API URL", key: "DEPLOYGUARD_GITHUB_API_BASE_URL", value: "http://api.github.com"},
		{name: "insecure web URL", key: "DEPLOYGUARD_GITHUB_WEB_BASE_URL", value: "http://github.com"},
		{name: "proxy header with spaces", key: "DEPLOYGUARD_TRUSTED_PROXY_HEADER", value: "X Forwarded For"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := make(map[string]string, len(base)+1)
			for key, value := range base {
				values[key] = value
			}
			values[test.key] = test.value
			if _, err := loadConfig(func(name string) string { return values[name] }); err == nil {
				t.Fatalf("loadConfig() accepted %s", test.key)
			}
		})
	}
}

func TestLoadExplainer(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if e, err := loadExplainer(env(map[string]string{"ANTHROPIC_BASE_URL": "http://127.0.0.1:1", "ANTHROPIC_AUTH_TOKEN": "x"})); e != nil || err != nil {
		t.Fatalf("ANTHROPIC_* must not enable AI: %v %v", e, err)
	}
	if _, err := loadExplainer(env(map[string]string{"DEPLOYGUARD_AI_BASE_URL": "http://127.0.0.1:20128"})); err == nil {
		t.Fatal("base URL without key and model must fail")
	}
	e, err := loadExplainer(env(map[string]string{"DEPLOYGUARD_AI_BASE_URL": "http://127.0.0.1:20128", "DEPLOYGUARD_AI_API_KEY": "k", "DEPLOYGUARD_AI_MODEL": "m"}))
	if e == nil || err != nil {
		t.Fatalf("valid config: %v %v", e, err)
	}
}

func githubTestEnv(t *testing.T, extra map[string]string) func(string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{
		"DEPLOYGUARD_GITHUB_APP_ID":              "123",
		"DEPLOYGUARD_GITHUB_PRIVATE_KEY_PEM":     string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
		"DEPLOYGUARD_GITHUB_OAUTH_CLIENT_ID":     "client-id",
		"DEPLOYGUARD_GITHUB_OAUTH_CLIENT_SECRET": "sensitive-oauth-secret",
		"DEPLOYGUARD_GITHUB_OAUTH_REDIRECT_URL":  "https://deployguard.example/auth/github/callback",
		"DEPLOYGUARD_PUBLIC_ORIGIN":              "https://deployguard.example",
	}
	for k, v := range extra {
		values[k] = v
	}
	return func(name string) string { return values[name] }
}

func TestWebhookSecretValidation(t *testing.T) {
	long := strings.Repeat("s", 24)
	plan := map[string]string{"DEPLOYGUARD_PLAN_WORKFLOW_FILENAME": "plan.yml", "DEPLOYGUARD_PLAN_ARTIFACT_NAME": "plan"}
	with := func(extra map[string]string) map[string]string {
		merged := map[string]string{}
		for k, v := range plan {
			merged[k] = v
		}
		for k, v := range extra {
			merged[k] = v
		}
		return merged
	}
	if _, err := loadConfig(githubTestEnv(t, with(map[string]string{"DEPLOYGUARD_GITHUB_WEBHOOK_SECRET": "short"}))); err == nil {
		t.Error("a short webhook secret must be rejected")
	}
	if _, err := loadConfig(githubTestEnv(t, map[string]string{"DEPLOYGUARD_GITHUB_WEBHOOK_SECRET": long})); err == nil {
		t.Error("a webhook without the plan workflow settings must be rejected")
	}
	config, err := loadConfig(githubTestEnv(t, with(map[string]string{"DEPLOYGUARD_GITHUB_WEBHOOK_SECRET": long})))
	if err != nil || config.webhookSecret != long {
		t.Errorf("valid webhook configuration: %v", err)
	}
	// The secret alone must never silently fall back to local mode.
	if _, err := loadConfig(func(name string) string {
		if name == "DEPLOYGUARD_GITHUB_WEBHOOK_SECRET" {
			return long
		}
		return ""
	}); err == nil {
		t.Error("webhook secret without GitHub settings must not start local mode")
	}
}

func TestGitHubHandlerMountsWebhookOnlyWhenConfigured(t *testing.T) {
	logger, _ := newLogger(func(string) string { return "" }, io.Discard)
	secret := strings.Repeat("s", 24)
	for name, tc := range map[string]struct {
		extra       map[string]string
		wantWebhook bool
	}{
		"without secret": {nil, false},
		"with secret": {map[string]string{
			"DEPLOYGUARD_GITHUB_WEBHOOK_SECRET": secret, "DEPLOYGUARD_PLAN_WORKFLOW_FILENAME": "plan.yml", "DEPLOYGUARD_PLAN_ARTIFACT_NAME": "plan",
		}, true},
	} {
		t.Run(name, func(t *testing.T) {
			config, err := loadConfig(githubTestEnv(t, tc.extra))
			if err != nil {
				t.Fatal(err)
			}
			stack, err := newGitHubHandler(config, logger)
			handler, wait := stack.Handler, stack.Wait
			if err != nil {
				t.Fatal(err)
			}
			defer wait()
			request := httptest.NewRequest(http.MethodPost, "/webhooks/github", strings.NewReader("{}"))
			request.Header.Set("X-GitHub-Event", "pull_request")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if got := response.Code == http.StatusUnauthorized; got != tc.wantWebhook {
				t.Errorf("unsigned webhook status %d, webhook mounted = %v, want %v", response.Code, got, tc.wantWebhook)
			}
			if tc.wantWebhook {
				health := httptest.NewRecorder()
				handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
				if health.Code != http.StatusOK {
					t.Errorf("/healthz status %d", health.Code)
				}
			}
		})
	}
}

func TestLoggerLevelsAndSecretRedaction(t *testing.T) {
	var out strings.Builder
	logger, err := newLogger(func(name string) string {
		if name == "DEPLOYGUARD_LOG_LEVEL" {
			return "warn"
		}
		return ""
	}, &out)
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("hidden by level")
	logger.Warn("shown", "api_key", "sk-very-secret", "webhook_secret", "hush", "repository_id", 7)
	logged := out.String()
	if strings.Contains(logged, "hidden by level") || strings.Contains(logged, "sk-very-secret") || strings.Contains(logged, "hush") {
		t.Errorf("log leaked or ignored its level: %s", logged)
	}
	if !strings.Contains(logged, `"repository_id":7`) || !strings.Contains(logged, "[REDACTED]") {
		t.Errorf("non-secret fields must stay visible: %s", logged)
	}
	if _, err := newLogger(func(string) string { return "loud" }, io.Discard); err == nil {
		t.Error("an unknown log level must be rejected")
	}
}

func TestSlogAuditorLogsOutcomeWithoutContent(t *testing.T) {
	var out strings.Builder
	logger, _ := newLogger(func(string) string { return "" }, &out)
	slogAuditor{logger: logger}.Record(context.Background(), gh.AuditEvent{Outcome: gh.AuditRejectedSignature, EventType: "pull_request", InstallationID: 4, RepositoryID: 9})
	for _, want := range []string{`"outcome":"rejected_signature"`, `"level":"WARN"`, `"repository_id":9`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("audit line missing %s: %s", want, out.String())
		}
	}
}

func TestPartialGitHubConfigurationNamesTriggersAndMissingVariables(t *testing.T) {
	_, err := loadConfig(func(name string) string {
		if name == "DEPLOYGUARD_PUBLIC_ORIGIN" {
			return "https://secret-looking-value.example"
		}
		return ""
	})
	if err == nil {
		t.Fatal("partial configuration must fail")
	}
	for _, want := range []string{"GitHub mode is on because", "DEPLOYGUARD_PUBLIC_ORIGIN", "DEPLOYGUARD_GITHUB_APP_ID", "unset"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "secret-looking-value") {
		t.Error("the error must name variables, never print their values")
	}
}

func TestListenErrorExplainsBusyPort(t *testing.T) {
	first, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	_, err = net.Listen("tcp", first.Addr().String())
	got := listenError(first.Addr().String(), err)
	if !strings.Contains(got.Error(), "already in use") || !strings.Contains(got.Error(), "DEPLOYGUARD_LISTEN_ADDRESS") {
		t.Fatalf("unhelpful error: %v", got)
	}
}

func TestLoadExplainerSelectsProviderFromEnvironment(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	for name, tc := range map[string]struct {
		env       map[string]string
		wantAI    bool
		wantError bool
	}{
		"nothing set keeps AI off":        {map[string]string{}, false, false},
		"provider alone, no key":          {map[string]string{"DEPLOYGUARD_AI_PROVIDER": "openai"}, false, true},
		"openai with default base URL":    {map[string]string{"DEPLOYGUARD_AI_PROVIDER": "openai", "DEPLOYGUARD_AI_API_KEY": "k", "DEPLOYGUARD_AI_MODEL": "m"}, true, false},
		"gemini":                          {map[string]string{"DEPLOYGUARD_AI_PROVIDER": "gemini", "DEPLOYGUARD_AI_API_KEY": "k", "DEPLOYGUARD_AI_MODEL": "gemini-2.0-flash"}, true, false},
		"mistral":                         {map[string]string{"DEPLOYGUARD_AI_PROVIDER": "mistral", "DEPLOYGUARD_AI_API_KEY": "k", "DEPLOYGUARD_AI_MODEL": "m"}, true, false},
		"legacy base URL means anthropic": {map[string]string{"DEPLOYGUARD_AI_BASE_URL": "http://127.0.0.1:20128", "DEPLOYGUARD_AI_API_KEY": "k", "DEPLOYGUARD_AI_MODEL": "m"}, true, false},
		"unknown provider":                {map[string]string{"DEPLOYGUARD_AI_PROVIDER": "skynet", "DEPLOYGUARD_AI_API_KEY": "k", "DEPLOYGUARD_AI_MODEL": "m"}, false, true},
		"key alone does not enable AI":    {map[string]string{"DEPLOYGUARD_AI_API_KEY": "k", "DEPLOYGUARD_AI_MODEL": "m"}, false, false},
	} {
		t.Run(name, func(t *testing.T) {
			explainer, err := loadExplainer(env(tc.env))
			if (err != nil) != tc.wantError || (explainer != nil) != tc.wantAI {
				t.Fatalf("explainer enabled = %v, err = %v; want enabled %v, error %v", explainer != nil, err, tc.wantAI, tc.wantError)
			}
		})
	}
}

func TestPRCommentsSettingValidation(t *testing.T) {
	long := strings.Repeat("s", 24)
	plan := map[string]string{"DEPLOYGUARD_PLAN_WORKFLOW_FILENAME": "plan.yml", "DEPLOYGUARD_PLAN_ARTIFACT_NAME": "plan"}
	with := func(extra map[string]string) map[string]string {
		merged := map[string]string{}
		for k, v := range plan {
			merged[k] = v
		}
		for k, v := range extra {
			merged[k] = v
		}
		return merged
	}
	if _, err := loadConfig(githubTestEnv(t, with(map[string]string{"DEPLOYGUARD_PR_COMMENTS": "maybe"}))); err == nil {
		t.Error("a non-boolean value must be rejected")
	}
	if _, err := loadConfig(githubTestEnv(t, with(map[string]string{"DEPLOYGUARD_PR_COMMENTS": "true"}))); err == nil {
		t.Error("comments without the webhook must be rejected")
	}
	config, err := loadConfig(githubTestEnv(t, with(map[string]string{"DEPLOYGUARD_PR_COMMENTS": "true", "DEPLOYGUARD_GITHUB_WEBHOOK_SECRET": long})))
	if err != nil || !config.prComments {
		t.Fatalf("valid comment configuration: %v", err)
	}
	config, err = loadConfig(githubTestEnv(t, with(map[string]string{"DEPLOYGUARD_GITHUB_WEBHOOK_SECRET": long})))
	if err != nil || config.prComments {
		t.Fatalf("comments must be off by default: %v %v", err, config.prComments)
	}
}

func TestDatabaseAndRetentionSettings(t *testing.T) {
	base := map[string]string{}
	with := func(extra map[string]string) func(string) string {
		merged := map[string]string{}
		for k, v := range base {
			merged[k] = v
		}
		for k, v := range extra {
			merged[k] = v
		}
		return githubTestEnv(t, merged)
	}
	for name, extra := range map[string]map[string]string{
		"remote database without TLS": {"DEPLOYGUARD_DATABASE_URL": "postgres://u:p@db.example.com/dg"},
		"not a postgres URL":          {"DEPLOYGUARD_DATABASE_URL": "mysql://u:p@localhost/dg"},
		"retention zero":              {"DEPLOYGUARD_RETENTION_DAYS": "0"},
		"retention too long":          {"DEPLOYGUARD_RETENTION_DAYS": "4000"},
		"retention not a number":      {"DEPLOYGUARD_RETENTION_DAYS": "soon"},
	} {
		if _, err := loadConfig(with(extra)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	config, err := loadConfig(with(map[string]string{"DEPLOYGUARD_DATABASE_URL": "postgres://u:p@localhost/dg", "DEPLOYGUARD_RETENTION_DAYS": "30"}))
	if err != nil || config.databaseURL == "" || config.retentionDays != 30 {
		t.Fatalf("valid database config: %v %+v", err, config.retentionDays)
	}
	config, err = loadConfig(with(nil))
	if err != nil || config.databaseURL != "" || config.retentionDays != 90 {
		t.Fatalf("database must be off with a 90-day default: %v", err)
	}
	// A database URL alone must not silently start local mode, and the message must not print it.
	_, err = loadConfig(func(name string) string {
		if name == "DEPLOYGUARD_DATABASE_URL" {
			return "postgres://u:hunter2@localhost/dg"
		}
		return ""
	})
	if err == nil || strings.Contains(err.Error(), "hunter2") || !strings.Contains(err.Error(), "DEPLOYGUARD_DATABASE_URL") {
		t.Fatalf("expected a GitHub-mode error naming the variable without its value: %v", err)
	}
}

func TestPurgeLoopDeletesOldVerdicts(t *testing.T) {
	memory := store.NewMemory()
	now := time.Now()
	for i, at := range []time.Time{now.Add(-200 * 24 * time.Hour), now.Add(-time.Hour)} {
		if err := memory.RecordAnalysis(context.Background(), store.Analysis{
			InstallationID: 1, RepositoryID: 1, RepositoryFullName: "a/b", PullRequest: i + 1, HeadSHA: "abc",
			Recommendation: "SAFE", Level: "LOW", CreatedAt: at,
		}); err != nil {
			t.Fatal(err)
		}
	}
	logger, _ := newLogger(func(string) string { return "" }, io.Discard)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { purgeLoop(ctx, memory, 90*24*time.Hour, logger); close(done) }()
	deadline := time.After(5 * time.Second)
	for {
		rows, _ := memory.ListAnalyses(context.Background(), 1, 10)
		if len(rows) == 1 && rows[0].PullRequest == 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("old verdict was not purged: %+v", rows)
		case <-time.After(20 * time.Millisecond):
		}
	}
	cancel()
	<-done
}

func TestProvenanceSettingRequiresPlanWorkflowAndAValidRootFile(t *testing.T) {
	if _, err := loadConfig(githubTestEnv(t, map[string]string{"DEPLOYGUARD_PROVENANCE_TRUSTED_ROOT": "/tmp/root.json"})); err == nil {
		t.Error("provenance without the plan workflow name must be rejected")
	}
	plan := map[string]string{"DEPLOYGUARD_PLAN_WORKFLOW_FILENAME": "plan.yml", "DEPLOYGUARD_PLAN_ARTIFACT_NAME": "plan"}
	env := githubTestEnv(t, map[string]string{
		"DEPLOYGUARD_PLAN_WORKFLOW_FILENAME": plan["DEPLOYGUARD_PLAN_WORKFLOW_FILENAME"], "DEPLOYGUARD_PLAN_ARTIFACT_NAME": plan["DEPLOYGUARD_PLAN_ARTIFACT_NAME"],
		"DEPLOYGUARD_PROVENANCE_TRUSTED_ROOT": "/nonexistent/trusted_root.json",
	})
	config, err := loadConfig(env)
	if err != nil || config.provenanceRoot == "" {
		t.Fatalf("valid provenance configuration: %v", err)
	}
	logger, _ := newLogger(func(string) string { return "" }, io.Discard)
	if _, err := newGitHubHandler(config, logger); err == nil || !strings.Contains(err.Error(), "trusted root") {
		t.Fatalf("a missing trusted root file must stop startup: %v", err)
	}
}

func TestHistoryPathChoices(t *testing.T) {
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == "DEPLOYGUARD_HISTORY_FILE" {
				return v
			}
			return ""
		}
	}
	for _, off := range []string{"off", "OFF", "none", "false", "0"} {
		if got := historyPath(env(off)); got != "" {
			t.Errorf("%q must turn history off, got %q", off, got)
		}
	}
	if got := historyPath(env("/var/lib/deployguard/h.jsonl")); got != "/var/lib/deployguard/h.jsonl" {
		t.Errorf("an absolute path is used as given, got %q", got)
	}
	if got := historyPath(env("relative/h.jsonl")); got != "" {
		t.Errorf("a relative path depends on the working directory, so history stays off, got %q", got)
	}
	if got := historyPath(env("")); !strings.HasSuffix(got, "/deployguard/history.jsonl") {
		t.Errorf("the default lives in the user's config folder, got %q", got)
	}
	config, err := loadConfig(func(k string) string {
		if k == "DEPLOYGUARD_HISTORY_FILE" {
			return "off"
		}
		return ""
	})
	if err != nil || !config.localOnly || config.historyFile != "" {
		t.Errorf("local mode with history off: %v %+v", err, config)
	}
}
