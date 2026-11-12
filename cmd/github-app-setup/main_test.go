package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testOptions(t *testing.T) options {
	t.Helper()
	return options{origin: "https://dg.example.com", name: "DG Test", out: filepath.Join(t.TempDir(), ".env.github"), workflow: "plan.yml", artifact: "plan"}
}

const fakePEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n-----END RSA PRIVATE KEY-----\n"

func fakeGitHub(t *testing.T, status int, body string) (*httptest.Server, *int) {
	t.Helper()
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/app-manifests/the-code/conversions" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server, &calls
}

func goodBody() string {
	b, _ := json.Marshal(credentials{ID: 77, Slug: "dg-test", ClientID: "Iv1.abc123", ClientSecret: "csecret0123", WebhookSecret: "whsecret0123", PEM: fakePEM})
	return string(b)
}

func TestManifestIsLeastPrivilegeAndPointsAtTheOrigin(t *testing.T) {
	opts := testOptions(t)
	raw, err := buildManifest(opts, "http://127.0.0.1:9/callback")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		URL         string            `json:"url"`
		Redirect    string            `json:"redirect_url"`
		Callbacks   []string          `json:"callback_urls"`
		Public      bool              `json:"public"`
		Hook        map[string]any    `json:"hook_attributes"`
		Permissions map[string]string `json:"default_permissions"`
		Events      []string          `json:"default_events"`
	}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	if m.Public || m.Hook["url"] != "https://dg.example.com/webhooks/github" || m.Callbacks[0] != "https://dg.example.com/auth/github/callback" || m.Redirect != "http://127.0.0.1:9/callback" {
		t.Errorf("manifest URLs wrong: %s", raw)
	}
	want := map[string]string{"checks": "write", "pull_requests": "read", "actions": "read", "metadata": "read"}
	if len(m.Permissions) != len(want) {
		t.Errorf("permissions %v, want exactly %v", m.Permissions, want)
	}
	for k, v := range want {
		if m.Permissions[k] != v {
			t.Errorf("permission %s = %q, want %q", k, m.Permissions[k], v)
		}
	}
	if len(m.Events) != 2 || m.Events[0] != "pull_request" || m.Events[1] != "workflow_run" {
		t.Errorf("events %v", m.Events)
	}
}

func TestValidateOptionsRejectsUnsafeInput(t *testing.T) {
	for name, mutate := range map[string]func(*options){
		"http origin":     func(o *options) { o.origin = "http://dg.example.com" },
		"origin path":     func(o *options) { o.origin = "https://dg.example.com/x" },
		"origin userinfo": func(o *options) { o.origin = "https://u:p@dg.example.com" },
		"empty name":      func(o *options) { o.name = " " },
		"workflow path":   func(o *options) { o.workflow = "../x.yml" },
		"artifact slash":  func(o *options) { o.artifact = "a/b" },
	} {
		opts := testOptions(t)
		mutate(&opts)
		if validateOptions(opts) == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if err := validateOptions(testOptions(t)); err != nil {
		t.Errorf("valid options rejected: %v", err)
	}
}

func TestCallbackWritesPrivateEnvFileWithoutLeakingSecrets(t *testing.T) {
	github, calls := fakeGitHub(t, http.StatusCreated, goodBody())
	opts := testOptions(t)
	done := make(chan error, 1)
	handler := newHandler(opts, "{}", "state1", github.URL, github.Client(), done)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/callback?code=the-code&state=state1", nil))
	if err := <-done; err != nil || *calls != 1 || response.Code != http.StatusOK {
		t.Fatalf("done=%v calls=%d status=%d", err, *calls, response.Code)
	}
	for _, secret := range []string{"csecret0123", "whsecret0123", "PRIVATE KEY"} {
		if strings.Contains(response.Body.String(), secret) {
			t.Errorf("response leaked %q", secret)
		}
	}
	info, err := os.Stat(opts.out)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("env file mode = %v, err = %v; want 0600", info.Mode().Perm(), err)
	}
	content, _ := os.ReadFile(opts.out)
	for _, want := range []string{"DEPLOYGUARD_GITHUB_APP_ID=77", "DEPLOYGUARD_GITHUB_OAUTH_CLIENT_SECRET=csecret0123", "DEPLOYGUARD_GITHUB_WEBHOOK_SECRET=whsecret0123",
		"DEPLOYGUARD_GITHUB_OAUTH_REDIRECT_URL=https://dg.example.com/auth/github/callback", "DEPLOYGUARD_PLAN_WORKFLOW_FILENAME=plan.yml", `DEPLOYGUARD_GITHUB_PRIVATE_KEY_PEM="-----BEGIN RSA PRIVATE KEY-----`} {
		if !strings.Contains(string(content), want) {
			t.Errorf("env file missing %q", want)
		}
	}
}

func TestCallbackIgnoresWrongStateAndMissingCode(t *testing.T) {
	github, calls := fakeGitHub(t, http.StatusCreated, goodBody())
	opts := testOptions(t)
	done := make(chan error, 1)
	handler := newHandler(opts, "{}", "state1", github.URL, github.Client(), done)
	for _, target := range []string{"/callback?code=the-code&state=wrong", "/callback?state=state1", "/callback"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, target, nil))
		if response.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", target, response.Code)
		}
	}
	if *calls != 0 || len(done) != 0 {
		t.Fatalf("a bad callback must not contact GitHub or finish setup (calls=%d)", *calls)
	}
	if _, err := os.Stat(opts.out); err == nil {
		t.Fatal("no env file may be written for a bad callback")
	}
}

func TestExchangeRejectsFailureAndIncompleteResponses(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		body   string
	}{
		"rejected code": {http.StatusNotFound, `{}`},
		"incomplete":    {http.StatusCreated, `{"id":1}`},
		"not json":      {http.StatusCreated, `nope`},
	} {
		github, _ := fakeGitHub(t, tc.status, tc.body)
		if _, err := exchange(t.Context(), github.Client(), github.URL, "the-code"); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestWriteEnvRefusesOverwriteUnlessForced(t *testing.T) {
	opts := testOptions(t)
	creds := credentials{ID: 1, Slug: "s", ClientID: "c", ClientSecret: "x", WebhookSecret: "w", PEM: fakePEM}
	if err := writeEnv(opts, creds); err != nil {
		t.Fatal(err)
	}
	if err := writeEnv(opts, creds); err == nil {
		t.Fatal("second write must not overwrite an existing file")
	}
	opts.force = true
	if err := writeEnv(opts, creds); err != nil {
		t.Fatalf("forced write failed: %v", err)
	}
}

func TestWriteEnvRejectsValuesThatCouldBreakTheFile(t *testing.T) {
	opts := testOptions(t)
	bad := credentials{ID: 1, Slug: "s", ClientID: "c", ClientSecret: "x\"; rm -rf ~; \"", WebhookSecret: "w", PEM: fakePEM}
	if err := writeEnv(opts, bad); err == nil {
		t.Fatal("a value with shell metacharacters must be refused")
	}
	if _, err := os.Stat(opts.out); err == nil {
		t.Fatal("nothing may be written when a value is unsafe")
	}
}

func TestStartPageEscapesTheManifest(t *testing.T) {
	opts := testOptions(t)
	handler := newHandler(opts, `{"name":"a\"><script>x</script>"}`, "s", "http://unused", http.DefaultClient, make(chan error, 1))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/start", nil))
	body := response.Body.String()
	if strings.Contains(body, "<script>x</script>") || !strings.Contains(body, "https://github.com/settings/apps/new?state=s") {
		t.Fatalf("start page wrong: %s", body)
	}
}

func TestPRCommentsFlagRaisesOnlyPullRequestsToWrite(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		opts := testOptions(t)
		opts.prComments = enabled
		raw, err := buildManifest(opts, "http://127.0.0.1:9/callback")
		if err != nil {
			t.Fatal(err)
		}
		var m struct {
			Permissions map[string]string `json:"default_permissions"`
		}
		_ = json.Unmarshal([]byte(raw), &m)
		want := "read"
		if enabled {
			want = "write"
		}
		if m.Permissions["pull_requests"] != want || m.Permissions["checks"] != "write" || m.Permissions["actions"] != "read" || len(m.Permissions) != 4 {
			t.Errorf("prComments=%v permissions %v", enabled, m.Permissions)
		}
	}
	opts := testOptions(t)
	opts.prComments = true
	if err := writeEnv(opts, credentials{ID: 1, Slug: "s", ClientID: "c", ClientSecret: "x", WebhookSecret: "w", PEM: fakePEM}); err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(opts.out)
	if !strings.Contains(string(content), "DEPLOYGUARD_PR_COMMENTS=true") {
		t.Error("env file should enable comments when the flag is set")
	}
}

func TestProvenanceFlagAddsOnlyAttestationsRead(t *testing.T) {
	opts := testOptions(t)
	opts.provenance = true
	raw, err := buildManifest(opts, "http://127.0.0.1:9/callback")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Permissions map[string]string `json:"default_permissions"`
	}
	_ = json.Unmarshal([]byte(raw), &m)
	if m.Permissions["attestations"] != "read" || m.Permissions["pull_requests"] != "read" || len(m.Permissions) != 5 {
		t.Errorf("permissions %v", m.Permissions)
	}
	raw, _ = buildManifest(testOptions(t), "http://127.0.0.1:9/callback")
	if strings.Contains(raw, "attestations") {
		t.Error("attestations must not be requested by default")
	}
}
