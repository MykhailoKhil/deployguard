// Command github-app-setup registers a GitHub App for DeployGuard using GitHub's App Manifest
// flow and writes the resulting credentials to an env file (mode 0600). Secrets are never printed.
//
// Usage: go run ./cmd/github-app-setup -origin https://your-public-host
package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	githubNewAppURL = "https://github.com/settings/apps/new"
	githubAPIURL    = "https://api.github.com"
	waitForCallback = 10 * time.Minute
)

type options struct {
	origin   string // public HTTPS origin of the DeployGuard server
	name     string // GitHub App name (must be unique on GitHub)
	out      string // env file to create
	workflow string // plan workflow file name
	artifact string // plan artifact name
	force    bool   // overwrite an existing env file
	// prComments requests Pull requests: write so DeployGuard can keep one comment per PR.
	prComments bool
	// provenance requests Attestations: read so DeployGuard can look up plan attestations.
	provenance bool
}

// credentials are the secrets GitHub returns once, when the manifest code is exchanged.
type credentials struct {
	ID            int64  `json:"id"`
	Slug          string `json:"slug"`
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret"`
	WebhookSecret string `json:"webhook_secret"`
	PEM           string `json:"pem"`
}

func main() {
	var opts options
	flag.StringVar(&opts.origin, "origin", "", "public HTTPS origin of DeployGuard, e.g. https://deployguard.example.com (required)")
	flag.StringVar(&opts.name, "name", "DeployGuard", "GitHub App name (must be unique on GitHub)")
	flag.StringVar(&opts.out, "out", ".env.github", "env file to create")
	flag.StringVar(&opts.workflow, "workflow", "deployguard-plan.yml", "file name of the workflow that builds the plan")
	flag.StringVar(&opts.artifact, "artifact", "deployguard-plan", "name of the plan artifact")
	flag.BoolVar(&opts.prComments, "pr-comments", false, "also request Pull requests: write so DeployGuard can post a PR comment (off by default)")
	flag.BoolVar(&opts.provenance, "provenance", false, "also request Attestations: read so DeployGuard can verify plan attestations (off by default)")
	flag.BoolVar(&opts.force, "force", false, "overwrite the output file if it exists")
	flag.Parse()
	if err := run(opts); err != nil {
		log.Fatalf("github-app-setup: %v", err)
	}
}

func run(opts options) error {
	if err := validateOptions(opts); err != nil {
		return err
	}
	if _, err := os.Stat(opts.out); err == nil && !opts.force {
		return fmt.Errorf("%s already exists; use -force to overwrite it", opts.out)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	state, err := randomHex(16)
	if err != nil {
		return err
	}
	redirect := "http://" + listener.Addr().String() + "/callback"
	manifest, err := buildManifest(opts, redirect)
	if err != nil {
		return err
	}
	done := make(chan error, 1)
	server := &http.Server{
		Handler:           newHandler(opts, manifest, state, githubAPIURL, http.DefaultClient, done),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = server.Serve(listener) }()
	fmt.Printf("1. Open http://%s/start in a browser that is signed in to GitHub.\n", listener.Addr())
	fmt.Println("2. GitHub will ask you to confirm; click \"Create GitHub App\".")
	fmt.Printf("Waiting up to %s...\n", waitForCallback)
	select {
	case err = <-done:
	case <-time.After(waitForCallback):
		err = errors.New("timed out waiting for GitHub")
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdown)
	return err
}

func validateOptions(opts options) error {
	origin, err := url.Parse(opts.origin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return errors.New("-origin must be an HTTPS origin without a path, e.g. https://deployguard.example.com")
	}
	if strings.TrimSpace(opts.name) == "" || len(opts.name) > 34 {
		return errors.New("-name must be 1 to 34 characters")
	}
	if strings.ContainsAny(opts.workflow, "/\\?#") || strings.Contains(opts.workflow, "..") || opts.workflow == "" {
		return errors.New("-workflow must be a plain file name")
	}
	if strings.ContainsAny(opts.artifact, "/\\?#") || strings.Contains(opts.artifact, "..") || opts.artifact == "" {
		return errors.New("-artifact must be a plain name")
	}
	return nil
}

// buildManifest returns the App Manifest JSON: least-privilege permissions, only the two events
// DeployGuard handles, and a private App.
func buildManifest(opts options, redirect string) (string, error) {
	permissions := map[string]string{"checks": "write", "pull_requests": "read", "actions": "read", "metadata": "read"}
	if opts.prComments {
		permissions["pull_requests"] = "write"
	}
	if opts.provenance {
		permissions["attestations"] = "read"
	}
	manifest := map[string]any{
		"name":                opts.name,
		"url":                 opts.origin,
		"redirect_url":        redirect,
		"callback_urls":       []string{opts.origin + "/auth/github/callback"},
		"public":              false,
		"hook_attributes":     map[string]any{"url": opts.origin + "/webhooks/github", "active": true},
		"default_permissions": permissions,
		"default_events":      []string{"pull_request", "workflow_run"},
	}
	encoded, err := json.Marshal(manifest)
	return string(encoded), err
}

var startPage = template.Must(template.New("start").Parse(`<!doctype html><meta charset="utf-8"><title>DeployGuard App setup</title>
<form id="f" method="post" action="{{.Action}}"><input type="hidden" name="manifest" value="{{.Manifest}}">
<noscript><p>JavaScript is off. Click the button to continue to GitHub.</p></noscript><button>Continue to GitHub</button></form>
<script>document.getElementById("f").submit()</script>`))

// newHandler serves /start (hands the manifest to GitHub) and /callback (receives the one-time
// code, exchanges it, writes the env file). The result is sent on done exactly once.
func newHandler(opts options, manifest, state, apiURL string, client *http.Client, done chan<- error) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		_ = startPage.Execute(w, map[string]string{"Action": githubNewAppURL + "?state=" + url.QueryEscape(state), "Manifest": manifest})
	})
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(state)) != 1 || q.Get("code") == "" {
			http.Error(w, "invalid state or missing code", http.StatusBadRequest)
			return // keep waiting for the real callback
		}
		creds, err := exchange(r.Context(), client, apiURL, q.Get("code"))
		if err == nil {
			err = writeEnv(opts, creds)
		}
		if err != nil {
			http.Error(w, "setup failed; see the terminal", http.StatusInternalServerError)
			done <- err
			return
		}
		fmt.Fprintf(w, "GitHub App created. Return to the terminal for the next step. You can close this tab.")
		fmt.Printf("\nCreated GitHub App %q (ID %d). Credentials written to %s (mode 0600).\n", creds.Slug, creds.ID, opts.out)
		fmt.Printf("Next: install it on a repository: https://github.com/apps/%s/installations/new\n", creds.Slug)
		if opts.provenance {
			fmt.Println("Provenance: run `gh attestation trusted-root > trusted_root.jsonl`, set DEPLOYGUARD_PROVENANCE_TRUSTED_ROOT to that file, and enable the attest step in your plan workflow.")
		}
		fmt.Printf("Then start DeployGuard: set -a && source %s && set +a && go run ./cmd/deployguard\n", opts.out)
		done <- nil
	})
	return mux
}

// exchange trades the one-time manifest code for the App's credentials.
func exchange(ctx context.Context, client *http.Client, apiURL, code string) (credentials, error) {
	endpoint := apiURL + "/app-manifests/" + url.PathEscape(code) + "/conversions"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return credentials{}, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	response, err := client.Do(request)
	if err != nil {
		return credentials{}, errors.New("contact GitHub: request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return credentials{}, fmt.Errorf("GitHub rejected the manifest code (status %d); it is single-use and expires after an hour", response.StatusCode)
	}
	var creds credentials
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&creds); err != nil || creds.ID <= 0 || creds.ClientID == "" || creds.ClientSecret == "" || creds.WebhookSecret == "" || creds.PEM == "" || creds.Slug == "" {
		return credentials{}, errors.New("GitHub returned an incomplete App description")
	}
	return creds, nil
}

// safeValue limits what may be written unquoted or quoted into an env file that users `source`.
var safeValue = regexp.MustCompile(`^[A-Za-z0-9_.:/+=\- \n]*$`)

// writeEnv creates the env file with mode 0600. It refuses to overwrite unless opts.force is set.
func writeEnv(opts options, c credentials) error {
	for _, value := range []string{c.ClientID, c.ClientSecret, c.WebhookSecret, c.PEM, c.Slug} {
		if !safeValue.MatchString(value) {
			return errors.New("GitHub returned a value that is not safe to write to an env file")
		}
	}
	content := fmt.Sprintf(`# DeployGuard GitHub-mode settings created by github-app-setup. Contains secrets: keep out of git.
# Load with: set -a && source %s && set +a
DEPLOYGUARD_PUBLIC_ORIGIN=%s
DEPLOYGUARD_GITHUB_APP_ID=%d
DEPLOYGUARD_GITHUB_OAUTH_CLIENT_ID=%s
DEPLOYGUARD_GITHUB_OAUTH_CLIENT_SECRET=%s
DEPLOYGUARD_GITHUB_OAUTH_REDIRECT_URL=%s/auth/github/callback
DEPLOYGUARD_GITHUB_WEBHOOK_SECRET=%s
DEPLOYGUARD_PLAN_WORKFLOW_FILENAME=%s
DEPLOYGUARD_PLAN_ARTIFACT_NAME=%s
DEPLOYGUARD_GITHUB_PRIVATE_KEY_PEM="%s"
%s`, opts.out, opts.origin, c.ID, c.ClientID, c.ClientSecret, opts.origin, c.WebhookSecret, opts.workflow, opts.artifact, strings.TrimSpace(c.PEM), optionalLines(opts))
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if opts.force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	file, err := os.OpenFile(opts.out, flags, 0o600)
	if err != nil {
		return fmt.Errorf("write %s: %w", opts.out, err)
	}
	defer file.Close()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	_, err = file.WriteString(content)
	return err
}

// optionalLines returns the env lines that depend on optional flags.
func optionalLines(opts options) string {
	if opts.prComments {
		return "DEPLOYGUARD_PR_COMMENTS=true\n"
	}
	return ""
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
