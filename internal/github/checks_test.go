package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net/http"
	"strings"
	"testing"
)

func newChecksTestClient(t *testing.T, handler func(*http.Request, string) *http.Response) *ChecksClient {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/app/installations/42/access_tokens" {
			return response(http.StatusCreated, `{"token":"t","expires_at":"2099-01-01T00:00:00Z"}`), nil
		}
		var body []byte
		if request.Body != nil {
			body, _ = io.ReadAll(request.Body)
		}
		return handler(request, string(body)), nil
	})}
	app, err := NewAppAuthenticator(AppAuthenticatorConfig{AppID: 101, PrivateKeyPEM: privateKeyPEM(key), APIBaseURL: "https://api.github.test", HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	checks, err := NewChecksClient(app)
	if err != nil {
		t.Fatal(err)
	}
	return checks
}

func TestPublishCreatesCheckRunWhenNoneExists(t *testing.T) {
	var created string
	checks := newChecksTestClient(t, func(r *http.Request, body string) *http.Response {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/app/commits/abc1234/check-runs":
			if q := r.URL.Query(); q.Get("check_name") != CheckRunName || q.Get("app_id") != "101" {
				t.Errorf("lookup must filter by name and app: %v", q)
			}
			return response(http.StatusOK, `{"check_runs":[]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/app/check-runs":
			created = body
			return response(http.StatusCreated, `{}`)
		}
		return response(http.StatusNotFound, "")
	})
	err := checks.Publish(context.Background(), 42, 7, "acme/app", CheckRun{HeadSHA: "abc1234", Conclusion: "failure", Title: "BLOCK", Summary: "details"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"head_sha":"abc1234"`, `"conclusion":"failure"`, `"name":"DeployGuard"`, `"status":"completed"`} {
		if !strings.Contains(created, want) {
			t.Errorf("created body %s missing %s", created, want)
		}
	}
}

func TestPublishUpdatesExistingCheckRunInsteadOfDuplicating(t *testing.T) {
	var method, path string
	checks := newChecksTestClient(t, func(r *http.Request, body string) *http.Response {
		if r.Method == http.MethodGet {
			return response(http.StatusOK, `{"check_runs":[{"id":555}]}`)
		}
		method, path = r.Method, r.URL.Path
		if strings.Contains(body, "head_sha") {
			t.Error("update must not resend head_sha")
		}
		return response(http.StatusOK, `{}`)
	})
	if err := checks.Publish(context.Background(), 42, 7, "acme/app", CheckRun{HeadSHA: "abc1234", Conclusion: "success", Title: "SAFE", Summary: "ok"}); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPatch || path != "/repos/acme/app/check-runs/555" {
		t.Fatalf("got %s %s, want PATCH of the existing run", method, path)
	}
}

func TestPublishRejectsInvalidInputBeforeAnyRequest(t *testing.T) {
	checks := newChecksTestClient(t, func(*http.Request, string) *http.Response {
		t.Error("no request expected")
		return response(http.StatusInternalServerError, "")
	})
	for name, call := range map[string]struct {
		repo string
		run  CheckRun
	}{
		"bad repo":       {"nope", CheckRun{HeadSHA: "abc1234", Conclusion: "success"}},
		"query in repo":  {"acme/app?x=1", CheckRun{HeadSHA: "abc1234", Conclusion: "success"}},
		"bad sha":        {"acme/app", CheckRun{HeadSHA: "../etc", Conclusion: "success"}},
		"bad conclusion": {"acme/app", CheckRun{HeadSHA: "abc1234", Conclusion: "action_required"}},
	} {
		if err := checks.Publish(context.Background(), 42, 7, call.repo, call.run); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestTruncateBytesKeepsValidUTF8(t *testing.T) {
	if got := truncateBytes("ééé", 3); got != "é" {
		t.Fatalf("got %q", got)
	}
}
