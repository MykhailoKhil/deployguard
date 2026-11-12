package github

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWebhookHandlerAcceptsVerifiedPullRequestEvent(t *testing.T) {
	processor := &recordingProcessor{}
	verifier := &recordingVerifier{}
	auditor := &recordingAuditor{}
	handler, err := NewWebhookHandler(WebhookConfig{
		WebhookSecret: []byte("test-secret"),
		Verifier:      verifier,
		Processor:     processor,
		Auditor:       auditor,
		Limiter:       allowAllLimiter{},
	})
	if err != nil {
		t.Fatalf("NewWebhookHandler() error = %v", err)
	}

	body := []byte(`{"action":"synchronize","installation":{"id":42},"repository":{"id":7,"full_name":"acme/deployguard"},"pull_request":{"number":12,"head":{"sha":"abc123"}}}`)
	request := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(body))
	request.Header.Set("X-GitHub-Event", "pull_request")
	request.Header.Set("X-Hub-Signature-256", signature("test-secret", body))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusAccepted)
	}
	if verifier.installationID != 42 || verifier.repositoryID != 7 || verifier.fullName != "acme/deployguard" {
		t.Fatalf("verifier received %#v", verifier)
	}
	if processor.event.PullRequestNumber != 12 || processor.event.HeadSHA != "abc123" {
		t.Fatalf("processor received %#v", processor.event)
	}
	if auditor.last.Outcome != AuditAccepted || auditor.last.RepositoryID != 7 {
		t.Fatalf("audit event = %#v", auditor.last)
	}
}

func TestWebhookHandlerRejectsInvalidSignatureBeforeProcessing(t *testing.T) {
	processor := &recordingProcessor{}
	handler, err := NewWebhookHandler(WebhookConfig{
		WebhookSecret: []byte("test-secret"),
		Verifier:      &recordingVerifier{},
		Processor:     processor,
		Limiter:       allowAllLimiter{},
	})
	if err != nil {
		t.Fatalf("NewWebhookHandler() error = %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewBufferString(`{"action":"opened"}`))
	request.Header.Set("X-GitHub-Event", "pull_request")
	request.Header.Set("X-Hub-Signature-256", "sha256=bad")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if processor.called {
		t.Fatal("processor was called for an invalid signature")
	}
}

func TestWebhookHandlerRejectsUnverifiedRepository(t *testing.T) {
	body := []byte(`{"action":"opened","installation":{"id":42},"repository":{"id":7,"full_name":"acme/deployguard"},"pull_request":{"number":12,"head":{"sha":"abc123"}}}`)
	handler, err := NewWebhookHandler(WebhookConfig{
		WebhookSecret: []byte("test-secret"),
		Verifier:      rejectingVerifier{},
		Processor:     &recordingProcessor{},
		Limiter:       allowAllLimiter{},
	})
	if err != nil {
		t.Fatalf("NewWebhookHandler() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(body))
	request.Header.Set("X-GitHub-Event", "pull_request")
	request.Header.Set("X-Hub-Signature-256", signature("test-secret", body))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
}

func signature(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

type recordingProcessor struct {
	called bool
	event  PullRequestEvent
}

func (p *recordingProcessor) ProcessPullRequest(_ context.Context, event PullRequestEvent) error {
	p.called = true
	p.event = event
	return nil
}

type recordingVerifier struct {
	installationID int64
	repositoryID   int64
	fullName       string
}

func (v *recordingVerifier) VerifyRepository(_ context.Context, installationID, repositoryID int64, fullName string) error {
	v.installationID = installationID
	v.repositoryID = repositoryID
	v.fullName = fullName
	return nil
}

type rejectingVerifier struct{}

func (rejectingVerifier) VerifyRepository(context.Context, int64, int64, string) error {
	return ErrRepositoryNotInstalled
}

type recordingAuditor struct{ last AuditEvent }

func (a *recordingAuditor) Record(_ context.Context, event AuditEvent) { a.last = event }

type allowAllLimiter struct{}

func (allowAllLimiter) Allow(string) bool { return true }

func TestMemoryRateLimiterEvictsExpiredWindowsAndCapsEntries(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	limiter := NewMemoryRateLimiter(1, time.Minute)
	limiter.now = func() time.Time { return now }
	if !limiter.Allow("a") || limiter.Allow("a") {
		t.Fatal("expected one request per window")
	}
	now = now.Add(2 * time.Minute)
	if !limiter.Allow("b") {
		t.Fatal("new window should allow requests")
	}
	if len(limiter.entries) != 1 {
		t.Fatalf("entries = %d, want expired entry swept", len(limiter.entries))
	}
	for i := 0; i < maxRateLimiterEntries; i++ {
		limiter.entries[fmt.Sprintf("k%d", i)] = rateWindow{started: now, count: 1}
	}
	if limiter.Allow("brand-new-key") {
		t.Fatal("table at capacity should reject unseen keys")
	}
}

func workflowRunBody(action, conclusion, event string, headRepoID int64, prs string) []byte {
	return []byte(`{"action":"` + action + `","installation":{"id":42},"repository":{"id":7,"full_name":"acme/app"},` +
		`"workflow_run":{"event":"` + event + `","conclusion":"` + conclusion + `","head_sha":"abc123","head_repository":{"id":` + fmt.Sprint(headRepoID) + `},"pull_requests":` + prs + `}}`)
}

func serveWorkflowRun(t *testing.T, body []byte) (*httptest.ResponseRecorder, *recordingProcessor) {
	t.Helper()
	processor := &recordingProcessor{}
	handler, err := NewWebhookHandler(WebhookConfig{WebhookSecret: []byte("secret"), Verifier: &recordingVerifier{}, Processor: processor, Limiter: allowAllLimiter{}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(body))
	request.Header.Set("X-GitHub-Event", "workflow_run")
	request.Header.Set("X-Hub-Signature-256", signature("secret", body))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder, processor
}

func TestWebhookWorkflowRunTriggersAnalysisForItsPullRequest(t *testing.T) {
	recorder, processor := serveWorkflowRun(t, workflowRunBody("completed", "success", "pull_request", 7, `[{"number":12}]`))
	if recorder.Code != http.StatusAccepted || processor.event.PullRequestNumber != 12 || processor.event.HeadSHA != "abc123" || processor.event.Source != "workflow_run" {
		t.Fatalf("status %d, event %#v", recorder.Code, processor.event)
	}
}

func TestWebhookWorkflowRunIgnoresIrrelevantRuns(t *testing.T) {
	for name, body := range map[string][]byte{
		"failed run":      workflowRunBody("completed", "failure", "pull_request", 7, `[{"number":12}]`),
		"push run":        workflowRunBody("completed", "success", "push", 7, `[{"number":12}]`),
		"requested":       workflowRunBody("requested", "", "pull_request", 7, `[{"number":12}]`),
		"fork run":        workflowRunBody("completed", "success", "pull_request", 8, `[{"number":12}]`),
		"no pull request": workflowRunBody("completed", "success", "pull_request", 7, `[]`),
	} {
		recorder, processor := serveWorkflowRun(t, body)
		if recorder.Code != http.StatusAccepted || processor.called {
			t.Errorf("%s: status %d, processed %v; want ignored with 202", name, recorder.Code, processor.called)
		}
	}
}

func TestWebhookWorkflowRunRequiresSignatureAndInstallation(t *testing.T) {
	processor := &recordingProcessor{}
	handler, _ := NewWebhookHandler(WebhookConfig{WebhookSecret: []byte("secret"), Verifier: &recordingVerifier{}, Processor: processor, Limiter: allowAllLimiter{}})
	body := workflowRunBody("completed", "success", "pull_request", 7, `[{"number":12}]`)
	request := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	request.Header.Set("X-GitHub-Event", "workflow_run")
	request.Header.Set("X-Hub-Signature-256", "sha256=00")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized || processor.called {
		t.Fatalf("unsigned workflow_run: status %d processed %v", recorder.Code, processor.called)
	}
	recorder, processor = serveWorkflowRun(t, []byte(`{"action":"completed","workflow_run":{"event":"pull_request","conclusion":"success","head_sha":"abc"}}`))
	if recorder.Code != http.StatusBadRequest || processor.called {
		t.Fatalf("missing installation: status %d processed %v", recorder.Code, processor.called)
	}
}

// --- intake behavior for events DeployGuard does not act on ---

type hookFixture struct {
	handler   *WebhookHandler
	processor *recordingProcessor
	auditor   *recordingAuditor
}

func newHook(t *testing.T) hookFixture {
	t.Helper()
	f := hookFixture{processor: &recordingProcessor{}, auditor: &recordingAuditor{}}
	var err error
	f.handler, err = NewWebhookHandler(WebhookConfig{WebhookSecret: []byte("secret"), Verifier: &recordingVerifier{}, Processor: f.processor, Auditor: f.auditor, Limiter: allowAllLimiter{}})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f hookFixture) send(event string, body []byte, signed bool, delivery string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(body))
	if event != "" {
		request.Header.Set("X-GitHub-Event", event)
	}
	if signed {
		request.Header.Set("X-Hub-Signature-256", signature("secret", body))
	}
	if delivery != "" {
		request.Header.Set("X-GitHub-Delivery", delivery)
	}
	recorder := httptest.NewRecorder()
	f.handler.ServeHTTP(recorder, request)
	return recorder
}

func prBody(action string) []byte {
	return []byte(`{"action":"` + action + `","installation":{"id":42},"repository":{"id":7,"full_name":"acme/app"},"pull_request":{"number":12,"head":{"sha":"abc123","repo":{"id":7}}}}`)
}

func TestPingIsAnsweredOnlyWhenSigned(t *testing.T) {
	f := newHook(t)
	if r := f.send("ping", []byte(`{"zen":"Keep it logically awesome."}`), true, ""); r.Code != http.StatusOK || f.processor.called {
		t.Fatalf("signed ping: status %d processed %v; GitHub's first delivery must succeed", r.Code, f.processor.called)
	}
	if r := f.send("ping", []byte(`{}`), false, ""); r.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned ping: status %d, want 401", r.Code)
	}
}

func TestOtherSignedEventsAreAcknowledgedAndIgnoredButUnsignedOnesAreRejected(t *testing.T) {
	f := newHook(t)
	body := []byte(`{"action":"created","comment":{"body":"/deployguard rerun"}}`)
	r := f.send("issue_comment", body, true, "")
	if r.Code != http.StatusAccepted || f.processor.called || f.auditor.last.Outcome != AuditIgnored || f.auditor.last.EventType != "issue_comment" {
		t.Fatalf("signed issue_comment: status %d processed %v audit %+v", r.Code, f.processor.called, f.auditor.last)
	}
	if r := f.send("issue_comment", body, false, ""); r.Code != http.StatusUnauthorized || f.processor.called {
		t.Fatalf("unsigned issue_comment: status %d, want 401", r.Code)
	}
	if r := f.send("", body, true, ""); r.Code != http.StatusBadRequest {
		t.Fatalf("missing event header: status %d, want 400", r.Code)
	}
}

func TestIrrelevantPullRequestActionsAreIgnoredNotRejected(t *testing.T) {
	for _, action := range []string{"closed", "labeled", "edited", "assigned", "ready_for_review", "converted_to_draft"} {
		f := newHook(t)
		if r := f.send("pull_request", prBody(action), true, ""); r.Code != http.StatusAccepted || f.processor.called || f.auditor.last.Outcome != AuditIgnored {
			t.Errorf("%s: status %d processed %v audit %v; want 202 ignored (400 shows as a failed delivery on GitHub)", action, r.Code, f.processor.called, f.auditor.last.Outcome)
		}
	}
	f := newHook(t)
	if r := f.send("pull_request", []byte(`{"action":"opened","installation":{"id":42}}`), true, ""); r.Code != http.StatusBadRequest || f.processor.called {
		t.Fatalf("a relevant action with missing fields is still a bad payload: %d", r.Code)
	}
	if r := f.send("pull_request", []byte(`not json`), true, ""); r.Code != http.StatusBadRequest {
		t.Fatalf("garbage: %d", r.Code)
	}
}

type countingProcessor struct {
	calls int
	fail  bool
}

func (p *countingProcessor) ProcessPullRequest(context.Context, PullRequestEvent) error {
	p.calls++
	if p.fail {
		return errors.New("busy")
	}
	return nil
}

func TestRedeliveredWebhookIsProcessedOnce(t *testing.T) {
	processor, auditor := &countingProcessor{}, &recordingAuditor{}
	handler, _ := NewWebhookHandler(WebhookConfig{WebhookSecret: []byte("secret"), Verifier: &recordingVerifier{}, Processor: processor, Auditor: auditor, Limiter: allowAllLimiter{}})
	send := func(delivery string) int {
		request := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(prBody("synchronize")))
		request.Header.Set("X-GitHub-Event", "pull_request")
		request.Header.Set("X-Hub-Signature-256", signature("secret", prBody("synchronize")))
		if delivery != "" {
			request.Header.Set("X-GitHub-Delivery", delivery)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder.Code
	}
	id := "72d3162e-cc78-11e3-81ab-4c9367dc0958"
	if send(id) != http.StatusAccepted || send(id) != http.StatusAccepted {
		t.Fatal("both deliveries are acknowledged")
	}
	if processor.calls != 1 || auditor.last.Outcome != AuditDuplicate {
		t.Fatalf("processed %d times, last audit %v; the redelivery must be recognized", processor.calls, auditor.last.Outcome)
	}
	if send("11111111-2222-3333-4444-555555555555"); processor.calls != 2 {
		t.Errorf("a different delivery is processed: %d", processor.calls)
	}
	// No usable delivery ID, so nothing can be deduplicated.
	send("")
	send("")
	send("not a guid!")
	send("not a guid!")
	if processor.calls != 6 {
		t.Errorf("without a valid delivery ID every request is processed: %d", processor.calls)
	}
}

func TestFailedDeliveryCanBeRetriedWithTheSameID(t *testing.T) {
	processor := &countingProcessor{fail: true}
	handler, _ := NewWebhookHandler(WebhookConfig{WebhookSecret: []byte("secret"), Verifier: &recordingVerifier{}, Processor: processor, Limiter: allowAllLimiter{}})
	send := func() int {
		request := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(prBody("opened")))
		request.Header.Set("X-GitHub-Event", "pull_request")
		request.Header.Set("X-Hub-Signature-256", signature("secret", prBody("opened")))
		request.Header.Set("X-GitHub-Delivery", "72d3162e-cc78-11e3-81ab-4c9367dc0958")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder.Code
	}
	if send() != http.StatusInternalServerError {
		t.Fatal("a failing processor returns 500")
	}
	processor.fail = false
	if send() != http.StatusAccepted || processor.calls != 2 {
		t.Fatalf("the retry must be processed, not skipped as a duplicate (calls %d)", processor.calls)
	}
}

func TestMemoryDeliveryTrackerExpiresAndStaysBounded(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tracker := NewMemoryDeliveryTracker(time.Hour, 3)
	tracker.now = func() time.Time { return now }
	tracker.Remember("aaaaaaaa")
	if !tracker.Seen("aaaaaaaa") || tracker.Seen("bbbbbbbb") {
		t.Fatal("seen/unseen wrong")
	}
	now = now.Add(2 * time.Hour)
	if tracker.Seen("aaaaaaaa") {
		t.Error("an entry past its TTL must be forgotten")
	}
	for _, id := range []string{"11111111", "22222222", "33333333", "44444444", "55555555"} {
		tracker.Remember(id)
	}
	if len(tracker.entries) > 3 {
		t.Errorf("tracker holds %d entries, cap is 3", len(tracker.entries))
	}
}
