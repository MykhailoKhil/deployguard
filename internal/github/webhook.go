// Package github contains GitHub App boundary adapters.
package github

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

const defaultWebhookBodyLimit = 1 << 20

// ErrRepositoryNotInstalled is returned when the App is not installed on the repository named by an event.
var ErrRepositoryNotInstalled = errors.New("repository is not available to this GitHub App installation")

// PullRequestEvent is the verified subset of a GitHub pull_request webhook.
type PullRequestEvent struct {
	Action             string
	InstallationID     int64
	RepositoryID       int64
	RepositoryFullName string
	PullRequestNumber  int
	HeadSHA            string
	// Source is the GitHub event that triggered this analysis: "pull_request"
	// or "workflow_run" (the plan workflow finished).
	Source string
	// Fork is true when the head branch lives in a different repository.
	Fork bool
}

// PullRequestProcessor begins the internal analysis workflow after webhook
// authentication and repository verification have succeeded.
type PullRequestProcessor interface {
	ProcessPullRequest(context.Context, PullRequestEvent) error
}

// RepositoryVerifier confirms that the signed event's repository belongs to
// the declared GitHub App installation before any analysis is performed.
type RepositoryVerifier interface {
	VerifyRepository(ctx context.Context, installationID, repositoryID int64, fullName string) error
}

// RateLimiter protects the webhook endpoint against request floods.
type RateLimiter interface {
	Allow(key string) bool
}

// AuditOutcome is a secret-safe webhook processing outcome.
type AuditOutcome string

const (
	AuditAccepted            AuditOutcome = "accepted"
	AuditRejectedRateLimited AuditOutcome = "rejected_rate_limited"
	AuditRejectedSignature   AuditOutcome = "rejected_signature"
	AuditRejectedPayload     AuditOutcome = "rejected_payload"
	AuditRejectedRepository  AuditOutcome = "rejected_repository"
	AuditProcessorFailed     AuditOutcome = "processor_failed"
	AuditIgnored             AuditOutcome = "ignored"
	AuditDuplicate           AuditOutcome = "duplicate"
)

// AuditEvent deliberately excludes raw webhook bodies and plan values.
type AuditEvent struct {
	Outcome        AuditOutcome
	EventType      string
	InstallationID int64
	RepositoryID   int64
	OccurredAt     time.Time
}

// Auditor records security-relevant events without exposing request content.
type Auditor interface {
	Record(context.Context, AuditEvent)
}

// WebhookConfig supplies the dependencies for a GitHub webhook endpoint.
type WebhookConfig struct {
	WebhookSecret []byte
	Verifier      RepositoryVerifier
	Processor     PullRequestProcessor
	Auditor       Auditor
	Limiter       RateLimiter
	MaxBodyBytes  int64
	// Deliveries remembers delivery IDs so a redelivered webhook is not processed twice. Optional:
	// a bounded in-memory tracker is used when nil.
	Deliveries DeliveryTracker
}

// WebhookHandler validates GitHub webhook requests before dispatching work.
type WebhookHandler struct {
	secret       []byte
	verifier     RepositoryVerifier
	processor    PullRequestProcessor
	auditor      Auditor
	limiter      RateLimiter
	maxBodyBytes int64
	deliveries   DeliveryTracker
}

// NewWebhookHandler creates a fail-closed webhook handler.
func NewWebhookHandler(config WebhookConfig) (*WebhookHandler, error) {
	if len(config.WebhookSecret) == 0 {
		return nil, errors.New("GitHub webhook secret is required")
	}
	if config.Verifier == nil {
		return nil, errors.New("repository verifier is required")
	}
	if config.Processor == nil {
		return nil, errors.New("pull request processor is required")
	}
	if config.Limiter == nil {
		config.Limiter = NewMemoryRateLimiter(60, time.Minute)
	}
	if config.MaxBodyBytes <= 0 {
		config.MaxBodyBytes = defaultWebhookBodyLimit
	}
	if config.Deliveries == nil {
		config.Deliveries = NewMemoryDeliveryTracker(24*time.Hour, 10000)
	}
	return &WebhookHandler{
		deliveries:   config.Deliveries,
		secret:       append([]byte(nil), config.WebhookSecret...),
		verifier:     config.Verifier,
		processor:    config.Processor,
		auditor:      config.Auditor,
		limiter:      config.Limiter,
		maxBodyBytes: config.MaxBodyBytes,
	}, nil
}

// ServeHTTP handles a webhook delivery. The signature is checked first for every event type, then:
//   - "ping" (GitHub sends it when a webhook is created) is answered 200;
//   - "pull_request" and "workflow_run" are analyzed when relevant (see the decoders);
//   - every other signed event, and irrelevant pull request actions such as "closed" or "labeled",
//     is acknowledged with 202 and ignored, so GitHub does not show them as failed deliveries;
//   - a delivery ID seen before is acknowledged and not processed again.
func (h *WebhookHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !h.limiter.Allow(clientKey(request.RemoteAddr)) {
		h.audit(request.Context(), AuditEvent{Outcome: AuditRejectedRateLimited, EventType: request.Header.Get("X-GitHub-Event"), OccurredAt: time.Now().UTC()})
		http.Error(writer, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	eventType := request.Header.Get("X-GitHub-Event")
	if eventType == "" {
		h.audit(request.Context(), AuditEvent{Outcome: AuditRejectedPayload, OccurredAt: time.Now().UTC()})
		http.Error(writer, "missing GitHub event type", http.StatusBadRequest)
		return
	}

	request.Body = http.MaxBytesReader(writer, request.Body, h.maxBodyBytes)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		h.audit(request.Context(), AuditEvent{Outcome: AuditRejectedPayload, EventType: eventType, OccurredAt: time.Now().UTC()})
		http.Error(writer, "invalid webhook payload", http.StatusRequestEntityTooLarge)
		return
	}
	if !verifySignature(h.secret, request.Header.Get("X-Hub-Signature-256"), body) {
		h.audit(request.Context(), AuditEvent{Outcome: AuditRejectedSignature, EventType: eventType, OccurredAt: time.Now().UTC()})
		http.Error(writer, "invalid webhook signature", http.StatusUnauthorized)
		return
	}

	var events []PullRequestEvent
	switch eventType {
	case "ping":
		h.audit(request.Context(), AuditEvent{Outcome: AuditIgnored, EventType: eventType, OccurredAt: time.Now().UTC()})
		writer.WriteHeader(http.StatusOK)
		return
	case "workflow_run":
		events, err = decodeWorkflowRunEvents(body)
	case "pull_request":
		var event PullRequestEvent
		var relevant bool
		if event, relevant, err = decodePullRequestEvent(body); err == nil && relevant {
			events = []PullRequestEvent{event}
		}
	default: // a signed event DeployGuard does not use, for example issue_comment
		h.audit(request.Context(), AuditEvent{Outcome: AuditIgnored, EventType: eventType, OccurredAt: time.Now().UTC()})
		writer.WriteHeader(http.StatusAccepted)
		return
	}
	if err != nil {
		h.audit(request.Context(), AuditEvent{Outcome: AuditRejectedPayload, EventType: eventType, OccurredAt: time.Now().UTC()})
		http.Error(writer, "invalid webhook payload", http.StatusBadRequest)
		return
	}
	if len(events) == 0 {
		h.audit(request.Context(), AuditEvent{Outcome: AuditIgnored, EventType: eventType, OccurredAt: time.Now().UTC()})
		writer.WriteHeader(http.StatusAccepted)
		return
	}
	for _, event := range events {
		if err := h.verifier.VerifyRepository(request.Context(), event.InstallationID, event.RepositoryID, event.RepositoryFullName); err != nil {
			h.auditEvent(request.Context(), AuditRejectedRepository, event)
			http.Error(writer, "repository is not authorized", http.StatusForbidden)
			return
		}
	}
	delivery := request.Header.Get("X-GitHub-Delivery")
	if validDeliveryID(delivery) && h.deliveries.Seen(delivery) {
		h.auditEvent(request.Context(), AuditDuplicate, events[0])
		writer.WriteHeader(http.StatusAccepted)
		return
	}
	for _, event := range events {
		if err := h.processor.ProcessPullRequest(request.Context(), event); err != nil {
			h.auditEvent(request.Context(), AuditProcessorFailed, event)
			http.Error(writer, "could not start analysis", http.StatusInternalServerError)
			return
		}
		h.auditEvent(request.Context(), AuditAccepted, event)
	}
	// Remembered only after success, so a delivery that failed can be redelivered and retried.
	if validDeliveryID(delivery) {
		h.deliveries.Remember(delivery)
	}
	writer.WriteHeader(http.StatusAccepted)
}

var deliveryIDPattern = regexp.MustCompile(`^[0-9A-Fa-f-]{8,64}$`)

func validDeliveryID(id string) bool { return deliveryIDPattern.MatchString(id) }

// DeliveryTracker remembers webhook delivery IDs (the X-GitHub-Delivery header, a GUID that stays
// the same when GitHub redelivers) so a redelivery is acknowledged without being processed again.
type DeliveryTracker interface {
	Seen(id string) bool
	Remember(id string)
}

// MemoryDeliveryTracker is a bounded in-memory DeliveryTracker. It forgets everything on restart,
// and each instance has its own memory; the stored verdict is also idempotent per commit, so a
// repeat that slips through is harmless.
type MemoryDeliveryTracker struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	entries map[string]time.Time
	now     func() time.Time
}

// NewMemoryDeliveryTracker remembers up to max delivery IDs for ttl each.
func NewMemoryDeliveryTracker(ttl time.Duration, max int) *MemoryDeliveryTracker {
	return &MemoryDeliveryTracker{ttl: ttl, max: max, entries: make(map[string]time.Time), now: time.Now}
}

func (t *MemoryDeliveryTracker) Seen(id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	at, ok := t.entries[id]
	if !ok {
		return false
	}
	if t.now().Sub(at) >= t.ttl {
		delete(t.entries, id)
		return false
	}
	return true
}

func (t *MemoryDeliveryTracker) Remember(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	if len(t.entries) >= t.max {
		for existing, at := range t.entries {
			if now.Sub(at) >= t.ttl {
				delete(t.entries, existing)
			}
		}
		if len(t.entries) >= t.max {
			// Still full of unexpired IDs: start over rather than grow without bound.
			t.entries = make(map[string]time.Time)
		}
	}
	t.entries[id] = now
}

func verifySignature(secret []byte, header string, body []byte) bool {
	const prefix = "sha256="
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	received, err := hex.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil || len(received) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(body)
	expected := mac.Sum(nil)
	return subtle.ConstantTimeCompare(expected, received) == 1
}

// decodePullRequestEvent returns the event and whether DeployGuard should act on it. A well-formed
// payload for an action it does not use (closed, labeled, edited, ...) is not an error: relevant is
// false and the caller acknowledges and ignores it. A relevant action with missing fields is an error.
func decodePullRequestEvent(body []byte) (event PullRequestEvent, relevant bool, err error) {
	var payload struct {
		Action       string `json:"action"`
		Installation struct {
			ID int64 `json:"id"`
		} `json:"installation"`
		Repository struct {
			ID       int64  `json:"id"`
			FullName string `json:"full_name"`
		} `json:"repository"`
		PullRequest struct {
			Number int `json:"number"`
			Head   struct {
				SHA  string `json:"sha"`
				Repo struct {
					ID int64 `json:"id"`
				} `json:"repo"`
			} `json:"head"`
		} `json:"pull_request"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return PullRequestEvent{}, false, err
	}
	if !isRelevantAction(payload.Action) {
		return PullRequestEvent{}, false, nil
	}
	event = PullRequestEvent{
		Action:             payload.Action,
		InstallationID:     payload.Installation.ID,
		RepositoryID:       payload.Repository.ID,
		RepositoryFullName: payload.Repository.FullName,
		PullRequestNumber:  payload.PullRequest.Number,
		HeadSHA:            payload.PullRequest.Head.SHA,
		Source:             "pull_request",
		// A deleted head repository reports ID 0, which is also treated as a fork.
		Fork: payload.PullRequest.Head.Repo.ID != payload.Repository.ID,
	}
	if event.InstallationID <= 0 || event.RepositoryID <= 0 || event.RepositoryFullName == "" || event.PullRequestNumber <= 0 || event.HeadSHA == "" {
		return PullRequestEvent{}, false, errors.New("required pull request event field is missing or invalid")
	}
	return event, true, nil
}

// maxWorkflowRunPullRequests bounds the work one signed event can trigger.
const maxWorkflowRunPullRequests = 5

// decodeWorkflowRunEvents turns a finished, successful pull-request workflow
// run into one event per associated pull request. Anything else (other
// actions, failed runs, fork runs, runs with no pull request) yields no
// events and is ignored rather than rejected.
func decodeWorkflowRunEvents(body []byte) ([]PullRequestEvent, error) {
	var payload struct {
		Action       string `json:"action"`
		Installation struct {
			ID int64 `json:"id"`
		} `json:"installation"`
		Repository struct {
			ID       int64  `json:"id"`
			FullName string `json:"full_name"`
		} `json:"repository"`
		WorkflowRun struct {
			Event          string `json:"event"`
			Conclusion     string `json:"conclusion"`
			HeadSHA        string `json:"head_sha"`
			HeadRepository struct {
				ID int64 `json:"id"`
			} `json:"head_repository"`
			PullRequests []struct {
				Number int `json:"number"`
			} `json:"pull_requests"`
		} `json:"workflow_run"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	run := payload.WorkflowRun
	if payload.Action != "completed" || run.Conclusion != "success" || run.Event != "pull_request" {
		return nil, nil
	}
	if payload.Installation.ID <= 0 || payload.Repository.ID <= 0 || payload.Repository.FullName == "" || run.HeadSHA == "" {
		return nil, errors.New("required workflow run event field is missing or invalid")
	}
	if run.HeadRepository.ID != payload.Repository.ID {
		return nil, nil
	}
	var events []PullRequestEvent
	for _, pullRequest := range run.PullRequests {
		if pullRequest.Number <= 0 {
			return nil, errors.New("invalid pull request number")
		}
		if len(events) == maxWorkflowRunPullRequests {
			break
		}
		events = append(events, PullRequestEvent{
			Action: payload.Action, InstallationID: payload.Installation.ID, RepositoryID: payload.Repository.ID,
			RepositoryFullName: payload.Repository.FullName, PullRequestNumber: pullRequest.Number,
			HeadSHA: run.HeadSHA, Source: "workflow_run",
		})
	}
	return events, nil
}

func isRelevantAction(action string) bool {
	switch action {
	case "opened", "reopened", "synchronize":
		return true
	default:
		return false
	}
}

func (h *WebhookHandler) auditEvent(ctx context.Context, outcome AuditOutcome, event PullRequestEvent) {
	h.audit(ctx, AuditEvent{Outcome: outcome, EventType: event.Source, InstallationID: event.InstallationID, RepositoryID: event.RepositoryID, OccurredAt: time.Now().UTC()})
}

func (h *WebhookHandler) audit(ctx context.Context, event AuditEvent) {
	if h.auditor != nil {
		h.auditor.Record(ctx, event)
	}
}

func clientKey(remoteAddress string) string {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err == nil {
		return host
	}
	return remoteAddress
}

type rateWindow struct {
	started time.Time
	count   int
}

const maxRateLimiterEntries = 100000

// MemoryRateLimiter is a bounded fixed-window limiter for stateless MVP use.
// Expired windows are swept at most once per window and the table is capped, so
// a flood of distinct keys cannot grow memory without bound. Production
// deployments should use a shared limiter before running multiple instances.
type MemoryRateLimiter struct {
	mu        sync.Mutex
	limit     int
	window    time.Duration
	entries   map[string]rateWindow
	lastSweep time.Time
	now       func() time.Time
}

// NewMemoryRateLimiter returns a limiter that allows limit calls per key in each window.
func NewMemoryRateLimiter(limit int, window time.Duration) *MemoryRateLimiter {
	return &MemoryRateLimiter{limit: limit, window: window, entries: make(map[string]rateWindow), now: time.Now}
}

// Allow reports whether key may proceed, counting the call when it does.
func (l *MemoryRateLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Sub(l.lastSweep) >= l.window || len(l.entries) >= maxRateLimiterEntries {
		for existing, entry := range l.entries {
			if now.Sub(entry.started) >= l.window {
				delete(l.entries, existing)
			}
		}
		l.lastSweep = now
	}
	entry, exists := l.entries[key]
	if !exists || now.Sub(entry.started) >= l.window {
		if !exists && len(l.entries) >= maxRateLimiterEntries {
			return false
		}
		l.entries[key] = rateWindow{started: now, count: 1}
		return true
	}
	if entry.count >= l.limit {
		return false
	}
	entry.count++
	l.entries[key] = entry
	return true
}

var _ http.Handler = (*WebhookHandler)(nil)
