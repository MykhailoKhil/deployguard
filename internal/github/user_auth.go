package github

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	defaultGitHubWebBaseURL = "https://github.com"
	defaultOAuthStateTTL    = 10 * time.Minute
	defaultSessionTTL       = 30 * time.Minute
	maxGitHubAuthBodyBytes  = 1 << 20
	maxPendingOAuthStates   = 10000
	stateSweepInterval      = time.Minute
	defaultHTTPTimeout      = 20 * time.Second
)

// ErrInvalidOAuthState is returned for an unknown, expired, or reused OAuth state, or a missing code.
var ErrInvalidOAuthState = errors.New("invalid or expired GitHub OAuth state")

// ErrTooManyPendingAuthorizations is returned when sign-in attempts are being
// started faster than they are completed or expire.
var ErrTooManyPendingAuthorizations = errors.New("too many pending GitHub authorizations")

// GitHubUser is the signed-in GitHub account.
type GitHubUser struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
}

// UserAuthenticatorConfig holds the GitHub App's OAuth credentials and the registered callback URL.
type UserAuthenticatorConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	WebBaseURL   string
	APIBaseURL   string
	HTTPClient   *http.Client
}

// UserAuthenticator runs the GitHub OAuth web flow used for sign-in.
type UserAuthenticator struct {
	clientID     string
	clientSecret string
	redirectURL  string
	webBaseURL   *url.URL
	apiBaseURL   *url.URL
	httpClient   *http.Client
	now          func() time.Time

	mu        sync.Mutex
	states    map[string]time.Time
	lastSweep time.Time
}

// UserSession is one signed-in browser session. The access token stays on the server.
type UserSession struct {
	User        GitHubUser
	AccessToken string
	CSRFToken   string
	ExpiresAt   time.Time
}

// SessionStore keeps sessions in memory until they expire or are revoked. A restart signs everyone out.
type SessionStore struct {
	ttl       time.Duration
	now       func() time.Time
	mu        sync.Mutex
	mapByID   map[string]UserSession
	lastSweep time.Time
}

// NewUserAuthenticator validates the configuration and returns a UserAuthenticator.
func NewUserAuthenticator(config UserAuthenticatorConfig) (*UserAuthenticator, error) {
	if strings.TrimSpace(config.ClientID) == "" || strings.TrimSpace(config.ClientSecret) == "" {
		return nil, errors.New("GitHub OAuth client credentials are required")
	}
	redirectURL, err := url.Parse(config.RedirectURL)
	if err != nil || redirectURL.Scheme != "https" || redirectURL.Host == "" || redirectURL.User != nil || redirectURL.Fragment != "" {
		return nil, errors.New("GitHub OAuth redirect URL must use HTTPS")
	}
	webBaseURL := config.WebBaseURL
	if webBaseURL == "" {
		webBaseURL = defaultGitHubWebBaseURL
	}
	parsedWebURL, err := parseBaseURL(webBaseURL)
	if err != nil || parsedWebURL.Scheme != "https" || parsedWebURL.User != nil || parsedWebURL.RawQuery != "" || parsedWebURL.Fragment != "" {
		return nil, errors.New("GitHub web base URL must use HTTPS")
	}
	apiBaseURL := config.APIBaseURL
	if apiBaseURL == "" {
		apiBaseURL = defaultGitHubAPIBaseURL
	}
	parsedAPIURL, err := parseBaseURL(apiBaseURL)
	if err != nil || parsedAPIURL.Scheme != "https" || parsedAPIURL.User != nil || parsedAPIURL.RawQuery != "" || parsedAPIURL.Fragment != "" {
		return nil, errors.New("GitHub API base URL must use HTTPS")
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultHTTPTimeout}
	}
	return &UserAuthenticator{
		clientID: config.ClientID, clientSecret: config.ClientSecret,
		redirectURL: redirectURL.String(), webBaseURL: parsedWebURL,
		apiBaseURL: parsedAPIURL, httpClient: client, now: time.Now,
		states: make(map[string]time.Time),
	}, nil
}

// BeginAuthorization returns the GitHub authorization URL and the state value to bind to the
// browser. Pending states are capped and expire, so anonymous callers cannot grow memory.
func (a *UserAuthenticator) BeginAuthorization() (string, string, error) {
	state, err := randomHex(32)
	if err != nil {
		return "", "", fmt.Errorf("create OAuth state: %w", err)
	}
	now := a.now()
	a.mu.Lock()
	// Sweep lazily: a full scan on every request would let anonymous callers
	// turn a large pending-state map into a CPU cost.
	if len(a.states) >= maxPendingOAuthStates || now.Sub(a.lastSweep) >= stateSweepInterval {
		for existing, expiry := range a.states {
			if !expiry.After(now) {
				delete(a.states, existing)
			}
		}
		a.lastSweep = now
	}
	if len(a.states) >= maxPendingOAuthStates {
		a.mu.Unlock()
		return "", "", ErrTooManyPendingAuthorizations
	}
	a.states[state] = now.Add(defaultOAuthStateTTL)
	a.mu.Unlock()

	endpoint := *a.webBaseURL
	endpoint.Path = strings.TrimSuffix(endpoint.Path, "/") + "/login/oauth/authorize"
	query := endpoint.Query()
	query.Set("client_id", a.clientID)
	query.Set("redirect_uri", a.redirectURL)
	query.Set("state", state)
	endpoint.RawQuery = query.Encode()
	return endpoint.String(), state, nil
}

// ConsumeState reports whether state was issued and has not expired, and forgets it, so each
// state works only once.
func (a *UserAuthenticator) ConsumeState(state string) bool {
	if state == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	expiresAt, exists := a.states[state]
	delete(a.states, state)
	return exists && expiresAt.After(a.now())
}

// CompleteAuthorization checks the state, exchanges the code for an access token, and returns
// the GitHub user with that token.
func (a *UserAuthenticator) CompleteAuthorization(ctx context.Context, code, state string) (GitHubUser, string, error) {
	if strings.TrimSpace(code) == "" || !a.ConsumeState(state) {
		return GitHubUser{}, "", ErrInvalidOAuthState
	}
	token, err := a.exchangeCode(ctx, code)
	if err != nil {
		return GitHubUser{}, "", err
	}
	user, err := a.getUser(ctx, token)
	if err != nil {
		return GitHubUser{}, "", err
	}
	return user, token, nil
}

func (a *UserAuthenticator) exchangeCode(ctx context.Context, code string) (string, error) {
	endpoint := *a.webBaseURL
	endpoint.Path = strings.TrimSuffix(endpoint.Path, "/") + "/login/oauth/access_token"
	form := url.Values{}
	form.Set("client_id", a.clientID)
	form.Set("client_secret", a.clientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", a.redirectURL)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", errors.New("create GitHub OAuth token request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := a.httpClient.Do(request)
	if err != nil {
		return "", errors.New("exchange GitHub OAuth code")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", errors.New("exchange GitHub OAuth code: unexpected response")
	}
	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxGitHubAuthBodyBytes)).Decode(&result); err != nil || result.AccessToken == "" {
		return "", errors.New("decode GitHub OAuth token response")
	}
	return result.AccessToken, nil
}

func (a *UserAuthenticator) getUser(ctx context.Context, token string) (GitHubUser, error) {
	endpoint := *a.apiBaseURL
	endpoint.Path = strings.TrimSuffix(endpoint.Path, "/") + "/user"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return GitHubUser{}, errors.New("create GitHub user request")
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := a.httpClient.Do(request)
	if err != nil {
		return GitHubUser{}, errors.New("load GitHub user identity")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return GitHubUser{}, errors.New("load GitHub user identity: unexpected response")
	}
	var user GitHubUser
	if err := json.NewDecoder(io.LimitReader(response.Body, maxGitHubAuthBodyBytes)).Decode(&user); err != nil || user.ID <= 0 || user.Login == "" {
		return GitHubUser{}, errors.New("decode GitHub user identity")
	}
	return user, nil
}

// NewSessionStore returns a store whose sessions last ttl (a default when ttl is not positive).
func NewSessionStore(ttl time.Duration) *SessionStore {
	if ttl <= 0 {
		ttl = defaultSessionTTL
	}
	return &SessionStore{ttl: ttl, now: time.Now, mapByID: make(map[string]UserSession)}
}

// Create stores a new session for the user and returns its random session ID.
func (s *SessionStore) Create(user GitHubUser, accessToken string) (string, error) {
	if user.ID <= 0 || user.Login == "" || accessToken == "" {
		return "", errors.New("valid GitHub user and access token are required")
	}
	sessionID, err := randomHex(32)
	if err != nil {
		return "", fmt.Errorf("create session ID: %w", err)
	}
	csrfToken, err := randomHex(32)
	if err != nil {
		return "", fmt.Errorf("create CSRF token: %w", err)
	}
	now := s.now()
	s.mu.Lock()
	if now.Sub(s.lastSweep) >= stateSweepInterval {
		for existing, session := range s.mapByID {
			if !session.ExpiresAt.After(now) {
				delete(s.mapByID, existing)
			}
		}
		s.lastSweep = now
	}
	s.mapByID[sessionID] = UserSession{User: user, AccessToken: accessToken, CSRFToken: csrfToken, ExpiresAt: now.Add(s.ttl)}
	s.mu.Unlock()
	return sessionID, nil
}

// Get returns the session if it exists and has not expired.
func (s *SessionStore) Get(sessionID string) (UserSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, exists := s.mapByID[sessionID]
	if !exists {
		return UserSession{}, false
	}
	if !session.ExpiresAt.After(s.now()) {
		delete(s.mapByID, sessionID)
		return UserSession{}, false
	}
	return session, true
}

// Revoke deletes a session (sign-out).
func (s *SessionStore) Revoke(sessionID string) {
	s.mu.Lock()
	delete(s.mapByID, sessionID)
	s.mu.Unlock()
}

func parseBaseURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("invalid base URL")
	}
	return parsed, nil
}

func randomHex(bytesLength int) (string, error) {
	randomBytes := make([]byte, bytesLength)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(randomBytes), nil
}
