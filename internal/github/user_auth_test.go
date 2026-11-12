package github

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestUserAuthenticatorConsumesOAuthStateExactlyOnce(t *testing.T) {
	authenticator, err := NewUserAuthenticator(UserAuthenticatorConfig{
		ClientID: "client-id", ClientSecret: "client-secret",
		RedirectURL: "https://deployguard.example/auth/github/callback",
		HTTPClient:  &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return response(http.StatusInternalServerError, ""), nil })},
	})
	if err != nil {
		t.Fatalf("NewUserAuthenticator() error = %v", err)
	}

	authorizationURL, state, err := authenticator.BeginAuthorization()
	if err != nil {
		t.Fatalf("BeginAuthorization() error = %v", err)
	}
	parsedURL, err := url.Parse(authorizationURL)
	if err != nil || parsedURL.Query().Get("state") != state || parsedURL.Query().Get("client_id") != "client-id" {
		t.Fatalf("authorization URL = %q, state = %q", authorizationURL, state)
	}
	if !authenticator.ConsumeState(state) {
		t.Fatal("ConsumeState() rejected freshly issued state")
	}
	if authenticator.ConsumeState(state) {
		t.Fatal("ConsumeState() accepted a replayed state")
	}
}

func TestUserAuthenticatorRejectsExpiredOAuthState(t *testing.T) {
	authenticator, err := NewUserAuthenticator(UserAuthenticatorConfig{ClientID: "client-id", ClientSecret: "client-secret", RedirectURL: "https://deployguard.example/auth/github/callback"})
	if err != nil {
		t.Fatalf("NewUserAuthenticator() error = %v", err)
	}
	authenticator.now = func() time.Time { return time.Unix(100, 0) }
	_, state, err := authenticator.BeginAuthorization()
	if err != nil {
		t.Fatalf("BeginAuthorization() error = %v", err)
	}
	authenticator.now = func() time.Time { return time.Unix(100, 0).Add(11 * time.Minute) }
	if authenticator.ConsumeState(state) {
		t.Fatal("ConsumeState() accepted expired state")
	}
}

func TestSessionStoreExpiresAndRevokesSessions(t *testing.T) {
	store := NewSessionStore(30 * time.Minute)
	store.now = func() time.Time { return time.Unix(100, 0) }
	sessionID, err := store.Create(GitHubUser{ID: 7, Login: "acme-user"}, "private-access-token")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if len(sessionID) != 64 || strings.Contains(sessionID, " ") {
		t.Fatalf("session ID = %q, want opaque 32-byte hex token", sessionID)
	}
	session, ok := store.Get(sessionID)
	if !ok || session.User.ID != 7 || session.AccessToken != "private-access-token" || len(session.CSRFToken) != 64 {
		t.Fatalf("Get() = %#v, %v", session, ok)
	}
	store.Revoke(sessionID)
	if _, ok := store.Get(sessionID); ok {
		t.Fatal("Get() returned a revoked session")
	}

	expiringID, err := store.Create(GitHubUser{ID: 8, Login: "another-user"}, "another-token")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	store.now = func() time.Time { return time.Unix(100, 0).Add(31 * time.Minute) }
	if _, ok := store.Get(expiringID); ok {
		t.Fatal("Get() returned an expired session")
	}
}

func TestUserAuthenticatorExchangesCodeAndLoadsIdentity(t *testing.T) {
	var requests int
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		switch request.URL.Path {
		case "/login/oauth/access_token":
			if request.Method != http.MethodPost || request.Header.Get("Accept") != "application/json" {
				t.Fatalf("token request = %s %s headers=%v", request.Method, request.URL, request.Header)
			}
			return response(http.StatusOK, `{"access_token":"user-token","token_type":"bearer"}`), nil
		case "/user":
			if request.Header.Get("Authorization") != "Bearer user-token" {
				t.Fatalf("user authorization = %q", request.Header.Get("Authorization"))
			}
			return response(http.StatusOK, `{"id":7,"login":"acme-user"}`), nil
		default:
			return response(http.StatusNotFound, ""), nil
		}
	})}
	authenticator, err := NewUserAuthenticator(UserAuthenticatorConfig{
		ClientID: "client-id", ClientSecret: "client-secret",
		RedirectURL: "https://deployguard.example/auth/github/callback",
		APIBaseURL:  "https://api.github.test", HTTPClient: client,
	})
	if err != nil {
		t.Fatalf("NewUserAuthenticator() error = %v", err)
	}
	_, state, err := authenticator.BeginAuthorization()
	if err != nil {
		t.Fatalf("BeginAuthorization() error = %v", err)
	}
	user, token, err := authenticator.CompleteAuthorization(context.Background(), "oauth-code", state)
	if err != nil {
		t.Fatalf("CompleteAuthorization() error = %v", err)
	}
	if user.ID != 7 || user.Login != "acme-user" || token != "user-token" || requests != 2 {
		t.Fatalf("CompleteAuthorization() = %#v, %q, %d requests", user, token, requests)
	}
}

func TestUserAuthenticatorRejectsOAuthStateMismatchWithoutExchangingCode(t *testing.T) {
	requests := 0
	authenticator, err := NewUserAuthenticator(UserAuthenticatorConfig{
		ClientID: "client-id", ClientSecret: "client-secret", RedirectURL: "https://deployguard.example/auth/github/callback",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			requests++
			return response(http.StatusOK, `{"access_token":"user-token"}`), nil
		})},
	})
	if err != nil {
		t.Fatalf("NewUserAuthenticator() error = %v", err)
	}
	_, _, err = authenticator.BeginAuthorization()
	if err != nil {
		t.Fatalf("BeginAuthorization() error = %v", err)
	}
	if _, _, err := authenticator.CompleteAuthorization(context.Background(), "oauth-code", "incorrect-state"); err == nil {
		t.Fatal("CompleteAuthorization() accepted an invalid state")
	}
	if requests != 0 {
		t.Fatalf("OAuth code was exchanged %d times, want 0", requests)
	}
}

func TestBeginAuthorizationCapsPendingStatesAndRecoversAfterExpiry(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	authenticator, err := NewUserAuthenticator(UserAuthenticatorConfig{
		ClientID: "id", ClientSecret: "secret", RedirectURL: "https://app.example/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	authenticator.now = func() time.Time { return now }
	for i := 0; i < maxPendingOAuthStates; i++ {
		if _, _, err := authenticator.BeginAuthorization(); err != nil {
			t.Fatalf("BeginAuthorization() #%d error = %v", i, err)
		}
	}
	if _, _, err := authenticator.BeginAuthorization(); !errors.Is(err, ErrTooManyPendingAuthorizations) {
		t.Fatalf("error = %v, want ErrTooManyPendingAuthorizations", err)
	}
	now = now.Add(defaultOAuthStateTTL + time.Second)
	if _, _, err := authenticator.BeginAuthorization(); err != nil {
		t.Fatalf("BeginAuthorization() after expiry error = %v", err)
	}
}
