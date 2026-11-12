package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestAppAuthenticatorVerifiesMatchingRepositoryInstallation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/repos/acme/deployguard/installation" {
			return response(http.StatusNotFound, ""), nil
		}
		if request.Header.Get("Authorization") == "" {
			return response(http.StatusUnauthorized, ""), nil
		}
		return response(http.StatusOK, `{"id":42}`), nil
	})}

	authenticator, err := NewAppAuthenticator(AppAuthenticatorConfig{
		AppID:         101,
		PrivateKeyPEM: privateKeyPEM(key),
		APIBaseURL:    "https://api.github.test",
		HTTPClient:    client,
	})
	if err != nil {
		t.Fatalf("NewAppAuthenticator() error = %v", err)
	}

	if err := authenticator.VerifyRepository(context.Background(), 42, 7, "acme/deployguard"); err != nil {
		t.Fatalf("VerifyRepository() error = %v", err)
	}
}

func TestAppAuthenticatorRejectsMismatchedInstallation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, `{"id":99}`), nil
	})}

	authenticator, err := NewAppAuthenticator(AppAuthenticatorConfig{
		AppID:         101,
		PrivateKeyPEM: privateKeyPEM(key),
		APIBaseURL:    "https://api.github.test",
		HTTPClient:    client,
	})
	if err != nil {
		t.Fatalf("NewAppAuthenticator() error = %v", err)
	}

	if err := authenticator.VerifyRepository(context.Background(), 42, 7, "acme/deployguard"); err == nil {
		t.Fatal("VerifyRepository() accepted a different installation")
	}
}

func TestAppAuthenticatorScopesInstallationTokenToRepository(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/app/installations/42/access_tokens" || request.Method != http.MethodPost {
			return response(http.StatusNotFound, ""), nil
		}
		body, err := io.ReadAll(request.Body)
		if err != nil || string(body) != `{"repository_ids":[7]}` || request.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("token scope = %s, content-type = %q, err = %v", body, request.Header.Get("Content-Type"), err)
		}
		return response(http.StatusCreated, `{"token":"scoped-token","expires_at":"2030-01-01T00:00:00Z"}`), nil
	})}
	authenticator, err := NewAppAuthenticator(AppAuthenticatorConfig{
		AppID: 101, PrivateKeyPEM: privateKeyPEM(key), APIBaseURL: "https://api.github.test", HTTPClient: client,
	})
	if err != nil {
		t.Fatalf("NewAppAuthenticator() error = %v", err)
	}
	token, err := authenticator.InstallationTokenForRepository(context.Background(), 42, 7)
	if err != nil || token.Token != "scoped-token" {
		t.Fatalf("InstallationTokenForRepository() = %#v, %v", token, err)
	}
}

func privateKeyPEM(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}
