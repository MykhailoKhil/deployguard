package github

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const defaultGitHubAPIBaseURL = "https://api.github.com"

// AppAuthenticatorConfig supplies GitHub App credentials held only in memory.
type AppAuthenticatorConfig struct {
	AppID         int64
	PrivateKeyPEM []byte
	APIBaseURL    string
	HTTPClient    *http.Client
}

// InstallationToken is a short-lived GitHub installation access token.
type InstallationToken struct {
	Token     string
	ExpiresAt time.Time
}

// AppAuthenticator authenticates as the GitHub App and verifies repository
// installation membership before repository-scoped work occurs.
type AppAuthenticator struct {
	appID      int64
	privateKey *rsa.PrivateKey
	apiBaseURL *url.URL
	httpClient *http.Client
	now        func() time.Time

	slugMu    sync.Mutex
	slugCache string // the App's URL slug, fetched once; bot comments are authored by "<slug>[bot]"
}

// NewAppAuthenticator parses an RSA private key and configures GitHub's API.
func NewAppAuthenticator(config AppAuthenticatorConfig) (*AppAuthenticator, error) {
	if config.AppID <= 0 {
		return nil, errors.New("GitHub App ID is required")
	}
	privateKey, err := parseRSAPrivateKey(config.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}
	baseURL := config.APIBaseURL
	if baseURL == "" {
		baseURL = defaultGitHubAPIBaseURL
	}
	parsedURL, err := url.Parse(baseURL)
	if err != nil || parsedURL.Scheme != "https" || parsedURL.Host == "" || parsedURL.User != nil || parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return nil, errors.New("GitHub API base URL must be a valid HTTPS URL")
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultHTTPTimeout}
	}
	return &AppAuthenticator{appID: config.AppID, privateKey: privateKey, apiBaseURL: parsedURL, httpClient: client, now: time.Now}, nil
}

// VerifyRepository confirms the signed webhook installation matches the GitHub
// App installation configured for the event repository.
func (a *AppAuthenticator) VerifyRepository(ctx context.Context, installationID, repositoryID int64, fullName string) error {
	if installationID <= 0 || repositoryID <= 0 {
		return ErrRepositoryNotInstalled
	}
	actualInstallationID, err := a.RepositoryInstallationID(ctx, repositoryID, fullName)
	if err != nil || actualInstallationID != installationID {
		return ErrRepositoryNotInstalled
	}
	return nil
}

// RepositoryInstallationID asks GitHub which installation of this App can access the repository.
// It returns ErrRepositoryNotInstalled when there is none or the name is malformed.
func (a *AppAuthenticator) RepositoryInstallationID(ctx context.Context, repositoryID int64, fullName string) (int64, error) {
	if repositoryID <= 0 {
		return 0, ErrRepositoryNotInstalled
	}
	owner, repository, ok := strings.Cut(fullName, "/")
	if !ok || owner == "" || repository == "" || strings.Contains(repository, "/") || strings.ContainsAny(fullName, "?#\\") {
		return 0, ErrRepositoryNotInstalled
	}
	jwt, err := a.appJWT()
	if err != nil {
		return 0, fmt.Errorf("create GitHub App JWT: %w", err)
	}
	endpoint := a.apiURL("/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repository) + "/installation")
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, fmt.Errorf("create GitHub installation verification request: %w", err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+jwt)
	response, err := a.httpClient.Do(request)
	if err != nil {
		return 0, fmt.Errorf("verify GitHub repository installation: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return 0, ErrRepositoryNotInstalled
	}
	var installation struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(response.Body).Decode(&installation); err != nil || installation.ID <= 0 {
		return 0, ErrRepositoryNotInstalled
	}
	return installation.ID, nil
}

var appSlugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// appInfo is what GET /app reports about this App.
type appInfo struct {
	slug        string
	permissions map[string]string
}

// fetchApp asks GitHub who this App is (authenticated with the App JWT).
func (a *AppAuthenticator) fetchApp(ctx context.Context) (appInfo, error) {
	jwt, err := a.appJWT()
	if err != nil {
		return appInfo{}, fmt.Errorf("create GitHub App JWT: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, a.apiURL("/app"), nil)
	if err != nil {
		return appInfo{}, errors.New("create GitHub App lookup request")
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+jwt)
	response, err := a.httpClient.Do(request)
	if err != nil {
		return appInfo{}, errors.New("look up the GitHub App")
	}
	var app struct {
		ID          int64             `json:"id"`
		Slug        string            `json:"slug"`
		Permissions map[string]string `json:"permissions"`
	}
	if err := decodeGitHubResponse(response, http.StatusOK, &app); err != nil || app.ID != a.appID || !appSlugPattern.MatchString(app.Slug) {
		return appInfo{}, errors.New("look up the GitHub App")
	}
	return appInfo{slug: app.Slug, permissions: app.Permissions}, nil
}

// Slug returns the App's URL slug from GitHub (cached after the first success). Comments the App
// writes with an installation token are authored by the bot user "<slug>[bot]".
func (a *AppAuthenticator) Slug(ctx context.Context) (string, error) {
	a.slugMu.Lock()
	defer a.slugMu.Unlock()
	if a.slugCache != "" {
		return a.slugCache, nil
	}
	info, err := a.fetchApp(ctx)
	if err != nil {
		return "", err
	}
	a.slugCache = info.slug
	return info.slug, nil
}

// Permissions returns the permissions the App is configured with on GitHub (for example
// "pull_requests": "write"). It is a fresh lookup each time. These are the App's settings; an
// installation owner must still accept a permission change before it applies to that installation.
func (a *AppAuthenticator) Permissions(ctx context.Context) (map[string]string, error) {
	info, err := a.fetchApp(ctx)
	if err != nil {
		return nil, err
	}
	return info.permissions, nil
}

// InstallationToken creates a short-lived installation access token for the
// verified installation. Callers must not persist the returned token.
func (a *AppAuthenticator) InstallationToken(ctx context.Context, installationID int64) (InstallationToken, error) {
	return a.installationToken(ctx, installationID, 0)
}

// InstallationTokenForRepository is InstallationToken narrowed to a single repository, so a
// leaked token cannot reach the installation's other repositories.
func (a *AppAuthenticator) InstallationTokenForRepository(ctx context.Context, installationID, repositoryID int64) (InstallationToken, error) {
	if repositoryID <= 0 {
		return InstallationToken{}, errors.New("GitHub repository ID is required")
	}
	return a.installationToken(ctx, installationID, repositoryID)
}

func (a *AppAuthenticator) installationToken(ctx context.Context, installationID, repositoryID int64) (InstallationToken, error) {
	if installationID <= 0 {
		return InstallationToken{}, errors.New("GitHub installation ID is required")
	}
	jwt, err := a.appJWT()
	if err != nil {
		return InstallationToken{}, fmt.Errorf("create GitHub App JWT: %w", err)
	}
	var body io.Reader
	if repositoryID > 0 {
		encoded, err := json.Marshal(struct {
			RepositoryIDs []int64 `json:"repository_ids"`
		}{RepositoryIDs: []int64{repositoryID}})
		if err != nil {
			return InstallationToken{}, errors.New("encode GitHub installation token scope")
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, a.apiURL(fmt.Sprintf("/app/installations/%d/access_tokens", installationID)), body)
	if err != nil {
		return InstallationToken{}, fmt.Errorf("create GitHub installation token request: %w", err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+jwt)
	if repositoryID > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := a.httpClient.Do(request)
	if err != nil {
		return InstallationToken{}, fmt.Errorf("create GitHub installation token: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return InstallationToken{}, fmt.Errorf("create GitHub installation token: unexpected status %d", response.StatusCode)
	}
	var result struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil || result.Token == "" || result.ExpiresAt.IsZero() {
		return InstallationToken{}, errors.New("decode GitHub installation token response")
	}
	return InstallationToken{Token: result.Token, ExpiresAt: result.ExpiresAt}, nil
}

func (a *AppAuthenticator) appJWT() (string, error) {
	header, err := base64RawJSON(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	now := a.now().UTC()
	claims, err := base64RawJSON(map[string]any{
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": a.appID,
	})
	if err != nil {
		return "", err
	}
	unsigned := header + "." + claims
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, a.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (a *AppAuthenticator) apiURL(path string) string {
	endpoint := *a.apiBaseURL
	// Split "path?query" so the "?" is not escaped into the path.
	path, rawQuery, _ := strings.Cut(path, "?")
	endpoint.Path = strings.TrimSuffix(endpoint.Path, "/") + path
	endpoint.RawQuery = rawQuery
	return endpoint.String()
}

func base64RawJSON(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("GitHub App private key must be PEM encoded")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("GitHub App private key is invalid")
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("GitHub App private key must be RSA")
	}
	return rsaKey, nil
}

var _ RepositoryVerifier = (*AppAuthenticator)(nil)
