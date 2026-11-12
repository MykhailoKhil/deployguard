package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const (
	// CheckRunName is the single check DeployGuard owns on a commit.
	CheckRunName = "DeployGuard"

	maxCheckTitleRunes = 255
	maxCheckTextBytes  = 60000 // GitHub's limit is 65535
)

var commitSHAPattern = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)

// CheckRun is the completed result DeployGuard publishes for one commit.
type CheckRun struct {
	HeadSHA string
	// Conclusion is "success", "neutral" or "failure".
	Conclusion string
	Title      string
	Summary    string
}

// ChecksClient publishes Check Runs as the GitHub App installation. It only
// ever writes the check run named CheckRunName, so a repeated webhook updates
// the existing run instead of creating duplicates.
type ChecksClient struct {
	app *AppAuthenticator
}

// NewChecksClient returns a client that publishes Check Runs as the given GitHub App.
func NewChecksClient(app *AppAuthenticator) (*ChecksClient, error) {
	if app == nil {
		return nil, errors.New("GitHub App authenticator is required")
	}
	return &ChecksClient{app: app}, nil
}

// Publish creates the DeployGuard check run for the commit, or updates it when
// one already exists. The installation token is scoped to the one repository.
func (c *ChecksClient) Publish(ctx context.Context, installationID, repositoryID int64, repositoryFullName string, run CheckRun) error {
	repositoryPath := pathRepository(repositoryFullName)
	if repositoryPath == "" || strings.ContainsAny(repositoryFullName, "?#\\") {
		return errors.New("invalid repository name")
	}
	if !commitSHAPattern.MatchString(run.HeadSHA) {
		return errors.New("invalid commit SHA")
	}
	switch run.Conclusion {
	case "success", "neutral", "failure":
	default:
		return errors.New("invalid check run conclusion")
	}
	token, err := c.app.InstallationTokenForRepository(ctx, installationID, repositoryID)
	if err != nil {
		return errors.New("authenticate GitHub check run request")
	}
	existingID, err := c.existingCheckRunID(ctx, token.Token, repositoryPath, run.HeadSHA)
	if err != nil {
		return err
	}
	body := map[string]any{
		"name":       CheckRunName,
		"status":     "completed",
		"conclusion": run.Conclusion,
		"output": map[string]string{
			"title":   truncateRunes(run.Title, maxCheckTitleRunes),
			"summary": truncateBytes(run.Summary, maxCheckTextBytes),
		},
	}
	method, endpoint := http.MethodPost, c.app.apiURL("/repos/"+repositoryPath+"/check-runs")
	if existingID > 0 {
		method, endpoint = http.MethodPatch, c.app.apiURL(fmt.Sprintf("/repos/%s/check-runs/%d", repositoryPath, existingID))
	} else {
		body["head_sha"] = run.HeadSHA
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return errors.New("encode check run")
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return errors.New("create check run request")
	}
	setGitHubHeaders(request, token.Token)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.app.httpClient.Do(request)
	if err != nil {
		return errors.New("publish GitHub check run")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		return fmt.Errorf("publish GitHub check run: unexpected status %d", response.StatusCode)
	}
	return nil
}

func (c *ChecksClient) existingCheckRunID(ctx context.Context, token, repositoryPath, sha string) (int64, error) {
	query := url.Values{"check_name": {CheckRunName}, "app_id": {fmt.Sprint(c.app.appID)}, "filter": {"latest"}, "per_page": {"1"}}
	endpoint := c.app.apiURL("/repos/" + repositoryPath + "/commits/" + url.PathEscape(sha) + "/check-runs?" + query.Encode())
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, errors.New("create check run lookup request")
	}
	setGitHubHeaders(request, token)
	response, err := c.app.httpClient.Do(request)
	if err != nil {
		return 0, errors.New("look up GitHub check run")
	}
	var result struct {
		CheckRuns []struct {
			ID int64 `json:"id"`
		} `json:"check_runs"`
	}
	if err := decodeGitHubResponse(response, http.StatusOK, &result); err != nil {
		return 0, errors.New("look up GitHub check run")
	}
	if len(result.CheckRuns) == 0 {
		return 0, nil
	}
	return result.CheckRuns[0].ID, nil
}

func truncateRunes(value string, limit int) string {
	if runes := []rune(value); len(runes) > limit {
		return string(runes[:limit])
	}
	return value
}

func truncateBytes(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	cut := limit
	for cut > 0 && value[cut]&0xC0 == 0x80 { // do not split a UTF-8 sequence
		cut--
	}
	return value[:cut]
}
