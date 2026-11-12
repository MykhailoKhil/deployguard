package github

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const maxGitHubResponseBytes = 2 << 20
const maxPlanArtifactBytes = 12 << 20
const maxPlanArtifactExpandedBytes = 10 << 20
const maxRepositoryPages = 10

// maxUserInstallations bounds the API calls one page view can cost.
const maxUserInstallations = 50

// ErrArtifactTooLarge is returned when a plan artifact exceeds the size limit.
var ErrArtifactTooLarge = errors.New("GitHub plan artifact exceeds size limit")

// ErrGitHubAccessDenied is returned when the user or the App installation cannot access the
// repository, or the pull request comes from a fork.
var ErrGitHubAccessDenied = errors.New("GitHub user or App installation cannot access this repository")

// Repository identifies a GitHub repository.
type Repository struct {
	ID       int64
	Name     string
	FullName string
	// InstallationID is the App installation through which the repository was listed (set by
	// ListRepositories; zero elsewhere).
	InstallationID int64
}

// PullRequest is an open pull request. Fork is true when its head branch lives in another repository.
type PullRequest struct {
	Number  int
	Title   string
	HeadSHA string
	Fork    bool
}

// ReviewClient lists repositories and pull requests for a signed-in user and downloads plan
// artifacts as the GitHub App. Each call re-checks that both the user and an App installation
// can access the repository.
type ReviewClient struct {
	apiBaseURL *url.URL
	app        *AppAuthenticator
	httpClient *http.Client
}

// VerifiedReview is a pull request confirmed accessible to the signed-in user and to an
// installation of the App.
type VerifiedReview struct {
	Repository     Repository
	PullRequest    PullRequest
	InstallationID int64
}

// PlanArtifactConfig names the CI workflow, artifact, and file that hold a Terraform plan.
// RunID, when set, pins one specific workflow run.
type PlanArtifactConfig struct {
	WorkflowFilename string
	ArtifactName     string
	PlanFilename     string
	RunID            int64
}

// ReviewClientConfig supplies the App authenticator and the (HTTPS) GitHub API address.
type ReviewClientConfig struct {
	APIBaseURL string
	App        *AppAuthenticator
	HTTPClient *http.Client
}

// NewReviewClient validates the configuration and returns a ReviewClient.
func NewReviewClient(config ReviewClientConfig) (*ReviewClient, error) {
	if config.App == nil {
		return nil, errors.New("GitHub App authenticator is required")
	}
	baseURL := config.APIBaseURL
	if baseURL == "" {
		baseURL = defaultGitHubAPIBaseURL
	}
	parsedURL, err := parseBaseURL(baseURL)
	if err != nil || parsedURL.Scheme != "https" || parsedURL.User != nil || parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return nil, errors.New("GitHub API base URL must use HTTPS")
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultHTTPTimeout}
	}
	return &ReviewClient{apiBaseURL: parsedURL, app: config.App, httpClient: client}, nil
}

// ListRepositories returns the repositories the signed-in user can reach through installations of
// this App. It uses the two endpoints GitHub documents for GitHub App user access tokens: the user's
// installations, then each installation's repositories. Both are limited to what the user has
// explicit access to, so the result is exactly "user can see it" AND "the App is installed there".
func (c *ReviewClient) ListRepositories(ctx context.Context, userToken string) ([]Repository, error) {
	if strings.TrimSpace(userToken) == "" {
		return nil, ErrGitHubAccessDenied
	}
	var installations []int64
	err := c.userPages(ctx, userToken, "/user/installations?per_page=100", func(response *http.Response) error {
		var page struct {
			Installations []struct {
				ID          int64      `json:"id"`
				SuspendedAt *time.Time `json:"suspended_at"`
			} `json:"installations"`
		}
		if err := decodeGitHubResponse(response, http.StatusOK, &page); err != nil {
			return err
		}
		for _, installation := range page.Installations {
			if installation.ID > 0 && installation.SuspendedAt == nil {
				installations = append(installations, installation.ID)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(installations) > maxUserInstallations {
		installations = installations[:maxUserInstallations]
	}
	seen := map[int64]bool{}
	var repositories []Repository
	for _, installationID := range installations {
		path := fmt.Sprintf("/user/installations/%d/repositories?per_page=100", installationID)
		err := c.userPages(ctx, userToken, path, func(response *http.Response) error {
			var page struct {
				Repositories []struct {
					ID       int64  `json:"id"`
					Name     string `json:"name"`
					FullName string `json:"full_name"`
				} `json:"repositories"`
			}
			if err := decodeGitHubResponse(response, http.StatusOK, &page); err != nil {
				return err
			}
			for _, repository := range page.Repositories {
				if repository.ID <= 0 || repository.Name == "" || repository.FullName == "" {
					return errors.New("invalid repository in response")
				}
				if !seen[repository.ID] {
					seen[repository.ID] = true
					repositories = append(repositories, Repository{ID: repository.ID, Name: repository.Name, FullName: repository.FullName, InstallationID: installationID})
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(repositories, func(i, j int) bool { return repositories[i].FullName < repositories[j].FullName })
	return repositories, nil
}

// userPages walks a paginated GitHub endpoint with the user's token. Every next-page URL GitHub
// returns must stay on the configured API host, so a hostile Link header cannot send the token
// elsewhere. decode handles one page.
func (c *ReviewClient) userPages(ctx context.Context, userToken, firstPath string, decode func(*http.Response) error) error {
	pageURL := c.apiURL(firstPath)
	basePath := strings.TrimSuffix(c.apiBaseURL.Path, "/")
	for pages := 0; pageURL != ""; pages++ {
		if pages >= maxRepositoryPages {
			return errors.New("load GitHub repositories: too many pages")
		}
		parsed, err := url.Parse(pageURL)
		if err != nil || parsed.Scheme != c.apiBaseURL.Scheme || parsed.Host != c.apiBaseURL.Host || parsed.User != nil || parsed.RawQuery == "" || (basePath != "" && parsed.Path != basePath && !strings.HasPrefix(parsed.Path, basePath+"/")) {
			return errors.New("load GitHub repositories: pagination URL is outside the configured API host")
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
		if err != nil {
			return errors.New("create GitHub repository request")
		}
		setGitHubHeaders(request, userToken)
		response, err := c.httpClient.Do(request)
		if err != nil {
			return errors.New("load GitHub repositories")
		}
		link := responseHeaderLink(response)
		if err := decode(response); err != nil {
			return errors.New("load GitHub repositories: unexpected response")
		}
		pageURL = nextPage(link)
	}
	return nil
}

// ListPullRequests returns the open pull requests of one repository the user can access.
func (c *ReviewClient) ListPullRequests(ctx context.Context, userToken string, repositoryID int64) (Repository, []PullRequest, error) {
	repository, err := c.userRepository(ctx, userToken, repositoryID)
	if err != nil {
		return Repository{}, nil, err
	}
	if _, err := c.app.RepositoryInstallationID(ctx, repository.ID, repository.FullName); err != nil {
		return Repository{}, nil, ErrGitHubAccessDenied
	}
	endpoint := c.apiURL(fmt.Sprintf("/repos/%s/pulls?state=open&per_page=100", pathRepository(repository.FullName)))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Repository{}, nil, errors.New("create GitHub pull request request")
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+userToken)
	response, err := c.httpClient.Do(request)
	if err != nil {
		return Repository{}, nil, errors.New("load GitHub pull requests")
	}
	var raw []struct {
		Number int    `json:"number"`
		Title  string `json:"title"`
		Head   struct {
			SHA  string `json:"sha"`
			Repo *struct {
				ID int64 `json:"id"`
			} `json:"repo"`
		} `json:"head"`
		Base struct {
			Repo struct {
				ID int64 `json:"id"`
			} `json:"repo"`
		} `json:"base"`
	}
	if err := decodeGitHubResponse(response, http.StatusOK, &raw); err != nil {
		return Repository{}, nil, errors.New("load GitHub pull requests: unexpected response")
	}
	pullRequests := make([]PullRequest, 0, len(raw))
	for _, item := range raw {
		if item.Number <= 0 || item.Title == "" || item.Head.SHA == "" || item.Base.Repo.ID != repository.ID {
			continue
		}
		fork := item.Head.Repo == nil || item.Head.Repo.ID != repository.ID
		pullRequests = append(pullRequests, PullRequest{Number: item.Number, Title: item.Title, HeadSHA: item.Head.SHA, Fork: fork})
	}
	return repository, pullRequests, nil
}

// VerifyPullRequest re-checks access and returns the repository and one pull request as GitHub
// currently reports them.
func (c *ReviewClient) VerifyPullRequest(ctx context.Context, userToken string, repositoryID int64, pullRequestNumber int) (Repository, PullRequest, error) {
	repository, pullRequest, _, err := c.verifyPullRequest(ctx, userToken, repositoryID, pullRequestNumber)
	return repository, pullRequest, err
}

func (c *ReviewClient) verifyPullRequest(ctx context.Context, userToken string, repositoryID int64, pullRequestNumber int) (Repository, PullRequest, int64, error) {
	if pullRequestNumber <= 0 {
		return Repository{}, PullRequest{}, 0, ErrGitHubAccessDenied
	}
	repository, err := c.userRepository(ctx, userToken, repositoryID)
	if err != nil {
		return Repository{}, PullRequest{}, 0, err
	}
	installationID, err := c.app.RepositoryInstallationID(ctx, repository.ID, repository.FullName)
	if err != nil {
		return Repository{}, PullRequest{}, 0, ErrGitHubAccessDenied
	}
	endpoint := c.apiURL(fmt.Sprintf("/repos/%s/pulls/%d", pathRepository(repository.FullName), pullRequestNumber))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Repository{}, PullRequest{}, 0, errors.New("create GitHub pull request request")
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+userToken)
	response, err := c.httpClient.Do(request)
	if err != nil {
		return Repository{}, PullRequest{}, 0, errors.New("load GitHub pull request")
	}
	var raw struct {
		Number int    `json:"number"`
		Title  string `json:"title"`
		State  string `json:"state"`
		Head   struct {
			SHA  string `json:"sha"`
			Repo *struct {
				ID int64 `json:"id"`
			} `json:"repo"`
		} `json:"head"`
		Base struct {
			Repo struct {
				ID int64 `json:"id"`
			} `json:"repo"`
		} `json:"base"`
	}
	if err := decodeGitHubResponse(response, http.StatusOK, &raw); err != nil {
		return Repository{}, PullRequest{}, 0, errors.New("load GitHub pull request: unexpected response")
	}
	if raw.Number != pullRequestNumber || raw.Title == "" || raw.State != "open" || raw.Head.SHA == "" || raw.Base.Repo.ID != repository.ID {
		return Repository{}, PullRequest{}, 0, ErrGitHubAccessDenied
	}
	fork := raw.Head.Repo == nil || raw.Head.Repo.ID != repository.ID
	return repository, PullRequest{Number: raw.Number, Title: raw.Title, HeadSHA: raw.Head.SHA, Fork: fork}, installationID, nil
}

// VerifyReview is VerifyPullRequest plus the installation ID needed for later App calls.
func (c *ReviewClient) VerifyReview(ctx context.Context, userToken string, repositoryID int64, pullRequestNumber int) (VerifiedReview, error) {
	repository, pullRequest, installationID, err := c.verifyPullRequest(ctx, userToken, repositoryID, pullRequestNumber)
	if err != nil {
		return VerifiedReview{}, err
	}
	return VerifiedReview{Repository: repository, PullRequest: pullRequest, InstallationID: installationID}, nil
}

// DownloadPlanArtifact returns the plan JSON uploaded by the successful workflow run for the pull
// request's current head commit. It refuses forks and runs from other repositories, and bounds the
// archive size.
func (c *ReviewClient) DownloadPlanArtifact(ctx context.Context, review VerifiedReview, config PlanArtifactConfig) ([]byte, error) {
	if review.PullRequest.Fork {
		return nil, ErrGitHubAccessDenied
	}
	if review.Repository.ID <= 0 || review.InstallationID <= 0 || review.PullRequest.Number <= 0 || review.PullRequest.HeadSHA == "" || config.WorkflowFilename == "" || config.ArtifactName == "" {
		return nil, errors.New("verified review and artifact configuration are required")
	}
	planFilename := config.PlanFilename
	if planFilename == "" {
		planFilename = "tfplan.json"
	}
	if strings.ContainsAny(planFilename, "/\\?#") || strings.Contains(planFilename, "..") {
		return nil, errors.New("plan filename must be a basename")
	}
	if strings.TrimSpace(config.ArtifactName) != config.ArtifactName || strings.ContainsAny(config.ArtifactName, "/\\?#") || strings.Contains(config.ArtifactName, "..") {
		return nil, errors.New("artifact name must be a basename")
	}
	token, err := c.app.InstallationTokenForRepository(ctx, review.InstallationID, review.Repository.ID)
	if err != nil {
		return nil, errors.New("authenticate GitHub artifact request")
	}
	runs, err := c.workflowRuns(ctx, token.Token, review.Repository, config.WorkflowFilename)
	if err != nil {
		return nil, err
	}
	var selected *workflowRun
	for index := range runs {
		run := &runs[index]
		if config.RunID > 0 && run.ID != config.RunID {
			continue
		}
		if run.Status != "completed" || run.Conclusion != "success" || run.HeadSHA != review.PullRequest.HeadSHA || run.HeadRepositoryID != review.Repository.ID || run.Event != "pull_request" || run.PullRequestNumber != review.PullRequest.Number {
			continue
		}
		if selected == nil || run.CreatedAt.After(selected.CreatedAt) {
			selected = run
		}
	}
	if selected == nil {
		return nil, errors.New("no successful workflow run matches the pull request head")
	}
	if config.RunID > 0 && selected.ID != config.RunID {
		return nil, errors.New("requested workflow run does not match the pull request head")
	}
	artifacts, err := c.workflowArtifacts(ctx, token.Token, review.Repository, selected.ID)
	if err != nil {
		return nil, err
	}
	for _, artifact := range artifacts {
		if artifact.Name != config.ArtifactName || artifact.Expired || artifact.ID <= 0 || artifact.SizeInBytes <= 0 || artifact.SizeInBytes > maxPlanArtifactBytes {
			continue
		}
		archiveURL := artifact.ArchiveDownloadURL
		if archiveURL == "" {
			archiveURL = c.apiURL(fmt.Sprintf("/repos/%s/actions/artifacts/%d/zip", pathRepository(review.Repository.FullName), artifact.ID))
		}
		archive, err := c.download(ctx, token.Token, archiveURL, maxPlanArtifactBytes)
		if err != nil {
			if errors.Is(err, ErrArtifactTooLarge) {
				return nil, err
			}
			return nil, errors.New("download GitHub plan artifact")
		}
		return extractPlanJSON(archive, planFilename)
	}
	return nil, errors.New("expected plan artifact is unavailable")
}

type workflowRun struct {
	ID                int64
	Status            string
	Conclusion        string
	Event             string
	HeadSHA           string
	HeadRepositoryID  int64
	WorkflowPath      string
	PullRequestNumber int
	CreatedAt         time.Time
}

func (c *ReviewClient) workflowRuns(ctx context.Context, token string, repository Repository, workflowFilename string) ([]workflowRun, error) {
	if workflowFilename == "" || strings.ContainsAny(workflowFilename, "/\\?#") || strings.Contains(workflowFilename, "..") {
		return nil, errors.New("workflow filename must be a basename")
	}
	endpoint := c.apiURL(fmt.Sprintf("/repos/%s/actions/workflows/%s/runs?per_page=100", pathRepository(repository.FullName), escapeWorkflowPath(workflowFilename)))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, errors.New("create GitHub workflow request")
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, errors.New("load GitHub workflow runs")
	}
	// GitHub's workflow-runs response has no top-level workflow ID or path, only
	// per-run fields; each run's own path is checked against the configured file.
	var payload struct {
		WorkflowRuns []struct {
			ID         int64  `json:"id"`
			Status     string `json:"status"`
			Conclusion string `json:"conclusion"`
			Event      string `json:"event"`
			HeadSHA    string `json:"head_sha"`
			Path       string `json:"path"`
			HeadRepo   *struct {
				ID int64 `json:"id"`
			} `json:"head_repository"`
			CreatedAt    time.Time `json:"created_at"`
			PullRequests []struct {
				Number int `json:"number"`
			} `json:"pull_requests"`
		} `json:"workflow_runs"`
	}
	if err := decodeGitHubResponse(response, http.StatusOK, &payload); err != nil {
		return nil, errors.New("load GitHub workflow runs")
	}
	runs := make([]workflowRun, 0, len(payload.WorkflowRuns))
	for _, run := range payload.WorkflowRuns {
		if run.ID <= 0 || !workflowPathMatches(run.Path, workflowFilename) || len(run.PullRequests) != 1 {
			continue
		}
		var headRepositoryID int64
		if run.HeadRepo != nil {
			headRepositoryID = run.HeadRepo.ID
		}
		runs = append(runs, workflowRun{ID: run.ID, Status: run.Status, Conclusion: run.Conclusion, Event: run.Event, HeadSHA: run.HeadSHA, HeadRepositoryID: headRepositoryID, WorkflowPath: run.Path, PullRequestNumber: run.PullRequests[0].Number, CreatedAt: run.CreatedAt})
	}
	return runs, nil
}

func (c *ReviewClient) workflowArtifacts(ctx context.Context, token string, repository Repository, runID int64) ([]struct {
	Name               string `json:"name"`
	Expired            bool   `json:"expired"`
	SizeInBytes        int64  `json:"size_in_bytes"`
	ID                 int64  `json:"id"`
	ArchiveDownloadURL string `json:"archive_download_url"`
}, error) {
	endpoint := c.apiURL(fmt.Sprintf("/repos/%s/actions/runs/%d/artifacts?per_page=100", pathRepository(repository.FullName), runID))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, errors.New("create GitHub artifact request")
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, errors.New("load GitHub artifacts")
	}
	var payload struct {
		Artifacts []struct {
			Name               string `json:"name"`
			Expired            bool   `json:"expired"`
			SizeInBytes        int64  `json:"size_in_bytes"`
			ID                 int64  `json:"id"`
			ArchiveDownloadURL string `json:"archive_download_url"`
		} `json:"artifacts"`
	}
	if err := decodeGitHubResponse(response, http.StatusOK, &payload); err != nil {
		return nil, errors.New("load GitHub artifacts: unexpected response")
	}
	return payload.Artifacts, nil
}

func (c *ReviewClient) download(ctx context.Context, token, targetURL string, maxBytes int64) ([]byte, error) {
	parsed, err := url.Parse(targetURL)
	if err != nil || parsed.Scheme != c.apiBaseURL.Scheme || parsed.Host != c.apiBaseURL.Host || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("GitHub artifact URL is outside the configured API host")
	}
	basePath := strings.TrimSuffix(c.apiBaseURL.Path, "/")
	if strings.TrimSuffix(parsed.Path, "/") == "" || (basePath != "" && parsed.Path != basePath && !strings.HasPrefix(parsed.Path, basePath+"/")) {
		return nil, errors.New("GitHub artifact URL is outside the configured API base path")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, errors.New("create artifact download request")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, errors.New("download artifact")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("download artifact: unexpected response")
	}
	if response.ContentLength > maxBytes {
		return nil, ErrArtifactTooLarge
	}
	limited := io.LimitReader(response.Body, maxBytes+1)
	content, err := io.ReadAll(limited)
	if err != nil || int64(len(content)) > maxBytes {
		return nil, ErrArtifactTooLarge
	}
	return content, nil
}

func extractPlanJSON(archive []byte, expectedName string) ([]byte, error) {
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil || len(reader.File) != 1 {
		return nil, errors.New("artifact archive must contain exactly one plan JSON file")
	}
	file := reader.File[0]
	if file.Name != expectedName || file.FileInfo().IsDir() || file.Mode().Type() != 0 && !file.Mode().IsRegular() || file.UncompressedSize64 > maxPlanArtifactExpandedBytes {
		if file.UncompressedSize64 > maxPlanArtifactExpandedBytes {
			return nil, ErrArtifactTooLarge
		}
		return nil, errors.New("artifact archive contains unexpected or oversized content")
	}
	contentReader, err := file.Open()
	if err != nil {
		return nil, errors.New("open plan artifact")
	}
	defer contentReader.Close()
	content, err := io.ReadAll(io.LimitReader(contentReader, maxPlanArtifactExpandedBytes+1))
	if int64(len(content)) > maxPlanArtifactExpandedBytes {
		return nil, ErrArtifactTooLarge
	}
	if err != nil || len(content) == 0 {
		if err != nil {
			return nil, errors.New("read plan artifact")
		}
		return nil, errors.New("plan artifact exceeds expanded size limit")
	}
	return content, nil
}

func (c *ReviewClient) userRepository(ctx context.Context, userToken string, repositoryID int64) (Repository, error) {
	if repositoryID <= 0 || userToken == "" {
		return Repository{}, ErrGitHubAccessDenied
	}
	endpoint := c.apiURL("/repositories/" + strconv.FormatInt(repositoryID, 10))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Repository{}, errors.New("create GitHub repository request")
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+userToken)
	response, err := c.httpClient.Do(request)
	if err != nil {
		return Repository{}, errors.New("load GitHub repository")
	}
	var raw struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		FullName string `json:"full_name"`
	}
	if err := decodeGitHubResponse(response, http.StatusOK, &raw); err != nil || raw.ID != repositoryID || raw.Name == "" || raw.FullName == "" {
		return Repository{}, ErrGitHubAccessDenied
	}
	return Repository{ID: raw.ID, Name: raw.Name, FullName: raw.FullName}, nil
}

func (c *ReviewClient) apiURL(path string) string {
	endpoint := *c.apiBaseURL
	// Callers pass "path?query"; assigning that whole string to URL.Path would
	// escape the "?" as %3F and send a malformed request, so split it.
	path, rawQuery, _ := strings.Cut(path, "?")
	endpoint.Path = strings.TrimSuffix(endpoint.Path, "/") + path
	endpoint.RawQuery = rawQuery
	return endpoint.String()
}

func pathRepository(fullName string) string {
	parts := strings.SplitN(fullName, "/", 2)
	if len(parts) != 2 {
		return ""
	}
	return url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1])
}

func escapeWorkflowPath(path string) string {
	parts := strings.Split(path, "/")
	for index := range parts {
		parts[index] = url.PathEscape(parts[index])
	}
	return strings.Join(parts, "/")
}

func workflowPathMatches(actual, configured string) bool {
	if at := strings.IndexByte(actual, '@'); at >= 0 {
		actual = actual[:at]
	}
	actual = strings.TrimPrefix(actual, ".github/workflows/")
	configured = strings.TrimPrefix(configured, ".github/workflows/")
	return actual == configured
}

// decodeGitHubResponseWithin is decodeGitHubResponse with its own size limit, for the few endpoints
// whose pages can legitimately exceed the default (for example 100 long comments). A body over the
// limit is an error, never a silently truncated parse.
func decodeGitHubResponseWithin(response *http.Response, expectedStatus int, limit int64, target any) error {
	defer response.Body.Close()
	if response.StatusCode != expectedStatus {
		return fmt.Errorf("unexpected GitHub API status %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return err
	}
	if int64(len(raw)) > limit {
		return fmt.Errorf("GitHub response is larger than %d bytes", limit)
	}
	return json.Unmarshal(raw, target)
}

func decodeGitHubResponse(response *http.Response, expectedStatus int, target any) error {
	defer response.Body.Close()
	if response.StatusCode != expectedStatus {
		return fmt.Errorf("unexpected GitHub API status %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxGitHubResponseBytes))
	return decoder.Decode(target)
}

func responseHeaderLink(response *http.Response) string {
	return response.Header.Get("Link")
}

func nextPage(linkHeader string) string {
	for _, segment := range strings.Split(linkHeader, ",") {
		if !strings.Contains(segment, `rel="next"`) {
			continue
		}
		start := strings.IndexByte(segment, '<')
		end := strings.IndexByte(segment, '>')
		if start >= 0 && end > start {
			return segment[start+1 : end]
		}
	}
	return ""
}
