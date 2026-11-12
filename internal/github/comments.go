package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

const (
	// CommentMarker starts every comment DeployGuard writes, so a rerun finds its own comment
	// instead of adding another.
	CommentMarker = "<!-- deployguard:pr-comment -->"

	stateLinePrefix = "<!-- deployguard:state "
	maxCommentBytes = 60000 // GitHub's limit is 65536
	maxCommentPages = 10    // 100 comments per page: stops a huge thread from costing unbounded calls
)

// ErrCommentPermission is returned when GitHub refuses to write a comment. The usual cause is that
// the App lacks "Pull requests: write", or that the installation owner has not accepted it yet.
var ErrCommentPermission = errors.New("GitHub refused the comment: the App needs the Pull requests: write permission, and the installation owner must accept it")

// ErrStaleHead is returned when the pull request's head moved on since the analysis started. The
// comment is left alone so an older verdict cannot overwrite a newer one.
var ErrStaleHead = errors.New("pull request head moved on; comment not updated")

// CommentUpdate is one verdict to show on a pull request.
type CommentUpdate struct {
	Body string // markdown without the marker; the client adds the marker and a state line
	// HeadSHA is the commit this verdict is for. The update is skipped if the PR head differs.
	HeadSHA string
	// Recommendation is "SAFE", "REVIEW" or "BLOCK", or "" when there is no verdict for the commit.
	Recommendation string
}

// CommentsClient keeps one DeployGuard comment on a pull request. It needs the GitHub App's
// "Pull requests: write" permission, which is off by default.
type CommentsClient struct {
	app   *AppAuthenticator
	locks keyedMutex
}

// NewCommentsClient returns a client that comments as the given GitHub App.
func NewCommentsClient(app *AppAuthenticator) (*CommentsClient, error) {
	if app == nil {
		return nil, errors.New("GitHub App authenticator is required")
	}
	return &CommentsClient{app: app}, nil
}

// Upsert shows the verdict on the pull request:
//   - the verdict is edited in place, which is silent;
//   - when it gets WORSE than the previous one (for example SAFE to BLOCK) a new comment is posted
//     instead, because GitHub notifies people about new comments but not about edits;
//   - the App's older comments are deleted, so at most one remains and any earlier duplicates heal;
//   - nothing is written if the pull request head is no longer update.HeadSHA.
//
// Calls for the same pull request are serialized within this process. Several DeployGuard
// instances can still race and briefly leave two comments; the next update removes the extra one.
// Comments by anyone else are never touched, even if they contain the marker.
func (c *CommentsClient) Upsert(ctx context.Context, installationID, repositoryID int64, repositoryFullName string, pullRequest int, update CommentUpdate) error {
	repositoryPath := pathRepository(repositoryFullName)
	if repositoryPath == "" || strings.ContainsAny(repositoryFullName, "?#\\") {
		return errors.New("invalid repository name")
	}
	if pullRequest <= 0 {
		return errors.New("invalid pull request number")
	}
	if !commitSHAPattern.MatchString(update.HeadSHA) {
		return errors.New("invalid commit SHA")
	}
	switch update.Recommendation {
	case "", "SAFE", "REVIEW", "BLOCK":
	default:
		return errors.New("invalid recommendation")
	}
	unlock := c.locks.acquire(fmt.Sprintf("%d/%d", repositoryID, pullRequest))
	defer unlock()

	token, err := c.app.InstallationTokenForRepository(ctx, installationID, repositoryID)
	if err != nil {
		return errors.New("authenticate GitHub comment request")
	}
	if err := c.requireCurrentHead(ctx, token.Token, repositoryPath, pullRequest, update.HeadSHA); err != nil {
		return err
	}
	own, err := c.ownComments(ctx, token.Token, repositoryPath, pullRequest)
	if err != nil {
		return err
	}
	body := CommentMarker + "\n" + stateLine(update) + "\n" + truncateBytes(update.Body, maxCommentBytes)

	var keep int64 // the comment that survives; every other own comment is deleted
	if len(own) > 0 && !worsened(previousRecommendation(own[len(own)-1].Body), update.Recommendation) {
		keep = own[len(own)-1].ID
		if err := c.writeComment(ctx, token.Token, http.MethodPatch, fmt.Sprintf("/repos/%s/issues/comments/%d", repositoryPath, keep), body, http.StatusOK); err != nil {
			return err
		}
	} else if err := c.writeComment(ctx, token.Token, http.MethodPost, fmt.Sprintf("/repos/%s/issues/%d/comments", repositoryPath, pullRequest), body, http.StatusCreated); err != nil {
		return err
	}
	for _, comment := range own {
		if comment.ID != keep {
			// Best effort: a failed delete only leaves a duplicate that the next update removes.
			c.deleteComment(ctx, token.Token, repositoryPath, comment.ID)
		}
	}
	return nil
}

func stateLine(update CommentUpdate) string {
	recommendation := update.Recommendation
	if recommendation == "" {
		recommendation = "NONE"
	}
	return fmt.Sprintf("%srecommendation=%s sha=%s -->", stateLinePrefix, recommendation, strings.ToLower(update.HeadSHA))
}

var stateLinePattern = regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(stateLinePrefix) + `recommendation=(SAFE|REVIEW|BLOCK|NONE) sha=[0-9a-f]+ -->$`)

// previousRecommendation reads the state line a previous update wrote ("" when absent or NONE).
func previousRecommendation(body string) string {
	match := stateLinePattern.FindStringSubmatch(body)
	if match == nil || match[1] == "NONE" {
		return ""
	}
	return match[1]
}

func recommendationRank(recommendation string) int {
	switch recommendation {
	case "BLOCK":
		return 2
	case "REVIEW":
		return 1
	}
	return 0 // SAFE, or no verdict
}

func worsened(previous, next string) bool {
	return recommendationRank(next) > recommendationRank(previous)
}

// requireCurrentHead refuses to write when the pull request's head is not headSHA.
func (c *CommentsClient) requireCurrentHead(ctx context.Context, token, repositoryPath string, pullRequest int, headSHA string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.app.apiURL(fmt.Sprintf("/repos/%s/pulls/%d", repositoryPath, pullRequest)), nil)
	if err != nil {
		return errors.New("create pull request lookup request")
	}
	setGitHubHeaders(request, token)
	response, err := c.app.httpClient.Do(request)
	if err != nil {
		return errors.New("look up the pull request")
	}
	var pull struct {
		Head struct {
			SHA string `json:"sha"`
		} `json:"head"`
	}
	if err := decodeGitHubResponse(response, http.StatusOK, &pull); err != nil || pull.Head.SHA == "" {
		return errors.New("look up the pull request")
	}
	if !strings.EqualFold(pull.Head.SHA, headSHA) {
		return ErrStaleHead
	}
	return nil
}

type ownComment struct {
	ID   int64
	Body string
}

// commentPage is one page of a pull request's comments.
type commentPage struct {
	comments []ownCandidate
	last     int // number of the last page, from the Link header (1 when there is no Link)
}

type ownCandidate struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
	App  *struct {
		ID int64 `json:"id"`
	} `json:"performed_via_github_app"`
	User *struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"user"`
}

// maxCommentListBytes bounds one page of comments. The default 2 MiB limit is too small: GitHub
// allows 64 KB comments, so 100 of them make a page over 6 MiB.
const maxCommentListBytes = 16 << 20

func (c *CommentsClient) listPage(ctx context.Context, token, repositoryPath string, pullRequest, page int) (commentPage, error) {
	endpoint := c.app.apiURL(fmt.Sprintf("/repos/%s/issues/%d/comments?per_page=100&page=%d", repositoryPath, pullRequest, page))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return commentPage{}, errors.New("create comment lookup request")
	}
	setGitHubHeaders(request, token)
	response, err := c.app.httpClient.Do(request)
	if err != nil {
		return commentPage{}, errors.New("look up GitHub comments")
	}
	result := commentPage{last: lastPageNumber(responseHeaderLink(response))}
	if err := decodeGitHubResponseWithin(response, http.StatusOK, maxCommentListBytes, &result.comments); err != nil {
		return commentPage{}, errors.New("look up GitHub comments")
	}
	return result, nil
}

var lastPagePattern = regexp.MustCompile(`<[^>]*[?&]page=(\d+)[^>]*>;\s*rel="last"`)

// lastPageNumber reads the last page number from a Link header (1 when there is none).
func lastPageNumber(link string) int {
	if match := lastPagePattern.FindStringSubmatch(link); match != nil {
		if n, err := strconv.Atoi(match[1]); err == nil && n > 1 {
			return n
		}
	}
	return 1
}

// pagesToScan lists the pages after page 1 to read. A short thread is read whole. In a very long one
// (more than maxCommentPages pages) only the oldest and the newest few pages are read, which is where
// this App's comment is: it is created early, and re-created at the end when a verdict worsens. A
// comment buried in the middle of a thread that long is not found, and a new one is posted.
func pagesToScan(last int) []int {
	var pages []int
	edge := maxCommentPages / 2
	for page := 2; page <= last; page++ {
		if last <= maxCommentPages || page <= edge || page > last-edge {
			pages = append(pages, page)
		}
	}
	return pages
}

// ownComments returns every comment this App wrote (oldest first). A comment is ours when it starts
// with the marker AND was authored by this App: GitHub reports the App on the comment, and the
// author is the bot user "<slug>[bot]". Either proves it, so a missing field cannot hide our comment.
func (c *CommentsClient) ownComments(ctx context.Context, token, repositoryPath string, pullRequest int) ([]ownComment, error) {
	botLogin := ""
	if slug, err := c.app.Slug(ctx); err == nil {
		botLogin = slug + "[bot]"
	}
	first, err := c.listPage(ctx, token, repositoryPath, pullRequest, 1)
	if err != nil {
		return nil, err
	}
	pages := []commentPage{first}
	for _, number := range pagesToScan(first.last) {
		page, err := c.listPage(ctx, token, repositoryPath, pullRequest, number)
		if err != nil {
			return nil, err
		}
		pages = append(pages, page)
	}
	var own []ownComment
	for _, page := range pages {
		for _, comment := range page.comments {
			byApp := comment.App != nil && comment.App.ID == c.app.appID
			byBot := botLogin != "" && comment.User != nil && comment.User.Type == "Bot" && strings.EqualFold(comment.User.Login, botLogin)
			if (byApp || byBot) && strings.HasPrefix(comment.Body, CommentMarker) {
				own = append(own, ownComment{ID: comment.ID, Body: comment.Body})
			}
		}
	}
	return own, nil
}

func (c *CommentsClient) writeComment(ctx context.Context, token, method, path, body string, want int) error {
	encoded, err := json.Marshal(map[string]string{"body": body})
	if err != nil {
		return errors.New("encode comment")
	}
	request, err := http.NewRequestWithContext(ctx, method, c.app.apiURL(path), bytes.NewReader(encoded))
	if err != nil {
		return errors.New("create comment request")
	}
	setGitHubHeaders(request, token)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.app.httpClient.Do(request)
	if err != nil {
		return errors.New("publish GitHub comment")
	}
	defer response.Body.Close()
	switch {
	case response.StatusCode == want:
		return nil
	case response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusNotFound:
		// 404 is what GitHub returns for a repository the token cannot write to.
		return fmt.Errorf("%w (status %d)", ErrCommentPermission, response.StatusCode)
	}
	return fmt.Errorf("publish GitHub comment: unexpected status %d", response.StatusCode)
}

func (c *CommentsClient) deleteComment(ctx context.Context, token, repositoryPath string, id int64) {
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.app.apiURL(fmt.Sprintf("/repos/%s/issues/comments/%d", repositoryPath, id)), nil)
	if err != nil {
		return
	}
	setGitHubHeaders(request, token)
	if response, err := c.app.httpClient.Do(request); err == nil {
		response.Body.Close()
	}
}

// keyedMutex serializes work per key and forgets a key when nobody holds or waits for it.
type keyedMutex struct {
	mu      sync.Mutex
	entries map[string]*keyedEntry
}

type keyedEntry struct {
	lock sync.Mutex
	refs int
}

func (k *keyedMutex) acquire(key string) (release func()) {
	k.mu.Lock()
	if k.entries == nil {
		k.entries = map[string]*keyedEntry{}
	}
	entry := k.entries[key]
	if entry == nil {
		entry = &keyedEntry{}
		k.entries[key] = entry
	}
	entry.refs++
	k.mu.Unlock()
	entry.lock.Lock()
	return func() {
		entry.lock.Unlock()
		k.mu.Lock()
		if entry.refs--; entry.refs == 0 {
			delete(k.entries, key)
		}
		k.mu.Unlock()
	}
}

func setGitHubHeaders(request *http.Request, token string) {
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+token)
}
