package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ownerApp matches the App ID used by newChecksTestClient (101); its slug below makes the bot
// user "dg-app[bot]".
const (
	ownerApp = 101
	ownerBot = "dg-app[bot]"
)

type fakeComment struct {
	id      int64
	body    string
	appID   int64 // 0 means performed_via_github_app is null
	login   string
	isBot   bool
	deleted bool
}

// fakeThread is a small stateful GitHub: one PR's comments, its head, and a count of writes.
type fakeThread struct {
	mu       sync.Mutex
	comments []*fakeComment
	nextID   int64
	head     string
	slugFail bool
	delFail  bool
	nullApp  bool // comments POSTed by the App come back with performed_via_github_app null
	posts    int
	patches  int
	deletes  int
}

func newThread() *fakeThread { return &fakeThread{head: "abc1234", nextID: 100} }

func (f *fakeThread) add(c fakeComment) *fakeComment {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	c.id = f.nextID
	f.comments = append(f.comments, &c)
	return f.comments[len(f.comments)-1]
}

func (f *fakeThread) live() []*fakeComment {
	var out []*fakeComment
	for _, c := range f.comments {
		if !c.deleted {
			out = append(out, c)
		}
	}
	return out
}

func (f *fakeThread) handle(t *testing.T) func(*http.Request, string) *http.Response {
	return func(r *http.Request, body string) *http.Response {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/app":
			if f.slugFail {
				return response(http.StatusNotFound, `{}`)
			}
			return response(http.StatusOK, fmt.Sprintf(`{"id":%d,"slug":"dg-app"}`, ownerApp))
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/app/pulls/7":
			return response(http.StatusOK, fmt.Sprintf(`{"head":{"sha":%q}}`, f.head))
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/app/issues/7/comments":
			page, _ := strconv.Atoi(r.URL.Query().Get("page"))
			if page < 1 {
				page = 1
			}
			// Simulate network latency while NOT holding the lock, so two concurrent callers can
			// both list before either posts. Without per-PR serialization that creates duplicates.
			f.mu.Unlock()
			time.Sleep(15 * time.Millisecond)
			f.mu.Lock()
			live := f.live()
			from, to := (page-1)*100, page*100
			if from > len(live) {
				from = len(live)
			}
			if to > len(live) {
				to = len(live)
			}
			var items []string
			for _, c := range live[from:to] {
				app := "null"
				if c.appID != 0 {
					app = fmt.Sprintf(`{"id":%d}`, c.appID)
				}
				typ := "User"
				if c.isBot {
					typ = "Bot"
				}
				items = append(items, fmt.Sprintf(`{"id":%d,"body":%s,"performed_via_github_app":%s,"user":{"login":%q,"type":%q}}`, c.id, mustJSON(c.body), app, c.login, typ))
			}
			resp := response(http.StatusOK, "["+strings.Join(items, ",")+"]")
			if lastPage := (len(live) + 99) / 100; lastPage > 1 {
				resp.Header.Set("Link", fmt.Sprintf(`<https://api.github.test/repos/acme/app/issues/7/comments?per_page=100&page=%d>; rel="last"`, lastPage))
			}
			return resp
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/app/issues/7/comments":
			f.posts++
			f.nextID++
			c := &fakeComment{id: f.nextID, body: decodeBody(t, body), appID: ownerApp, login: ownerBot, isBot: true}
			if f.nullApp {
				c.appID = 0
			}
			f.comments = append(f.comments, c)
			return response(http.StatusCreated, `{}`)
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/repos/acme/app/issues/comments/"):
			id, _ := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/repos/acme/app/issues/comments/"), 10, 64)
			for _, c := range f.live() {
				if c.id == id {
					f.patches++
					c.body = decodeBody(t, body)
					return response(http.StatusOK, `{}`)
				}
			}
			return response(http.StatusNotFound, `{}`)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/repos/acme/app/issues/comments/"):
			if f.delFail {
				return response(http.StatusInternalServerError, `{}`)
			}
			id, _ := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/repos/acme/app/issues/comments/"), 10, 64)
			for _, c := range f.live() {
				if c.id == id {
					f.deletes++
					c.deleted = true
					return response(http.StatusNoContent, ``)
				}
			}
			return response(http.StatusNotFound, `{}`)
		}
		t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		return response(http.StatusNotFound, `{}`)
	}
}

func mustJSON(value string) string { b, _ := json.Marshal(value); return string(b) }

func decodeBody(t *testing.T, raw string) string {
	var sent struct{ Body string }
	if err := json.Unmarshal([]byte(raw), &sent); err != nil {
		t.Errorf("bad request body %q: %v", raw, err)
	}
	return sent.Body
}

func commentsFixture(t *testing.T, thread *fakeThread) *CommentsClient {
	t.Helper()
	checks := newChecksTestClient(t, thread.handle(t)) // shares the fake token endpoint and App 101
	client, err := NewCommentsClient(checks.app)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func ownBody(recommendation, sha, text string) string {
	return CommentMarker + "\n" + stateLine(CommentUpdate{HeadSHA: sha, Recommendation: recommendation}) + "\n" + text
}

func upsert(client *CommentsClient, recommendation, text string) error {
	return client.Upsert(context.Background(), 42, 7, "acme/app", 7, CommentUpdate{Body: text, HeadSHA: "abc1234", Recommendation: recommendation})
}

func TestUpsertCreatesTheCommentWithMarkerAndStateWhenNoneExists(t *testing.T) {
	thread := newThread()
	thread.add(fakeComment{body: "human talk", login: "someone"})
	client := commentsFixture(t, thread)
	if err := upsert(client, "BLOCK", "verdict text"); err != nil {
		t.Fatal(err)
	}
	live := thread.live()
	if thread.posts != 1 || thread.deletes != 0 || len(live) != 2 {
		t.Fatalf("posts %d deletes %d comments %d", thread.posts, thread.deletes, len(live))
	}
	body := live[1].body
	if !strings.HasPrefix(body, CommentMarker+"\n") || !strings.Contains(body, "recommendation=BLOCK sha=abc1234 -->") || !strings.Contains(body, "verdict text") {
		t.Fatalf("created body %q", body)
	}
}

func TestSameOrBetterVerdictEditsInPlaceWithoutANewComment(t *testing.T) {
	for _, tc := range []struct{ previous, next string }{{"BLOCK", "BLOCK"}, {"BLOCK", "REVIEW"}, {"BLOCK", "SAFE"}, {"REVIEW", "SAFE"}, {"SAFE", "SAFE"}, {"BLOCK", ""}} {
		thread := newThread()
		old := thread.add(fakeComment{body: ownBody(tc.previous, "0000000", "old"), appID: ownerApp, login: ownerBot, isBot: true})
		if err := upsert(commentsFixture(t, thread), tc.next, "new"); err != nil {
			t.Fatal(err)
		}
		if thread.posts != 0 || thread.patches != 1 || thread.deletes != 0 || len(thread.live()) != 1 || !strings.Contains(old.body, "new") {
			t.Errorf("%s->%q: posts %d patches %d deletes %d", tc.previous, tc.next, thread.posts, thread.patches, thread.deletes)
		}
	}
}

func TestWorseningVerdictPostsANewCommentSoPeopleAreNotified(t *testing.T) {
	for _, tc := range []struct{ previous, next string }{{"SAFE", "BLOCK"}, {"SAFE", "REVIEW"}, {"REVIEW", "BLOCK"}, {"NONE", "BLOCK"}, {"NONE", "REVIEW"}} {
		thread := newThread()
		thread.add(fakeComment{body: ownBody(tc.previous, "0000000", "old"), appID: ownerApp, login: ownerBot, isBot: true})
		if err := upsert(commentsFixture(t, thread), tc.next, "new"); err != nil {
			t.Fatal(err)
		}
		live := thread.live()
		if thread.posts != 1 || thread.patches != 0 || thread.deletes != 1 || len(live) != 1 || !strings.Contains(live[0].body, "new") {
			t.Errorf("%s->%s: posts %d patches %d deletes %d comments %d; want a new comment replacing the old one", tc.previous, tc.next, thread.posts, thread.patches, thread.deletes, len(live))
		}
	}
}

func TestEarlierDuplicatesAreHealed(t *testing.T) {
	thread := newThread()
	for i := 0; i < 3; i++ {
		thread.add(fakeComment{body: ownBody("BLOCK", "0000000", fmt.Sprintf("dup %d", i)), appID: ownerApp, login: ownerBot, isBot: true})
	}
	human := thread.add(fakeComment{body: "keep me", login: "someone"})
	if err := upsert(commentsFixture(t, thread), "BLOCK", "latest"); err != nil {
		t.Fatal(err)
	}
	live := thread.live()
	if len(live) != 2 || thread.deletes != 2 || thread.patches != 1 || live[len(live)-1] == human && live[0] == human {
		t.Fatalf("comments %d deletes %d patches %d; want one DeployGuard comment plus the human's", len(live), thread.deletes, thread.patches)
	}
	if human.deleted {
		t.Fatal("a human's comment must never be deleted")
	}
}

func TestOnlyOwnCommentsAreTouchedEvenWithTheMarker(t *testing.T) {
	thread := newThread()
	human := thread.add(fakeComment{body: ownBody("BLOCK", "0000000", "imposter"), login: "someone"})
	otherApp := thread.add(fakeComment{body: ownBody("BLOCK", "0000000", "other app"), appID: 999, login: "other[bot]", isBot: true})
	otherBotNoApp := thread.add(fakeComment{body: ownBody("BLOCK", "0000000", "other bot"), login: "other[bot]", isBot: true})
	humanNamedLikeBot := thread.add(fakeComment{body: ownBody("BLOCK", "0000000", "lookalike"), login: ownerBot}) // a User, not a Bot
	if err := upsert(commentsFixture(t, thread), "BLOCK", "mine"); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]*fakeComment{"human": human, "other app": otherApp, "other bot": otherBotNoApp, "lookalike user": humanNamedLikeBot} {
		if c.deleted || strings.Contains(c.body, "mine") {
			t.Errorf("%s comment was touched", name)
		}
	}
	if thread.posts != 1 {
		t.Errorf("a new own comment should be created, posts = %d", thread.posts)
	}
}

func TestOwnCommentIsFoundByBotLoginWhenTheAppFieldIsMissing(t *testing.T) {
	thread := newThread()
	thread.nullApp = true // GitHub reports performed_via_github_app as null
	client := commentsFixture(t, thread)
	for i := 0; i < 3; i++ {
		if err := upsert(client, "BLOCK", fmt.Sprintf("run %d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if thread.posts != 1 || thread.patches != 2 || len(thread.live()) != 1 {
		t.Fatalf("posts %d patches %d comments %d; a null app field must not cause a new comment on every run", thread.posts, thread.patches, len(thread.live()))
	}
}

func TestOwnCommentIsStillFoundByAppIDWhenTheSlugLookupFails(t *testing.T) {
	thread := newThread()
	thread.slugFail = true
	thread.add(fakeComment{body: ownBody("BLOCK", "0000000", "old"), appID: ownerApp, login: ownerBot, isBot: true})
	if err := upsert(commentsFixture(t, thread), "BLOCK", "new"); err != nil {
		t.Fatal(err)
	}
	if thread.posts != 0 || thread.patches != 1 {
		t.Fatalf("posts %d patches %d", thread.posts, thread.patches)
	}
}

func TestStaleHeadWritesNothing(t *testing.T) {
	thread := newThread()
	thread.head = "def5678" // the PR moved on
	thread.add(fakeComment{body: ownBody("SAFE", "def5678", "newer verdict"), appID: ownerApp, login: ownerBot, isBot: true})
	err := upsert(commentsFixture(t, thread), "BLOCK", "older verdict")
	if !errors.Is(err, ErrStaleHead) {
		t.Fatalf("err = %v, want ErrStaleHead", err)
	}
	if thread.posts+thread.patches+thread.deletes != 0 || !strings.Contains(thread.live()[0].body, "newer verdict") {
		t.Fatal("a stale analysis must not change the comment")
	}
}

func TestConcurrentUpdatesForOnePullRequestLeaveOneComment(t *testing.T) {
	thread := newThread()
	client := commentsFixture(t, thread)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := upsert(client, "BLOCK", fmt.Sprintf("run %d", i)); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if thread.posts != 1 || len(thread.live()) != 1 {
		t.Fatalf("posts %d comments %d; concurrent runs must not create duplicates", thread.posts, len(thread.live()))
	}
	if len(client.locks.entries) != 0 {
		t.Errorf("lock table leaked %d entries", len(client.locks.entries))
	}
}

func TestFailedDeleteDoesNotFailTheUpdate(t *testing.T) {
	thread := newThread()
	thread.delFail = true
	thread.add(fakeComment{body: ownBody("SAFE", "0000000", "old"), appID: ownerApp, login: ownerBot, isBot: true})
	if err := upsert(commentsFixture(t, thread), "BLOCK", "new"); err != nil {
		t.Fatalf("the new comment was posted, so the update succeeded: %v", err)
	}
	if thread.posts != 1 || len(thread.live()) != 2 {
		t.Fatalf("posts %d comments %d; the old comment stays until the next run heals it", thread.posts, len(thread.live()))
	}
}

func TestUpsertFindsItsCommentOnALaterPage(t *testing.T) {
	thread := newThread()
	for i := 0; i < 100; i++ {
		thread.add(fakeComment{body: "filler", login: "someone"})
	}
	mine := thread.add(fakeComment{body: ownBody("BLOCK", "0000000", "old"), appID: ownerApp, login: ownerBot, isBot: true})
	if err := upsert(commentsFixture(t, thread), "BLOCK", "new"); err != nil {
		t.Fatal(err)
	}
	if thread.posts != 0 || thread.patches != 1 || !strings.Contains(mine.body, "new") {
		t.Fatalf("posts %d patches %d", thread.posts, thread.patches)
	}
}

func TestUpsertCapsTheCommentSizeAndRejectsBadInput(t *testing.T) {
	thread := newThread()
	client := commentsFixture(t, thread)
	if err := upsert(client, "BLOCK", strings.Repeat("é", 100000)); err != nil {
		t.Fatal(err)
	}
	if n := len(thread.live()[0].body); n > 65536 {
		t.Fatalf("comment body is %d bytes, GitHub's limit is 65536", n)
	}
	update := CommentUpdate{Body: "v", HeadSHA: "abc1234", Recommendation: "BLOCK"}
	for name, call := range map[string]func() error{
		"bad repo":      func() error { return client.Upsert(context.Background(), 42, 7, "nope", 7, update) },
		"query in repo": func() error { return client.Upsert(context.Background(), 42, 7, "acme/app?x", 7, update) },
		"pr zero":       func() error { return client.Upsert(context.Background(), 42, 7, "acme/app", 0, update) },
		"bad sha": func() error {
			u := update
			u.HeadSHA = "../x"
			return client.Upsert(context.Background(), 42, 7, "acme/app", 7, u)
		},
		"bad verdict": func() error {
			u := update
			u.Recommendation = "MAYBE"
			return client.Upsert(context.Background(), 42, 7, "acme/app", 7, u)
		},
	} {
		if err := call(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestStateLineRoundTripAndRanking(t *testing.T) {
	for _, recommendation := range []string{"SAFE", "REVIEW", "BLOCK", ""} {
		line := stateLine(CommentUpdate{HeadSHA: "ABC1234", Recommendation: recommendation})
		if got := previousRecommendation("x\n" + line + "\ny"); got != recommendation {
			t.Errorf("round trip of %q gave %q (%s)", recommendation, got, line)
		}
	}
	if previousRecommendation("no state here") != "" || previousRecommendation(CommentMarker+"\n<!-- deployguard:state recommendation=EVIL sha=abc -->") != "" {
		t.Error("a missing or malformed state line means no previous verdict")
	}
	if !worsened("SAFE", "BLOCK") || !worsened("", "REVIEW") || worsened("BLOCK", "BLOCK") || worsened("BLOCK", "SAFE") || worsened("SAFE", "") {
		t.Error("ranking is wrong")
	}
}

func TestPermissionRefusalIsATypedError(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound} {
		thread := newThread()
		checks := newChecksTestClient(t, func(r *http.Request, body string) *http.Response {
			if r.Method == http.MethodPost {
				return response(status, `{}`)
			}
			return thread.handle(t)(r, body)
		})
		client, _ := NewCommentsClient(checks.app)
		err := upsert(client, "BLOCK", "v")
		if !errors.Is(err, ErrCommentPermission) || !strings.Contains(err.Error(), "Pull requests: write") {
			t.Errorf("status %d: err = %v", status, err)
		}
	}
}

func TestAppPermissionsAreReadFromGitHub(t *testing.T) {
	checks := newChecksTestClient(t, func(r *http.Request, _ string) *http.Response {
		if r.URL.Path == "/app" {
			return response(http.StatusOK, fmt.Sprintf(`{"id":%d,"slug":"dg-app","permissions":{"checks":"write","pull_requests":"read"}}`, ownerApp))
		}
		return response(http.StatusNotFound, `{}`)
	})
	got, err := checks.app.Permissions(context.Background())
	if err != nil || got["checks"] != "write" || got["pull_requests"] != "read" {
		t.Fatalf("got %v, %v", got, err)
	}
	wrongApp := newChecksTestClient(t, func(*http.Request, string) *http.Response {
		return response(http.StatusOK, `{"id":999,"slug":"someone-else","permissions":{}}`)
	})
	if _, err := wrongApp.app.Permissions(context.Background()); err == nil {
		t.Error("a response describing a different App must be rejected")
	}
}

func TestOwnCommentIsFoundAtBothEndsOfAVeryLongThread(t *testing.T) {
	// 1200 comments = 12 pages: pages 1-5 and 8-12 are read; 6-7 are not (documented limit).
	for name, tc := range map[string]struct {
		ownAt     int
		wantFound bool
	}{
		"oldest page":      {3, true},
		"page 5":           {450, true},
		"newest page":      {1190, true},
		"page 8":           {750, true},
		"unscanned middle": {600, false}, // page 7
	} {
		thread := newThread()
		var mine *fakeComment
		for i := 0; i < 1200; i++ {
			if i == tc.ownAt {
				mine = thread.add(fakeComment{body: ownBody("BLOCK", "0000000", "old"), appID: ownerApp, login: ownerBot, isBot: true})
				continue
			}
			thread.add(fakeComment{body: "filler", login: "someone"})
		}
		if err := upsert(commentsFixture(t, thread), "BLOCK", "new"); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if tc.wantFound && (thread.posts != 0 || !strings.Contains(mine.body, "new")) {
			t.Errorf("%s: posts %d; the existing comment should have been found and edited", name, thread.posts)
		}
		if !tc.wantFound && thread.posts != 1 {
			t.Errorf("%s: posts %d; a comment in the unscanned middle is not found and a new one is posted", name, thread.posts)
		}
	}
}

func TestPagesToScan(t *testing.T) {
	for last, want := range map[int][]int{1: nil, 2: {2}, 10: {2, 3, 4, 5, 6, 7, 8, 9, 10}, 12: {2, 3, 4, 5, 8, 9, 10, 11, 12}, 40: {2, 3, 4, 5, 36, 37, 38, 39, 40}} {
		got := pagesToScan(last)
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("pagesToScan(%d) = %v, want %v", last, got, want)
		}
	}
	if lastPageNumber(`<https://x/y?per_page=100&page=2>; rel="next", <https://x/y?per_page=100&page=7>; rel="last"`) != 7 || lastPageNumber("") != 1 || lastPageNumber(`<https://x/y?page=2>; rel="next"`) != 1 {
		t.Error("Link header parsing is wrong")
	}
}

func TestLargeCommentPagesAreReadWithoutTruncation(t *testing.T) {
	// 100 comments of 30 KB make a page of about 3 MB, over the 2 MiB default limit that broke the lookup.
	thread := newThread()
	big := strings.Repeat("x", 30000)
	for i := 0; i < 99; i++ {
		thread.add(fakeComment{body: big, login: "someone"})
	}
	mine := thread.add(fakeComment{body: ownBody("BLOCK", "0000000", "old"), appID: ownerApp, login: ownerBot, isBot: true})
	if err := upsert(commentsFixture(t, thread), "BLOCK", "new"); err != nil {
		t.Fatalf("a large page must be readable: %v", err)
	}
	if thread.posts != 0 || !strings.Contains(mine.body, "new") {
		t.Fatalf("posts %d; the comment on a large page should have been found and edited", thread.posts)
	}
}

func TestAbsurdlyLargePagesFailLoudlyInsteadOfParsingATruncatedBody(t *testing.T) {
	thread := newThread()
	huge := strings.Repeat("y", 180000)
	for i := 0; i < 100; i++ { // about 18 MB, over the 16 MiB cap
		thread.add(fakeComment{body: huge, login: "someone"})
	}
	err := upsert(commentsFixture(t, thread), "BLOCK", "new")
	if err == nil || thread.posts != 0 {
		t.Fatalf("err = %v, posts = %d; an over-limit page must be an error and write nothing", err, thread.posts)
	}
}
