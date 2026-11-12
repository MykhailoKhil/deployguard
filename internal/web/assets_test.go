package web

import (
	"bytes"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/deployguard/deployguard/assets"
	"github.com/deployguard/deployguard/internal/domain"
)

type modeUnderTest struct {
	name string
	base string
	h    http.Handler
}

func modes(t *testing.T) []modeUnderTest {
	t.Helper()
	return []modeUnderTest{
		{"local", "http://127.0.0.1:8080", NewLocalHandler("127.0.0.1:8080", nil)},
		{"github", "https://deployguard.example", newTestHandler(t, &testGitHub{}, &testAuthenticator{})},
	}
}

func get(h http.Handler, url string) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	h.ServeHTTP(response, httptest.NewRequest(http.MethodGet, url, nil))
	return response
}

func TestEveryBrandAssetIsServedInBothModes(t *testing.T) {
	for _, mode := range modes(t) {
		for name := range brandAssets {
			response := get(mode.h, mode.base+"/assets/brand/"+name)
			want, err := assets.Brand.ReadFile("brand/" + name)
			if err != nil {
				t.Fatal(err)
			}
			if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), want) {
				t.Errorf("%s %s: status %d, body matches embedded file: %v", mode.name, name, response.Code, bytes.Equal(response.Body.Bytes(), want))
			}
			if got := response.Header().Get("Content-Type"); got != "image/svg+xml" {
				t.Errorf("%s %s: content type %q", mode.name, name, got)
			}
			if got := response.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("%s %s: nosniff header %q", mode.name, name, got)
			}
			if !strings.HasPrefix(response.Body.String(), "<svg") {
				t.Errorf("%s %s: not an SVG document", mode.name, name)
			}
		}
	}
}

func TestOnlyTheListedBrandFilesAreServed(t *testing.T) {
	for _, mode := range modes(t) {
		for _, path := range []string{
			"/assets/brand/", "/assets/brand", "/assets/brand/README.md", "/assets/brand/missing.svg", "/assets/brand/MARK.SVG",
			"/assets/brand/../app.css", "/assets/brand/%2e%2e/app.css", "/assets/brand/..%2fapp.css", "/assets/brand/mark.svg/",
			"/assets/brand//mark.svg", "/assets/brand/mark.svg%00.png", "/assets/brand/./mark.svg",
		} {
			if response := get(mode.h, mode.base+path); response.Code != http.StatusNotFound {
				t.Errorf("%s %s: status %d, want 404 (only the four listed file names exist)", mode.name, path, response.Code)
			}
		}
		post := httptest.NewRecorder()
		mode.h.ServeHTTP(post, httptest.NewRequest(http.MethodPost, mode.base+"/assets/brand/mark.svg", nil))
		if post.Code == http.StatusOK {
			t.Errorf("%s: POST to an asset must not succeed", mode.name)
		}
	}
}

func TestFaviconRequestsAreRedirectedToTheMark(t *testing.T) {
	for _, mode := range modes(t) {
		response := get(mode.h, mode.base+"/favicon.ico")
		if response.Code != http.StatusFound || response.Header().Get("Location") != "/assets/brand/mark.svg" {
			t.Errorf("%s: status %d location %q; /favicon.ico must not be a 404", mode.name, response.Code, response.Header().Get("Location"))
		}
	}
}

func TestEmbeddedBrandFilesMatchTheAllowListAndAreSafe(t *testing.T) {
	entries, err := fs.ReadDir(assets.Brand, "brand")
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, entry := range entries {
		found[entry.Name()] = true
	}
	for name := range brandAssets {
		if !found[name] {
			t.Errorf("%s is allowed but not embedded", name)
		}
	}
	unsafe := regexp.MustCompile(`(?i)<script|\son[a-z]+\s*=|<foreignObject|href\s*=\s*"https?:|@import|data:text/html`)
	for name := range found {
		if !brandAssets[name] {
			t.Errorf("%s is embedded but not in the allow-list, so it would never be served", name)
		}
		content, _ := assets.Brand.ReadFile("brand/" + name)
		if loc := unsafe.FindString(string(content)); loc != "" {
			t.Errorf("%s contains %q: SVG files must carry no script, event handler or external reference", name, loc)
		}
	}
}

func TestContentSecurityPolicyAllowsOnlyOwnImages(t *testing.T) {
	for _, mode := range modes(t) {
		policy := get(mode.h, mode.base+"/assets/brand/mark.svg").Header().Get("Content-Security-Policy")
		for _, want := range []string{"img-src 'self'", "default-src 'none'", "script-src 'self'", "frame-ancestors 'none'"} {
			if !strings.Contains(policy, want) {
				t.Errorf("%s policy %q missing %q", mode.name, policy, want)
			}
		}
		if strings.Contains(policy, "data:") || strings.Contains(policy, "unsafe-inline") || strings.Contains(policy, "img-src *") || strings.Contains(policy, "https:") {
			t.Errorf("%s policy is too loose: %q", mode.name, policy)
		}
	}
}

// TestEverySiteReferenceResolves renders each page and requests every local asset it points at, so a
// renamed or missing file shows up as a failing test instead of a broken image in the browser.
func TestEverySiteReferenceResolves(t *testing.T) {
	handler := newTestHandler(t, &testGitHub{}, &testAuthenticator{})
	render := func(name string, data any) string {
		var buffer bytes.Buffer
		if err := handler.templates.ExecuteTemplate(&buffer, name, data); err != nil {
			t.Fatalf("render %s: %v", name, err)
		}
		return buffer.String()
	}
	analysis := &domain.Analysis{Recommendation: domain.RecommendationSafe, Level: domain.RiskLow, Explanation: "ok"}
	pages := map[string]string{
		"home":          render("home", pageData{User: "user"}),
		"pull-requests": render("pull-requests", pageData{User: "user"}),
		"result":        render("result", pageData{User: "user", Analysis: analysis}),
		"signed-out":    render("signed-out", pageData{}),
		"history":       render("history", pageData{User: "user", HistoryNote: "none yet"}),
		"error":         render("error", errorData{Status: 404, Message: "x", BackHref: "/", BackLabel: "Back", Mode: "GITHUB MODE"}),
	}
	pages["local home"] = get(NewLocalHandler("127.0.0.1:8080", nil), "http://127.0.0.1:8080/").Body.String()
	pages["local history"] = get(NewLocalHandler("127.0.0.1:8080", nil), "http://127.0.0.1:8080/history").Body.String()

	reference := regexp.MustCompile(`(?:src|href)="(/(?:assets|favicon)[^"]*)"`)
	local, remote := NewLocalHandler("127.0.0.1:8080", nil), handler
	checked := map[string]bool{}
	for page, html := range pages {
		refs := reference.FindAllStringSubmatch(html, -1)
		if len(refs) == 0 {
			t.Errorf("%s references no local assets at all", page)
		}
		for _, match := range refs {
			path := match[1]
			for name, target := range map[string]struct {
				h    http.Handler
				base string
			}{"local": {local, "http://127.0.0.1:8080"}, "github": {remote, "https://deployguard.example"}} {
				response := get(target.h, target.base+path)
				ok := response.Code == http.StatusOK
				if !ok {
					t.Errorf("%s page references %s, which returns %d in %s mode", page, path, response.Code, name)
				}
				checked[path] = true
			}
		}
	}
	for _, must := range []string{"/assets/app.css", "/assets/theme.js", "/assets/brand/mark.svg"} {
		if !checked[must] {
			t.Errorf("no page references %s", must)
		}
	}
	for page, html := range pages {
		if page == "local home" || page == "local history" || page == "history" || page == "home" || page == "pull-requests" || page == "result" || page == "signed-out" || page == "error" {
			if !strings.Contains(html, `rel="icon" type="image/svg+xml" href="/assets/brand/mark.svg"`) {
				t.Errorf("%s has no icon link", page)
			}
		}
	}
	if !strings.Contains(pages["home"], `<img class="brand-mark" src="/assets/brand/mark.svg"`) || !strings.Contains(pages["home"], `alt=""`) {
		t.Error("the header must show the brand mark as a decorative image next to the text name")
	}
}
