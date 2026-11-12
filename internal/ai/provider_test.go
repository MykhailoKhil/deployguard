package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// capture records the one request an adapter sends and replies with the given status and body.
type capture struct {
	method, path, rawQuery string
	header                 http.Header
	body                   map[string]any
}

func fakeAPI(t *testing.T, status int, reply string) (*httptest.Server, *capture) {
	t.Helper()
	got := &capture{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		got.method, got.path, got.rawQuery, got.header = r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone()
		_ = json.Unmarshal(raw, &got.body)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(server.Close)
	return server, got
}

func complete(t *testing.T, cfg Config) (string, error) {
	t.Helper()
	provider, err := NewProvider(cfg)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return provider.Complete(context.Background(), "SYSTEM TEXT", "USER TEXT")
}

func TestAnthropicAdapter(t *testing.T) {
	server, got := fakeAPI(t, 200, `{"content":[{"type":"thinking","text":""},{"type":"text","text":" hello "}]}`)
	text, err := complete(t, Config{BaseURL: server.URL, APIKey: "k", Model: "m"}) // empty provider = anthropic
	if err != nil || text != "hello" {
		t.Fatalf("text %q err %v", text, err)
	}
	if got.path != "/v1/messages" || got.header.Get("X-Api-Key") != "k" || got.header.Get("Anthropic-Version") == "" {
		t.Errorf("request %s headers %v", got.path, got.header)
	}
	if got.body["system"] != "SYSTEM TEXT" || got.body["model"] != "m" {
		t.Errorf("body %v", got.body)
	}
}

func TestOpenAIAdapterAndMistralShareTheChatCompletionsShape(t *testing.T) {
	for name, wantField := range map[string]string{ProviderOpenAI: "max_tokens", ProviderMistral: "max_tokens"} {
		server, got := fakeAPI(t, 200, `{"choices":[{"message":{"content":" reply "}}]}`)
		text, err := complete(t, Config{Provider: name, BaseURL: server.URL, APIKey: "k", Model: "m"})
		if err != nil || text != "reply" {
			t.Fatalf("%s: text %q err %v", name, text, err)
		}
		if got.path != "/v1/chat/completions" || got.header.Get("Authorization") != "Bearer k" {
			t.Errorf("%s: request %s headers %v", name, got.path, got.header)
		}
		if _, ok := got.body[wantField]; !ok {
			t.Errorf("%s: body should use %s on a custom base URL: %v", name, wantField, got.body)
		}
		messages := got.body["messages"].([]any)
		if len(messages) != 2 || messages[0].(map[string]any)["role"] != "system" || messages[1].(map[string]any)["content"] != "USER TEXT" {
			t.Errorf("%s: messages %v", name, messages)
		}
	}
}

func TestOpenAIUsesMaxCompletionTokensOnlyOnItsOwnAPI(t *testing.T) {
	own, err := NewProvider(Config{Provider: ProviderOpenAI, APIKey: "k", Model: "m"}) // default base URL
	if err != nil {
		t.Fatal(err)
	}
	if own.(openAIProvider).tokenField != "max_completion_tokens" {
		t.Error("OpenAI's own API should use max_completion_tokens")
	}
	custom, _ := NewProvider(Config{Provider: ProviderOpenAI, BaseURL: "http://127.0.0.1:1", APIKey: "k", Model: "m"})
	if custom.(openAIProvider).tokenField != "max_tokens" {
		t.Error("a compatible server should get max_tokens")
	}
}

func TestGeminiAdapterKeepsTheKeyOutOfTheURL(t *testing.T) {
	server, got := fakeAPI(t, 200, `{"candidates":[{"content":{"parts":[{"text":"part one "},{"text":"and two"}]}}]}`)
	text, err := complete(t, Config{Provider: ProviderGemini, BaseURL: server.URL, APIKey: "secret-key", Model: "gemini-2.0-flash"})
	if err != nil || text != "part one and two" {
		t.Fatalf("text %q err %v", text, err)
	}
	if got.path != "/v1beta/models/gemini-2.0-flash:generateContent" || got.header.Get("X-Goog-Api-Key") != "secret-key" {
		t.Errorf("request %s headers %v", got.path, got.header)
	}
	if strings.Contains(got.rawQuery, "secret-key") || got.rawQuery != "" {
		t.Errorf("the key must not appear in the URL: %q", got.rawQuery)
	}
	if got.body["system_instruction"] == nil || got.body["contents"] == nil {
		t.Errorf("body %v", got.body)
	}
}

func TestAdaptersReturnErrorsInsteadOfPartialText(t *testing.T) {
	replies := map[string]string{
		ProviderAnthropic: `{"content":[{"type":"text","text":"  "}]}`,
		ProviderOpenAI:    `{"choices":[]}`,
		ProviderMistral:   `{"choices":[{"message":{"content":""}}]}`,
		ProviderGemini:    `{"candidates":[]}`,
	}
	for name, empty := range replies {
		for label, tc := range map[string]struct {
			status int
			body   string
		}{"empty": {200, empty}, "bad json": {200, "nope"}, "server error": {500, `{"error":"leaky detail"}`}} {
			server, _ := fakeAPI(t, tc.status, tc.body)
			text, err := complete(t, Config{Provider: name, BaseURL: server.URL, APIKey: "k", Model: "m"})
			if err == nil || text != "" {
				t.Errorf("%s/%s: text %q err %v, want an error", name, label, text, err)
			}
			if err != nil && strings.Contains(err.Error(), "leaky detail") {
				t.Errorf("%s/%s: error must not echo response content: %v", name, label, err)
			}
		}
	}
}

func TestNewProviderValidation(t *testing.T) {
	for name, cfg := range map[string]Config{
		"unknown provider":  {Provider: "skynet", APIKey: "k", Model: "m"},
		"missing key":       {Provider: ProviderOpenAI, Model: "m"},
		"missing model":     {Provider: ProviderOpenAI, APIKey: "k"},
		"plain http remote": {Provider: ProviderOpenAI, BaseURL: "http://example.com", APIKey: "k", Model: "m"},
		"userinfo in url":   {Provider: ProviderMistral, BaseURL: "https://u:p@example.com", APIKey: "k", Model: "m"},
		"bad gemini model":  {Provider: ProviderGemini, APIKey: "k", Model: "../x?y"},
	} {
		if _, err := NewProvider(cfg); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := NewProvider(Config{Provider: "skynet", APIKey: "k", Model: "m"}); err == nil || !strings.Contains(err.Error(), "anthropic, gemini, mistral, openai") {
		t.Errorf("unknown-provider error should list the choices: %v", err)
	}
	if _, err := NewProvider(Config{Provider: "  OpenAI ", APIKey: "k", Model: "m"}); err != nil {
		t.Errorf("provider names should be case-insensitive: %v", err)
	}
}

func TestEveryProviderHasADefaultHTTPSBaseURL(t *testing.T) {
	for _, name := range Providers() {
		if _, err := NewProvider(Config{Provider: name, APIKey: "k", Model: "m"}); err != nil {
			t.Errorf("%s with no base URL: %v", name, err)
		}
		if !strings.HasPrefix(defaultBaseURL[name], "https://") {
			t.Errorf("%s default base URL must be HTTPS: %q", name, defaultBaseURL[name])
		}
	}
}

func TestExplainerWorksWithAnyProvider(t *testing.T) {
	server, got := fakeAPI(t, 200, `{"choices":[{"message":{"content":"One sentence.\nNext step: Review."}}]}`)
	explainer, err := NewFromConfig(Config{Provider: ProviderOpenAI, BaseURL: server.URL, APIKey: "k", Model: "m"})
	if err != nil {
		t.Fatal(err)
	}
	text := explainer.Explain(context.Background(), sample())
	if text != "One sentence.\nNext step: Review." {
		t.Fatalf("text %q", text)
	}
	body, _ := json.Marshal(got.body)
	if !strings.Contains(string(body), "aws_db_instance.main") || strings.Contains(string(body), "SECRET-EVIDENCE") {
		t.Errorf("provider-agnostic prompt must carry findings and never evidence: %s", body)
	}
}
