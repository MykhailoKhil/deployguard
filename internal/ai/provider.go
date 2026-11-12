package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Supported provider names for Config.Provider.
const (
	ProviderAnthropic = "anthropic"
	ProviderOpenAI    = "openai"
	ProviderGemini    = "gemini"
	ProviderMistral   = "mistral"
)

// defaultBaseURL is used when Config.BaseURL is empty. Setting BaseURL points the same adapter at
// a gateway or a compatible service (for example OpenRouter, Ollama, vLLM or OmniRoute).
var defaultBaseURL = map[string]string{
	ProviderAnthropic: "https://api.anthropic.com",
	ProviderOpenAI:    "https://api.openai.com",
	ProviderGemini:    "https://generativelanguage.googleapis.com",
	ProviderMistral:   "https://api.mistral.ai",
}

// maxOutputTokens caps the model's reply; the prompt itself asks for about 100 words.
const maxOutputTokens = 400

// Provider turns one system prompt and one user message into text. It knows nothing about
// Terraform: adapters only translate between this call and one vendor's HTTP API.
type Provider interface {
	Complete(ctx context.Context, system, user string) (string, error)
}

// Config selects and configures a provider. All fields come from the environment, never source.
type Config struct {
	Provider string // one of Providers(); empty means anthropic
	BaseURL  string // optional; defaults per provider
	APIKey   string
	Model    string
}

// Providers lists the supported provider names, sorted.
func Providers() []string {
	names := make([]string, 0, len(defaultBaseURL))
	for name := range defaultBaseURL {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// NewProvider validates the configuration and returns the matching adapter. The API key is only
// ever sent over HTTPS, or to a loopback host.
func NewProvider(cfg Config) (Provider, error) {
	name := strings.ToLower(strings.TrimSpace(cfg.Provider))
	if name == "" {
		name = ProviderAnthropic
	}
	fallback, known := defaultBaseURL[name]
	if !known {
		return nil, fmt.Errorf("unknown AI provider %q; choose one of: %s", cfg.Provider, strings.Join(Providers(), ", "))
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = fallback
	}
	base, err := validateBase(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	if cfg.APIKey == "" || cfg.Model == "" {
		return nil, errors.New("AI API key and model are required")
	}
	api := apiClient{base: strings.TrimRight(base.String(), "/"), key: cfg.APIKey, model: cfg.Model, client: newHTTPClient()}
	switch name {
	case ProviderOpenAI:
		// OpenAI's own API prefers max_completion_tokens; compatible servers expect max_tokens.
		tokenField := "max_tokens"
		if base.Hostname() == "api.openai.com" {
			tokenField = "max_completion_tokens"
		}
		return openAIProvider{api: api, tokenField: tokenField}, nil
	case ProviderMistral:
		return openAIProvider{api: api, tokenField: "max_tokens"}, nil
	case ProviderGemini:
		if !geminiModel.MatchString(cfg.Model) {
			return nil, errors.New("Gemini model names may only contain letters, digits, '.', '_' and '-'")
		}
		return geminiProvider{api: api}, nil
	default:
		return anthropicProvider{api: api}, nil
	}
}

func validateBase(raw string) (*url.URL, error) {
	base, err := url.Parse(raw)
	if err != nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("invalid AI base URL")
	}
	if base.Scheme != "https" && !(base.Scheme == "http" && isLoopback(base.Hostname())) {
		return nil, errors.New("AI base URL must use HTTPS unless it is a loopback address")
	}
	return base, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func newHTTPClient() *http.Client {
	return &http.Client{Timeout: requestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// apiClient is the plumbing every adapter shares.
type apiClient struct {
	base   string // base URL without a trailing slash
	key    string
	model  string
	client *http.Client
}

// postJSON sends body as JSON and returns the response body. Errors never include the key or the
// response content, so they are safe to log.
func (a apiClient) postJSON(ctx context.Context, path string, headers map[string]string, body any) ([]byte, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, errors.New("encode AI request")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, a.base+path, bytes.NewReader(encoded))
	if err != nil {
		return nil, errors.New("create AI request")
	}
	request.Header.Set("Content-Type", "application/json")
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := a.client.Do(request)
	if err != nil {
		return nil, errors.New("AI request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AI request returned status %d", response.StatusCode)
	}
	return io.ReadAll(io.LimitReader(response.Body, maxResponse))
}

var errEmptyReply = errors.New("AI reply had no text")

// anthropicProvider speaks the Anthropic Messages API (also served by OmniRoute and others).
type anthropicProvider struct{ api apiClient }

func (p anthropicProvider) Complete(ctx context.Context, system, user string) (string, error) {
	raw, err := p.api.postJSON(ctx, "/v1/messages", map[string]string{
		"Anthropic-Version": "2023-06-01",
		"X-Api-Key":         p.api.key,
		// Some Anthropic-compatible gateways authenticate with a bearer token instead.
		"Authorization": "Bearer " + p.api.key,
	}, map[string]any{
		"model": p.api.model, "max_tokens": maxOutputTokens, "system": system,
		"messages": []map[string]string{{"role": "user", "content": user}},
	})
	if err != nil {
		return "", err
	}
	var reply struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if json.Unmarshal(raw, &reply) != nil {
		return "", errors.New("decode AI reply")
	}
	for _, part := range reply.Content {
		if text := strings.TrimSpace(part.Text); part.Type == "text" && text != "" {
			return text, nil
		}
	}
	return "", errEmptyReply
}

// openAIProvider speaks the Chat Completions API, which OpenAI, Mistral and many gateways share.
type openAIProvider struct {
	api        apiClient
	tokenField string
}

func (p openAIProvider) Complete(ctx context.Context, system, user string) (string, error) {
	raw, err := p.api.postJSON(ctx, "/v1/chat/completions", map[string]string{
		"Authorization": "Bearer " + p.api.key,
	}, map[string]any{
		"model": p.api.model, p.tokenField: maxOutputTokens,
		"messages": []map[string]string{{"role": "system", "content": system}, {"role": "user", "content": user}},
	})
	if err != nil {
		return "", err
	}
	var reply struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if json.Unmarshal(raw, &reply) != nil {
		return "", errors.New("decode AI reply")
	}
	if len(reply.Choices) > 0 {
		if text := strings.TrimSpace(reply.Choices[0].Message.Content); text != "" {
			return text, nil
		}
	}
	return "", errEmptyReply
}

// geminiModel restricts the model name because it becomes part of the URL path.
var geminiModel = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// geminiProvider speaks Google's generateContent API. The key travels in a header, not the URL,
// so it cannot leak into access logs.
type geminiProvider struct{ api apiClient }

func (p geminiProvider) Complete(ctx context.Context, system, user string) (string, error) {
	raw, err := p.api.postJSON(ctx, "/v1beta/models/"+p.api.model+":generateContent", map[string]string{
		"X-Goog-Api-Key": p.api.key,
	}, map[string]any{
		"system_instruction": map[string]any{"parts": []map[string]string{{"text": system}}},
		"contents":           []map[string]any{{"role": "user", "parts": []map[string]string{{"text": user}}}},
		"generationConfig":   map[string]any{"maxOutputTokens": maxOutputTokens},
	})
	if err != nil {
		return "", err
	}
	var reply struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if json.Unmarshal(raw, &reply) != nil {
		return "", errors.New("decode AI reply")
	}
	if len(reply.Candidates) > 0 {
		var text strings.Builder
		for _, part := range reply.Candidates[0].Content.Parts {
			text.WriteString(part.Text)
		}
		if trimmed := strings.TrimSpace(text.String()); trimmed != "" {
			return trimmed, nil
		}
	}
	return "", errEmptyReply
}
