package web

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLocalHandler(t *testing.T) {
	handler := NewLocalHandler("127.0.0.1:8080", nil)
	t.Run("home", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/", nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Terraform") {
			t.Fatalf("home response = %d %s", response.Code, response.Body.String())
		}
		assertThemePage(t, response.Body.String())
		if policy := response.Header().Get("Content-Security-Policy"); !strings.Contains(policy, "script-src 'self'") || strings.Contains(policy, "'unsafe-inline'") {
			t.Fatalf("unexpected content security policy: %q", policy)
		}
	})
	for _, test := range []struct {
		name, content, origin, host string
		status                      int
	}{
		{"valid", `{"format_version":"1.2","resource_changes":[]}`, "http://127.0.0.1:8080", "127.0.0.1:8080", http.StatusOK},
		{"invalid", `not JSON`, "http://127.0.0.1:8080", "127.0.0.1:8080", http.StatusUnprocessableEntity},
		{"cross origin", `{}`, "https://evil.example", "127.0.0.1:8080", http.StatusForbidden},
		{"no origin", `{}`, "", "127.0.0.1:8080", http.StatusForbidden},
		{"dns rebinding", `{}`, "http://evil.example:8080", "evil.example:8080", http.StatusForbidden},
		{"oversized", strings.Repeat("a", maxPlanBytes+1), "http://127.0.0.1:8080", "127.0.0.1:8080", http.StatusRequestEntityTooLarge},
	} {
		t.Run(test.name, func(t *testing.T) {
			var body bytes.Buffer
			form := multipart.NewWriter(&body)
			file, err := form.CreateFormFile("plan", "tfplan.json")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.Write([]byte(test.content)); err != nil {
				t.Fatal(err)
			}
			if err := form.Close(); err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/analyze", &body)
			request.Host = test.host
			request.Header.Set("Origin", test.origin)
			request.Header.Set("Content-Type", form.FormDataContentType())
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.status, response.Body.String())
			}
			if test.name == "valid" && !strings.Contains(response.Body.String(), "Recommendation") {
				t.Fatalf("analysis missing: %s", response.Body.String())
			}
			if test.name == "valid" {
				assertThemePage(t, response.Body.String())
			}
		})
	}
	t.Run("github unavailable", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/auth/github", nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("status = %d", response.Code)
		}
	})
}
