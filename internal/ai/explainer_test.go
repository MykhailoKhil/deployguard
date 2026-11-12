package ai

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deployguard/deployguard/internal/domain"
)

func sample() domain.Analysis {
	return domain.Analysis{Score: 80, Level: domain.RiskHigh, Recommendation: domain.RecommendationBlock,
		Findings: []domain.Finding{{RuleID: "replace", Severity: domain.SeverityHigh, Summary: "aws_db_instance.main is replaced", Remediation: "Review", Resources: []string{"aws_db_instance.main"},
			Evidence: []domain.Evidence{{Summary: "SECRET-EVIDENCE"}}}}}
}

func TestExplainSuccessSendsOnlyFindings(t *testing.T) {
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		if r.URL.Path != "/v1/messages" || r.Header.Get("X-Api-Key") != "k" {
			t.Errorf("bad request %s key=%q", r.URL.Path, r.Header.Get("X-Api-Key"))
		}
		w.Write([]byte(`{"content":[{"type":"thinking","text":""},{"type":"text","text":" Database replacement. "}]}`))
	}))
	defer server.Close()
	e, err := New(server.URL, "k", "m")
	if err != nil {
		t.Fatal(err)
	}
	if text := e.Explain(context.Background(), sample()); text != "Database replacement." {
		t.Fatalf("text = %q", text)
	}
	if !strings.Contains(got, "aws_db_instance.main") || strings.Contains(got, "SECRET-EVIDENCE") {
		t.Fatalf("request body leaks evidence or drops findings: %s", got)
	}
}

func TestExplainFailuresReturnEmpty(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"500": func(w http.ResponseWriter, r *http.Request) { http.Error(w, "x", 500) },
		"empty": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"content":[{"type":"text","text":"  "}]}`))
		},
		"json": func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`nope`)) },
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://127.0.0.1:1/", http.StatusFound)
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(handler)
			defer server.Close()
			e, _ := New(server.URL, "k", "m")
			if text := e.Explain(context.Background(), sample()); text != "" {
				t.Fatalf("text = %q, want empty", text)
			}
		})
	}
}

func TestExplainTimeoutReturnsEmpty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select { // bounded: an unread body means the server may never see the client hang up
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer server.Close()
	e, _ := New(server.URL, "k", "m")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if text := e.Explain(ctx, sample()); text != "" {
		t.Fatalf("text = %q", text)
	}
}

func TestDisabledMakesNoCalls(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer server.Close()
	var nilExplainer *Explainer
	if nilExplainer.Explain(context.Background(), sample()) != "" || calls.Load() != 0 {
		t.Fatal("nil explainer must be a no-op")
	}
	e, _ := New(server.URL, "k", "m")
	if e.Explain(context.Background(), domain.Analysis{}) != "" || calls.Load() != 0 {
		t.Fatal("no findings must not call the model")
	}
}

func TestNewValidation(t *testing.T) {
	for _, c := range [][3]string{
		{"http://example.com", "k", "m"}, {"https://example.com", "", "m"}, {"https://example.com", "k", ""},
		{"https://u:p@example.com", "k", "m"}, {"::bad", "k", "m"},
	} {
		if _, err := New(c[0], c[1], c[2]); err == nil {
			t.Errorf("New(%v) should fail", c)
		}
	}
	for _, base := range []string{"https://example.com", "http://127.0.0.1:20128", "http://localhost:20128"} {
		if _, err := New(base, "k", "m"); err != nil {
			t.Errorf("New(%q): %v", base, err)
		}
	}
}

func TestRequestAsksForNextStepsFromRemediation(t *testing.T) {
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.Write([]byte(`{"content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()
	e, _ := New(server.URL, "k", "m")
	e.Explain(context.Background(), sample())
	if !strings.Contains(got, "Next step: ") || !strings.Contains(got, `\"remediation\":\"Review\"`) {
		t.Fatalf("request must demand Next step lines and carry each finding's remediation: %s", got)
	}
}
