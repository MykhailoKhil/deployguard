package store

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func verdict(score int) LocalVerdict {
	return LocalVerdict{PlanSHA256: fmt.Sprintf("%064x", score), Recommendation: "BLOCK", Level: "HIGH", Score: score,
		Findings: []FindingSummary{{RuleID: "rds-public-access", Severity: "CRITICAL"}}}
}

func openHistory(t *testing.T, max int) (*FileHistory, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "deployguard", "history.jsonl")
	h, err := OpenFileHistory(path, max)
	if err != nil {
		t.Fatal(err)
	}
	return h, path
}

func TestFileHistoryListsNewestFirstAndKeepsOnlyTheVerdict(t *testing.T) {
	h, path := openHistory(t, 100)
	for score := 1; score <= 3; score++ {
		if err := h.Add(verdict(score)); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := h.List(10)
	if err != nil || len(rows) != 3 || rows[0].Score != 3 || rows[2].Score != 1 {
		t.Fatalf("rows %+v err %v; want newest first", rows, err)
	}
	if rows[0].At.IsZero() || len(rows[0].Findings) != 1 || rows[0].PlanSHA256 == "" {
		t.Errorf("entry incomplete: %+v", rows[0])
	}
	if limited, _ := h.List(2); len(limited) != 2 || limited[0].Score != 3 {
		t.Errorf("limit not applied: %+v", limited)
	}
	raw, _ := os.ReadFile(path)
	for _, forbidden := range []string{"resource", "address", "password"} {
		if len(raw) == 0 || strings.Contains(string(raw), forbidden) {
			t.Errorf("history file must hold only the verdict, found %q in %s", forbidden, raw)
		}
	}
}

func TestFileHistoryIsPrivateAndSurvivesReopen(t *testing.T) {
	h, path := openHistory(t, 100)
	_ = h.Add(verdict(7))
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("history file mode %v, want 0600", info.Mode().Perm())
	}
	if info, _ := os.Stat(filepath.Dir(path)); info.Mode().Perm() != 0o700 {
		t.Errorf("history folder mode %v, want 0700", info.Mode().Perm())
	}
	again, err := OpenFileHistory(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	if rows, _ := again.List(10); len(rows) != 1 || rows[0].Score != 7 {
		t.Errorf("history lost on reopen: %+v", rows)
	}
}

func TestFileHistoryTrimsToTheNewestAndSkipsDamagedLines(t *testing.T) {
	h, path := openHistory(t, 5)
	for score := 1; score <= 30; score++ {
		if err := h.Add(verdict(score)); err != nil {
			t.Fatal(err)
		}
	}
	rows, _ := h.List(200)
	if len(rows) > 10 || rows[0].Score != 30 {
		t.Fatalf("file must stay bounded (at most 2x the limit) and keep the newest: %d rows, first %d", len(rows), rows[0].Score)
	}
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString("this is not json\n{\"recommendation\":\"\"}\n")
	f.Close()
	if again, _ := h.List(200); len(again) != len(rows) {
		t.Errorf("damaged lines must be skipped, not break the list: %d vs %d", len(again), len(rows))
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("mode after trim %v, want 0600", info.Mode().Perm())
	}
}

func TestFileHistoryRejectsBadInputAndUnusablePaths(t *testing.T) {
	h, _ := openHistory(t, 10)
	for name, bad := range map[string]LocalVerdict{
		"no recommendation": {Level: "LOW"}, "bad score": {Recommendation: "SAFE", Level: "LOW", Score: 101},
	} {
		if h.Add(bad) == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := OpenFileHistory("", 10); err == nil {
		t.Error("an empty path must be rejected")
	}
	blocker := filepath.Join(t.TempDir(), "file")
	_ = os.WriteFile(blocker, []byte("x"), 0o600)
	if _, err := OpenFileHistory(filepath.Join(blocker, "sub", "h.jsonl"), 10); err == nil {
		t.Error("a path under a regular file must fail")
	}
}

func TestFileHistoryHandlesConcurrentAdds(t *testing.T) {
	h, _ := openHistory(t, 1000)
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := h.Add(verdict(i%100 + 1)); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if rows, _ := h.List(200); len(rows) != 40 {
		t.Fatalf("got %d rows, want 40 (no lost or torn lines)", len(rows))
	}
}
