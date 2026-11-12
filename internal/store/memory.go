package store

import (
	"context"
	"sort"
	"sync"
	"time"
)

// Memory is an in-process Store for tests and for running without a database. It enforces the same
// tenant scoping as the PostgreSQL store, but nothing survives a restart.
type Memory struct {
	mu       sync.Mutex
	nextID   int64
	analyses []Analysis
	now      func() time.Time
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{now: time.Now}
}

func (m *Memory) RecordAnalysis(_ context.Context, a Analysis) error {
	if err := a.validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if a.CreatedAt.IsZero() {
		a.CreatedAt = m.now()
	}
	a.Findings = append([]FindingSummary(nil), a.Findings...)
	// One verdict per commit: re-analyzing a commit replaces its row (same as the PostgreSQL store).
	for i, existing := range m.analyses {
		if existing.InstallationID == a.InstallationID && existing.RepositoryID == a.RepositoryID &&
			existing.PullRequest == a.PullRequest && existing.HeadSHA == a.HeadSHA {
			a.ID = existing.ID
			m.analyses[i] = a
			return nil
		}
	}
	m.nextID++
	a.ID = m.nextID
	m.analyses = append(m.analyses, a)
	return nil
}

func (m *Memory) ListAnalyses(_ context.Context, installationID int64, limit int) ([]Analysis, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Analysis
	for _, a := range m.analyses {
		if a.InstallationID == installationID {
			out = append(out, a)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID > out[j].ID
	})
	if limit < 1<<30 {
		if n := clampLimit(limit); len(out) > n {
			out = out[:n]
		}
	}
	return out, nil
}

func (m *Memory) ListAnalysesForRepositories(ctx context.Context, installationID int64, repositoryIDs []int64, limit int) ([]Analysis, error) {
	allowed := make(map[int64]bool, len(repositoryIDs))
	for _, id := range repositoryIDs {
		allowed[id] = true
	}
	all, err := m.ListAnalyses(ctx, installationID, 1<<30)
	if err != nil {
		return nil, err
	}
	var out []Analysis
	for _, a := range all {
		if allowed[a.RepositoryID] {
			out = append(out, a)
		}
	}
	if n := clampLimit(limit); len(out) > n {
		out = out[:n]
	}
	return out, nil
}

func (m *Memory) CountAnalysesSince(_ context.Context, installationID int64, since time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, a := range m.analyses {
		if a.InstallationID == installationID && !a.CreatedAt.Before(since) {
			count++
		}
	}
	return count, nil
}

func (m *Memory) PurgeAnalysesBefore(_ context.Context, cutoff time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := m.analyses[:0]
	var removed int64
	for _, a := range m.analyses {
		if a.CreatedAt.Before(cutoff) {
			removed++
			continue
		}
		kept = append(kept, a)
	}
	m.analyses = kept
	return removed, nil
}

func (m *Memory) Close() error { return nil }

var _ Store = (*Memory)(nil)
