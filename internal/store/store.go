// Package store persists what DeployGuard must remember between requests: a verdict history per
// tenant. It deliberately never stores Terraform plans or
// attribute values, only the verdict and the rule IDs that fired.
//
// A tenant is a GitHub App installation. Every operation takes the installation ID, and the
// PostgreSQL implementation also enforces isolation in the database with row-level security.
package store

import (
	"context"
	"errors"
	"time"
)

// FindingSummary is the part of a finding worth keeping: which rule fired, how severe.
type FindingSummary struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
}

// Analysis is one stored verdict.
type Analysis struct {
	ID                 int64
	InstallationID     int64
	RepositoryID       int64
	RepositoryFullName string
	PullRequest        int
	HeadSHA            string
	Recommendation     string
	Level              string
	Score              int
	Findings           []FindingSummary
	CreatedAt          time.Time // set by the store when zero
}

// ErrInvalid is returned for input that can never be stored (a bug in the caller, not a failure).
var ErrInvalid = errors.New("invalid store input")

// Store is the persistence surface. Implementations must be safe for concurrent use.
type Store interface {
	// RecordAnalysis stores a verdict for a tenant. There is one verdict per commit of a pull
	// request: recording the same commit again replaces its verdict.
	RecordAnalysis(ctx context.Context, analysis Analysis) error
	// ListAnalyses returns a tenant's newest verdicts first (limit 1..200).
	ListAnalyses(ctx context.Context, installationID int64, limit int) ([]Analysis, error)
	// ListAnalysesForRepositories is ListAnalyses limited to the given repositories (newest first,
	// limit 1..200). Callers pass only repositories the signed-in user may see, so the user never
	// sees another repository's verdicts from the same installation. No repositories, no rows.
	ListAnalysesForRepositories(ctx context.Context, installationID int64, repositoryIDs []int64, limit int) ([]Analysis, error)
	// CountAnalysesSince counts a tenant's verdicts recorded at or after since.
	CountAnalysesSince(ctx context.Context, installationID int64, since time.Time) (int, error)
	// PurgeAnalysesBefore deletes verdicts older than cutoff for every tenant (retention).
	PurgeAnalysesBefore(ctx context.Context, cutoff time.Time) (int64, error)
	Close() error
}

func (a Analysis) validate() error {
	if a.InstallationID <= 0 || a.RepositoryID <= 0 || a.RepositoryFullName == "" || a.PullRequest <= 0 || a.HeadSHA == "" {
		return ErrInvalid
	}
	if a.Recommendation == "" || a.Level == "" || a.Score < 0 || a.Score > 100 {
		return ErrInvalid
	}
	return nil
}

func clampLimit(limit int) int {
	if limit < 1 {
		return 1
	}
	if limit > 200 {
		return 200
	}
	return limit
}
