package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func sampleAnalysis(installation int64, pr int, at time.Time) Analysis {
	return Analysis{
		InstallationID: installation, RepositoryID: 7, RepositoryFullName: "acme/app", PullRequest: pr, HeadSHA: "abc1234",
		Recommendation: "BLOCK", Level: "CRITICAL", Score: 75, CreatedAt: at,
		Findings: []FindingSummary{{RuleID: "rds-public-access", Severity: "CRITICAL"}},
	}
}

// storeContract is run against every implementation, so Memory and Postgres cannot drift apart.
func storeContract(t *testing.T, s Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	old, mid, recent := now.Add(-72*time.Hour), now.Add(-24*time.Hour), now.Add(-time.Hour)
	for _, a := range []Analysis{sampleAnalysis(1, 10, old), sampleAnalysis(1, 11, mid), sampleAnalysis(1, 12, recent), sampleAnalysis(2, 20, recent)} {
		if err := s.RecordAnalysis(ctx, a); err != nil {
			t.Fatalf("RecordAnalysis: %v", err)
		}
	}

	list, err := s.ListAnalyses(ctx, 1, 10)
	if err != nil || len(list) != 3 {
		t.Fatalf("tenant 1 list = %d rows, err %v; want 3", len(list), err)
	}
	if list[0].PullRequest != 12 || list[2].PullRequest != 10 {
		t.Errorf("newest first expected, got PRs %d,%d,%d", list[0].PullRequest, list[1].PullRequest, list[2].PullRequest)
	}
	if len(list[0].Findings) != 1 || list[0].Findings[0].RuleID != "rds-public-access" {
		t.Errorf("findings summary lost: %+v", list[0].Findings)
	}
	for _, a := range list {
		if a.InstallationID != 1 {
			t.Errorf("tenant 1 saw tenant %d's row", a.InstallationID)
		}
	}
	if other, _ := s.ListAnalyses(ctx, 2, 10); len(other) != 1 || other[0].PullRequest != 20 {
		t.Errorf("tenant 2 list = %+v", other)
	}
	if none, err := s.ListAnalyses(ctx, 3, 10); err != nil || len(none) != 0 {
		t.Errorf("unknown tenant must see nothing: %v %v", none, err)
	}
	if limited, _ := s.ListAnalyses(ctx, 1, 2); len(limited) != 2 {
		t.Errorf("limit 2 returned %d rows", len(limited))
	}

	if n, err := s.CountAnalysesSince(ctx, 1, now.Add(-48*time.Hour)); err != nil || n != 2 {
		t.Errorf("count since -48h = %d, err %v; want 2", n, err)
	}
	if n, _ := s.CountAnalysesSince(ctx, 2, now.Add(-48*time.Hour)); n != 1 {
		t.Errorf("count must be tenant-scoped, got %d", n)
	}

	removed, err := s.PurgeAnalysesBefore(ctx, now.Add(-48*time.Hour))
	if err != nil || removed != 1 {
		t.Fatalf("purge removed %d, err %v; want 1 (the 72h-old row)", removed, err)
	}
	if list, _ := s.ListAnalyses(ctx, 1, 10); len(list) != 2 {
		t.Errorf("after purge tenant 1 has %d rows, want 2", len(list))
	}
	if other, _ := s.ListAnalyses(ctx, 2, 10); len(other) != 1 {
		t.Error("purge must not touch newer rows of other tenants")
	}

	for name, bad := range map[string]Analysis{
		"no installation": {RepositoryID: 7, RepositoryFullName: "a/b", PullRequest: 1, HeadSHA: "x", Recommendation: "SAFE", Level: "LOW"},
		"bad score":       func() Analysis { a := sampleAnalysis(1, 1, now); a.Score = 101; return a }(),
		"no head sha":     func() Analysis { a := sampleAnalysis(1, 1, now); a.HeadSHA = ""; return a }(),
	} {
		if err := s.RecordAnalysis(ctx, bad); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}

	// Re-analyzing a commit replaces its verdict; another commit of the same PR is a new row.
	again := sampleAnalysis(1, 12, now)
	again.Recommendation, again.Level, again.Score = "SAFE", "LOW", 0
	again.Findings = nil
	if err := s.RecordAnalysis(ctx, again); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordAnalysis(ctx, func() Analysis { a := sampleAnalysis(1, 12, now); a.HeadSHA = "def5678"; return a }()); err != nil {
		t.Fatal(err)
	}
	rows, _ := s.ListAnalyses(ctx, 1, 10)
	var sameCommit, otherCommit int
	for _, row := range rows {
		if row.PullRequest == 12 && row.HeadSHA == "abc1234" {
			sameCommit++
			if row.Recommendation != "SAFE" || row.Score != 0 || len(row.Findings) != 0 {
				t.Errorf("re-analysis must replace the verdict: %+v", row)
			}
		}
		if row.PullRequest == 12 && row.HeadSHA == "def5678" {
			otherCommit++
		}
	}
	if sameCommit != 1 || otherCommit != 1 || len(rows) != 3 { // PR 11, and PR 12 at two commits (PR 10 was purged above)
		t.Errorf("rows %d, same commit %d, other commit %d; want one row per commit", len(rows), sameCommit, otherCommit)
	}
}

func repositoryFilterContract(t *testing.T, s Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	record := func(installation, repository int64, pr int, at time.Time) {
		a := sampleAnalysis(installation, pr, at)
		a.RepositoryID, a.RepositoryFullName = repository, fmt.Sprintf("acme/repo%d", repository)
		if err := s.RecordAnalysis(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	record(5, 100, 1, now.Add(-3*time.Hour))
	record(5, 100, 2, now.Add(-1*time.Hour))
	record(5, 101, 3, now.Add(-2*time.Hour))
	record(6, 100, 9, now) // another tenant, same repository ID: must never appear for tenant 5
	prs := func(rows []Analysis) string {
		var out []string
		for _, r := range rows {
			out = append(out, fmt.Sprint(r.PullRequest))
		}
		return strings.Join(out, ",")
	}
	for name, tc := range map[string]struct {
		repos []int64
		limit int
		want  string
	}{
		"one repository":     {[]int64{100}, 10, "2,1"},
		"two repositories":   {[]int64{100, 101}, 10, "2,3,1"},
		"unknown repository": {[]int64{999}, 10, ""},
		"no repositories":    {nil, 10, ""},
		"empty list":         {[]int64{}, 10, ""},
		"limit applies":      {[]int64{100, 101}, 2, "2,3"},
		"duplicate ids":      {[]int64{100, 100}, 10, "2,1"},
	} {
		rows, err := s.ListAnalysesForRepositories(ctx, 5, tc.repos, tc.limit)
		if err != nil || prs(rows) != tc.want {
			t.Errorf("%s: got %q, err %v; want %q", name, prs(rows), err, tc.want)
		}
	}
	if rows, _ := s.ListAnalysesForRepositories(ctx, 6, []int64{100}, 10); prs(rows) != "9" {
		t.Errorf("tenant 6 sees %q, want only its own row", prs(rows))
	}
}

func TestMemoryStoreContract(t *testing.T) {
	storeContract(t, NewMemory())
	repositoryFilterContract(t, NewMemory())
}

func TestValidateURL(t *testing.T) {
	for url, ok := range map[string]bool{
		"postgres://u:p@localhost:5432/db":                     true,
		"postgres://u:p@127.0.0.1/db":                          true,
		"postgresql://u:p@db.internal:5432/db?sslmode=require": true,
		"postgres://u:p@db.internal/db?sslmode=verify-full":    true,
		"postgres://u:p@db.internal/db":                        false, // remote without TLS
		"postgres://u:p@db.internal/db?sslmode=disable":        false,
		"postgres://u:p@db.internal/db?sslmode=prefer":         false,
		"mysql://u:p@localhost/db":                             false,
		"not a url":                                            false,
		"postgres:///db":                                       false,
	} {
		if err := ValidateURL(url); (err == nil) != ok {
			t.Errorf("ValidateURL(%q) = %v, want ok=%v", url, err, ok)
		}
	}
}

// --- PostgreSQL integration tests: they run only when DEPLOYGUARD_TEST_POSTGRES_URL points at a
// --- disposable server (superuser URL). Each test creates its own database and non-super role.

func adminURL(t *testing.T) string {
	t.Helper()
	raw := os.Getenv("DEPLOYGUARD_TEST_POSTGRES_URL")
	if raw == "" {
		t.Skip("set DEPLOYGUARD_TEST_POSTGRES_URL to run PostgreSQL integration tests")
	}
	return raw
}

func randomName(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// newPostgres creates a fresh database owned by a NOSUPERUSER, NOBYPASSRLS role and opens the store as it.
func newPostgres(t *testing.T) (*Postgres, string) {
	t.Helper()
	admin := adminURL(t)
	adminDB, err := sql.Open("pgx", admin)
	if err != nil {
		t.Fatal(err)
	}
	name, password := "dg_"+randomName(t), randomName(t)+randomName(t)
	role := name + "_app"
	for _, stmt := range []string{
		`CREATE ROLE ` + role + ` LOGIN PASSWORD '` + password + `' NOSUPERUSER NOBYPASSRLS`,
		`CREATE DATABASE ` + name + ` OWNER ` + role,
	} {
		if _, err := adminDB.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	t.Cleanup(func() {
		_, _ = adminDB.Exec(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '` + name + `'`)
		_, _ = adminDB.Exec(`DROP DATABASE IF EXISTS ` + name)
		_, _ = adminDB.Exec(`DROP ROLE IF EXISTS ` + role)
		adminDB.Close()
	})
	u, _ := url.Parse(admin)
	u.User = url.UserPassword(role, password)
	u.Path = "/" + name
	store, err := Open(context.Background(), u.String())
	if err != nil {
		t.Fatalf("Open as the app role: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store, admin
}

func TestPostgresStoreContract(t *testing.T) {
	store, _ := newPostgres(t)
	storeContract(t, store)
	repositoryFilterContract(t, store)
}

func TestPostgresRowLevelSecurityFailsClosed(t *testing.T) {
	store, _ := newPostgres(t)
	ctx := context.Background()
	for _, id := range []int64{1, 2} {
		if err := store.RecordAnalysis(ctx, sampleAnalysis(id, 1, time.Now())); err != nil {
			t.Fatal(err)
		}
	}
	// A query with no tenant scope and no WHERE clause: the database itself must return nothing.
	var count int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM analyses`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("unscoped read saw %d rows (err %v); RLS must fail closed", count, err)
	}
	// Scoped to tenant 1, a careless "all rows" query still only sees tenant 1.
	if err := store.withTenant(ctx, 1, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM analyses`).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			t.Errorf("tenant 1 scope saw %d rows, want 1", count)
		}
		// Writing a row for another tenant must be refused by the policy.
		_, err := tx.ExecContext(ctx, `INSERT INTO analyses (installation_id, repository_id, repository_full_name, pull_request, head_sha, recommendation, level, score)
			VALUES (2, 7, 'a/b', 1, 'x', 'SAFE', 'LOW', 0)`)
		if err == nil {
			t.Error("inserting a row for another tenant must fail")
		}
		return errTestRollback
	}); err != errTestRollback {
		t.Fatalf("unexpected error: %v", err)
	}
	// Unscoped deletes and updates touch nothing.
	res, err := store.db.ExecContext(ctx, `DELETE FROM analyses`)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := res.RowsAffected(); n != 0 {
		t.Errorf("an unscoped DELETE removed %d rows", n)
	}
	if rows, _ := store.ListAnalyses(ctx, 1, 10); len(rows) != 1 {
		t.Error("tenant 1's row must survive")
	}
}

var errTestRollback = &rollbackError{}

type rollbackError struct{}

func (*rollbackError) Error() string { return "rollback" }

func TestPostgresTenantSettingDoesNotLeakAcrossPooledConnections(t *testing.T) {
	store, _ := newPostgres(t)
	store.db.SetMaxOpenConns(1) // force every call onto the same connection
	ctx := context.Background()
	if err := store.RecordAnalysis(ctx, sampleAnalysis(1, 1, time.Now())); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM analyses`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("tenant scope leaked to the next user of the connection: %d rows, err %v", count, err)
	}
}

func TestPostgresRefusesRolesThatBypassRowLevelSecurity(t *testing.T) {
	if _, err := Open(context.Background(), adminURL(t)); err == nil || !strings.Contains(err.Error(), "bypasses row-level security") {
		t.Fatalf("a superuser connection must be refused, got %v", err)
	}
}

func TestPostgresMigrationsAreIdempotent(t *testing.T) {
	first, admin := newPostgres(t)
	if err := first.migrate(context.Background()); err != nil {
		t.Fatalf("second migration run: %v", err)
	}
	var versions int
	if err := first.db.QueryRow(`SELECT count(*) FROM schema_migrations WHERE version = 1`).Scan(&versions); err != nil || versions != 1 {
		t.Fatalf("migration 1 recorded %d times (err %v)", versions, err)
	}
	_ = admin
}

func TestPostgresRetentionPolicyAllowsNothingExceptOldDeletes(t *testing.T) {
	store, _ := newPostgres(t)
	ctx := context.Background()
	if err := store.RecordAnalysis(ctx, sampleAnalysis(1, 1, time.Now().Add(-time.Hour))); err != nil {
		t.Fatal(err)
	}
	// With the purge setting but no tenant, rows newer than the cutoff stay invisible and undeletable.
	tx, _ := store.db.BeginTx(ctx, nil)
	defer tx.Rollback()
	_, _ = tx.ExecContext(ctx, `SELECT set_config('app.purge_before', $1, true)`, time.Now().Add(-48*time.Hour).UTC().Format(time.RFC3339Nano))
	var count int
	_ = tx.QueryRowContext(ctx, `SELECT count(*) FROM analyses`).Scan(&count)
	if count != 0 {
		t.Errorf("the purge setting must not expose rows newer than the cutoff, saw %d", count)
	}
	res, _ := tx.ExecContext(ctx, `DELETE FROM analyses`)
	if n, _ := res.RowsAffected(); n != 0 {
		t.Errorf("a cutoff older than the row must not delete it, removed %d", n)
	}
}

func TestPostgresMigrationRemovesExistingDuplicatesAndKeepsTheNewest(t *testing.T) {
	store, _ := newPostgres(t) // fully migrated; rebuild an older schema state below
	ctx := context.Background()
	// Go back to the schema as it was before migration 2: no unique index.
	if _, err := store.db.ExecContext(ctx, `DROP INDEX analyses_one_per_commit; DELETE FROM schema_migrations WHERE version = 2`); err != nil {
		t.Fatal(err)
	}
	old, newer := time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
	for _, at := range []time.Time{old, newer} {
		if err := store.withTenant(ctx, 1, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO analyses (installation_id, repository_id, repository_full_name, pull_request, head_sha, recommendation, level, score, created_at)
				VALUES (1, 7, 'acme/app', 3, 'abc1234', $1, 'LOW', 5, $2)`, map[bool]string{true: "SAFE", false: "BLOCK"}[at.Equal(newer)], at)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.migrate(ctx); err != nil {
		t.Fatalf("migration with duplicates present: %v", err)
	}
	rows, err := store.ListAnalyses(ctx, 1, 10)
	if err != nil || len(rows) != 1 || rows[0].Recommendation != "SAFE" {
		t.Fatalf("rows %+v, err %v; want only the newest verdict", rows, err)
	}
	var forced bool
	if err := store.db.QueryRowContext(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE relname = 'analyses'`).Scan(&forced); err != nil || !forced {
		t.Fatalf("row-level security must be forced again after the migration (forced=%v, err=%v)", forced, err)
	}
}
