package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// migrationLock serializes migrations when several instances start at once.
const migrationLock = 7233001

// Postgres is the PostgreSQL-backed Store. Tenant isolation is enforced twice: every query filters
// by installation ID, and row-level security makes the database refuse cross-tenant access even if
// a query forgets to.
type Postgres struct {
	db *sql.DB
}

// ValidateURL checks a PostgreSQL connection URL without connecting. A remote server must be
// reached over TLS, so credentials and data never cross a network in clear text.
func ValidateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Host == "" && u.Query().Get("host") == "" {
		return errors.New("database URL must look like postgres://user:password@host:5432/dbname")
	}
	host := u.Hostname()
	if host == "" {
		host = u.Query().Get("host")
	}
	local := host == "localhost" || strings.HasPrefix(host, "/") || func() bool { ip := net.ParseIP(host); return ip != nil && ip.IsLoopback() }()
	if mode := u.Query().Get("sslmode"); !local && mode != "require" && mode != "verify-ca" && mode != "verify-full" {
		return errors.New("database URL for a remote host must set sslmode=require, verify-ca or verify-full")
	}
	return nil
}

// Open connects, refuses roles that bypass row-level security, and applies pending migrations.
func Open(ctx context.Context, databaseURL string) (*Postgres, error) {
	if err := ValidateURL(databaseURL); err != nil {
		return nil, err
	}
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, errors.New("open database")
	}
	db.SetMaxOpenConns(10)
	db.SetConnMaxLifetime(30 * time.Minute)
	store := &Postgres{db: db}
	if err := store.init(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (p *Postgres) init(ctx context.Context) error {
	if err := p.db.PingContext(ctx); err != nil {
		return errors.New("cannot reach the database (check the URL, credentials and network)")
	}
	var bypass bool
	if err := p.db.QueryRowContext(ctx, `SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&bypass); err != nil {
		return errors.New("cannot read the database role")
	}
	if bypass {
		return errors.New("refusing to run as a database role that bypasses row-level security (superuser or BYPASSRLS); use a dedicated role")
	}
	return p.migrate(ctx)
}

func (p *Postgres) migrate(ctx context.Context) error { return p.migrateUpTo(ctx, 1<<30) }

// migrateUpTo applies pending migrations with a version of at most maxVersion (tests use it to
// start from an older schema).
func (p *Postgres) migrateUpTo(ctx context.Context, maxVersion int) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationLock); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	entries, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		version, err := strconv.Atoi(strings.SplitN(entry.Name(), "_", 2)[0])
		if err != nil {
			return fmt.Errorf("bad migration name %q", entry.Name())
		}
		if version > maxVersion {
			break
		}
		var applied bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, version).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		script, err := migrationFiles.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(script)); err != nil {
			return fmt.Errorf("apply migration %s: %w", entry.Name(), err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// withTenant runs fn in a transaction whose row-level-security scope is one installation.
func (p *Postgres) withTenant(ctx context.Context, installationID int64, fn func(*sql.Tx) error) error {
	if installationID <= 0 {
		return ErrInvalid
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// is_local = true: the setting dies with the transaction, so it cannot leak to the next user
	// of a pooled connection.
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.installation_id', $1, true)`, strconv.FormatInt(installationID, 10)); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (p *Postgres) RecordAnalysis(ctx context.Context, a Analysis) error {
	if err := a.validate(); err != nil {
		return err
	}
	findings, err := json.Marshal(append([]FindingSummary{}, a.Findings...))
	if err != nil {
		return err
	}
	created := a.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	return p.withTenant(ctx, a.InstallationID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO analyses
			(installation_id, repository_id, repository_full_name, pull_request, head_sha, recommendation, level, score, findings, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10)
			ON CONFLICT (installation_id, repository_id, pull_request, head_sha) DO UPDATE SET
				repository_full_name = EXCLUDED.repository_full_name, recommendation = EXCLUDED.recommendation,
				level = EXCLUDED.level, score = EXCLUDED.score, findings = EXCLUDED.findings, created_at = EXCLUDED.created_at`,
			a.InstallationID, a.RepositoryID, a.RepositoryFullName, a.PullRequest, a.HeadSHA, a.Recommendation, a.Level, a.Score, string(findings), created)
		return err
	})
}

func (p *Postgres) ListAnalyses(ctx context.Context, installationID int64, limit int) ([]Analysis, error) {
	return p.listAnalyses(ctx, installationID, nil, limit)
}

// maxRepositoryFilter bounds how many repository IDs one query may carry.
const maxRepositoryFilter = 2000

func (p *Postgres) ListAnalysesForRepositories(ctx context.Context, installationID int64, repositoryIDs []int64, limit int) ([]Analysis, error) {
	if len(repositoryIDs) == 0 {
		return nil, nil
	}
	if len(repositoryIDs) > maxRepositoryFilter {
		repositoryIDs = repositoryIDs[:maxRepositoryFilter]
	}
	return p.listAnalyses(ctx, installationID, repositoryIDs, limit)
}

// listAnalyses reads a tenant's newest verdicts; a non-nil repositoryIDs limits it to those repositories.
func (p *Postgres) listAnalyses(ctx context.Context, installationID int64, repositoryIDs []int64, limit int) ([]Analysis, error) {
	var out []Analysis
	err := p.withTenant(ctx, installationID, func(tx *sql.Tx) error {
		query := `SELECT id, installation_id, repository_id, repository_full_name, pull_request, head_sha,
			recommendation, level, score, findings, created_at
			FROM analyses WHERE installation_id = $1 AND ($2::bigint[] IS NULL OR repository_id = ANY($2))
			ORDER BY created_at DESC, id DESC LIMIT $3`
		var filter any
		if repositoryIDs != nil {
			filter = repositoryIDs
		}
		rows, err := tx.QueryContext(ctx, query, installationID, filter, clampLimit(limit))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a Analysis
			var findings []byte
			if err := rows.Scan(&a.ID, &a.InstallationID, &a.RepositoryID, &a.RepositoryFullName, &a.PullRequest, &a.HeadSHA,
				&a.Recommendation, &a.Level, &a.Score, &findings, &a.CreatedAt); err != nil {
				return err
			}
			if err := json.Unmarshal(findings, &a.Findings); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

func (p *Postgres) CountAnalysesSince(ctx context.Context, installationID int64, since time.Time) (int, error) {
	var count int
	err := p.withTenant(ctx, installationID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM analyses WHERE installation_id = $1 AND created_at >= $2`, installationID, since).Scan(&count)
	})
	return count, err
}

// PurgeAnalysesBefore deletes old verdicts of every tenant. It works through a delete-only policy
// that requires the cutoff to be set, so it cannot read or alter anything else.
func (p *Postgres) PurgeAnalysesBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.purge_before', $1, true)`, cutoff.UTC().Format(time.RFC3339Nano)); err != nil {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM analyses WHERE created_at < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	removed, _ := result.RowsAffected()
	return removed, tx.Commit()
}

func (p *Postgres) Close() error { return p.db.Close() }

var _ Store = (*Postgres)(nil)
