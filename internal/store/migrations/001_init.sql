-- Tenant = GitHub App installation. Every tenant table is protected by row-level security that is
-- FORCED, so even the table owner sees only the rows of the installation set in app.installation_id.
-- An unset or empty setting matches no rows (fails closed).

CREATE TABLE analyses (
    id                   BIGSERIAL PRIMARY KEY,
    installation_id      BIGINT       NOT NULL CHECK (installation_id > 0),
    repository_id        BIGINT       NOT NULL CHECK (repository_id > 0),
    repository_full_name TEXT         NOT NULL,
    pull_request         INTEGER      NOT NULL CHECK (pull_request > 0),
    head_sha             TEXT         NOT NULL,
    recommendation       TEXT         NOT NULL,
    level                TEXT         NOT NULL,
    score                INTEGER      NOT NULL CHECK (score BETWEEN 0 AND 100),
    findings             JSONB        NOT NULL DEFAULT '[]',
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX analyses_tenant_time ON analyses (installation_id, created_at DESC);
ALTER TABLE analyses ENABLE ROW LEVEL SECURITY;
ALTER TABLE analyses FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON analyses
    USING      (installation_id = nullif(current_setting('app.installation_id', true), '')::bigint)
    WITH CHECK (installation_id = nullif(current_setting('app.installation_id', true), '')::bigint);
-- Retention can read and delete rows of any tenant, but only rows OLDER than the cutoff, and only
-- while the cutoff is set (a DELETE with a WHERE clause must also be allowed to read the rows).
CREATE POLICY retention_read ON analyses FOR SELECT
    USING (created_at < nullif(current_setting('app.purge_before', true), '')::timestamptz);
CREATE POLICY retention_purge ON analyses FOR DELETE
    USING (created_at < nullif(current_setting('app.purge_before', true), '')::timestamptz);
