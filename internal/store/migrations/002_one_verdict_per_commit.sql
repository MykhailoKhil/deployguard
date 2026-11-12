-- One stored verdict per commit of a pull request. Re-analyzing a commit (a workflow rerun, a
-- redelivered webhook) updates its row instead of adding a duplicate.
--
-- Existing duplicates must be removed first, keeping the newest. FORCE ROW LEVEL SECURITY would hide
-- every row from this migration (no tenant is set), so it is lifted for the cleanup and restored
-- immediately; the whole migration runs in one transaction, so a failure leaves nothing half-done.
ALTER TABLE analyses NO FORCE ROW LEVEL SECURITY;
DELETE FROM analyses older USING analyses newer
 WHERE older.installation_id = newer.installation_id
   AND older.repository_id   = newer.repository_id
   AND older.pull_request    = newer.pull_request
   AND older.head_sha        = newer.head_sha
   AND (older.created_at, older.id) < (newer.created_at, newer.id);
ALTER TABLE analyses FORCE ROW LEVEL SECURITY;

CREATE UNIQUE INDEX analyses_one_per_commit
    ON analyses (installation_id, repository_id, pull_request, head_sha);
