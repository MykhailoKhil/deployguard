#!/bin/sh
# Runs once, the first time the data volume is created (official postgres image hook).
# Creates the restricted role and database DeployGuard uses, and turns on TLS.
#
# DeployGuard refuses to connect as a superuser or a BYPASSRLS role, so the app never uses the
# admin account (POSTGRES_USER). The app role owns only its own database.
set -eu
: "${DEPLOYGUARD_DB_PASSWORD:?DEPLOYGUARD_DB_PASSWORD must be set for the postgres service}"

# psql substitutes :'pw' as a properly quoted literal, so the password never needs shell quoting.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres -v pw="$DEPLOYGUARD_DB_PASSWORD" <<'SQL'
CREATE ROLE deployguard LOGIN PASSWORD :'pw' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
CREATE DATABASE deployguard OWNER deployguard;
SQL

# A throwaway self-signed certificate: it encrypts traffic between containers (DeployGuard requires
# TLS for any non-loopback database host). Use a real certificate if the database leaves this network.
openssl req -new -x509 -days 3650 -nodes -subj "/CN=postgres" \
  -keyout "$PGDATA/server.key" -out "$PGDATA/server.crt" 2>/dev/null
chmod 600 "$PGDATA/server.key"
cat >> "$PGDATA/postgresql.conf" <<'CONF'
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'
CONF
# Accept network connections only over TLS.
sed -i 's/^host all all all /hostssl all all all /' "$PGDATA/pg_hba.conf"
grep -q '^hostssl all all all ' "$PGDATA/pg_hba.conf"
