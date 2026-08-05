#!/bin/sh
set -eu

: "${CONTROL_DB_USER:?CONTROL_DB_USER is required}"
: "${CONTROL_DB_PASSWORD:?CONTROL_DB_PASSWORD is required}"
: "${EXECUTION_DB_USER:?EXECUTION_DB_USER is required}"
: "${EXECUTION_DB_PASSWORD:?EXECUTION_DB_PASSWORD is required}"

if [ "$CONTROL_DB_USER" = "$EXECUTION_DB_USER" ]; then
  echo "CONTROL_DB_USER and EXECUTION_DB_USER must be distinct" >&2
  exit 64
fi
if [ "$CONTROL_DB_USER" = "$POSTGRES_USER" ] || [ "$EXECUTION_DB_USER" = "$POSTGRES_USER" ]; then
  echo "application roles must not reuse POSTGRES_USER" >&2
  exit 64
fi

psql -v ON_ERROR_STOP=1 \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" \
  --set=control_user="$CONTROL_DB_USER" \
  --set=control_password="$CONTROL_DB_PASSWORD" \
  --set=execution_user="$EXECUTION_DB_USER" \
  --set=execution_password="$EXECUTION_DB_PASSWORD" \
  --set=database_name="$POSTGRES_DB" <<'SQL'
-- Keep psql variable expansion outside quoted PL/pgSQL bodies.  format(%I/%L)
-- provides identifier/literal quoting without exposing credentials in logs.
SELECT format('CREATE ROLE %I LOGIN', :'control_user')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'control_user')\gexec
SELECT format('ALTER ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L', :'control_user', :'control_password')\gexec
SELECT format('CREATE ROLE %I LOGIN', :'execution_user')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'execution_user')\gexec
SELECT format('ALTER ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L', :'execution_user', :'execution_password')\gexec

SELECT format('CREATE SCHEMA IF NOT EXISTS control AUTHORIZATION %I', :'control_user')\gexec
SELECT format('CREATE SCHEMA IF NOT EXISTS execution AUTHORIZATION %I', :'execution_user')\gexec
SELECT format('ALTER SCHEMA control OWNER TO %I', :'control_user')\gexec
SELECT format('ALTER SCHEMA execution OWNER TO %I', :'execution_user')\gexec
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA control FROM PUBLIC;
REVOKE ALL ON SCHEMA execution FROM PUBLIC;
SELECT format('GRANT USAGE, CREATE ON SCHEMA control TO %I', :'control_user')\gexec
SELECT format('GRANT USAGE, CREATE ON SCHEMA execution TO %I', :'execution_user')\gexec
SELECT format('REVOKE ALL ON SCHEMA execution FROM %I', :'control_user')\gexec
SELECT format('REVOKE ALL ON SCHEMA control FROM %I', :'execution_user')\gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA control REVOKE ALL ON TABLES FROM PUBLIC', :'control_user')\gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA execution REVOKE ALL ON TABLES FROM PUBLIC', :'execution_user')\gexec
SELECT format('ALTER ROLE %I IN DATABASE %I SET search_path = control, pg_catalog', :'control_user', :'database_name')\gexec
SELECT format('ALTER ROLE %I IN DATABASE %I SET search_path = execution, pg_catalog', :'execution_user', :'database_name')\gexec
SQL
