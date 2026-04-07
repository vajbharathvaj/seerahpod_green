# Deployment Notes

## Railway PostgreSQL setup

1. In Railway, add a PostgreSQL service to your project.
2. Railway will provide either:
   - `DATABASE_URL`, or
   - `PGDATABASE`, `PGUSER`, `PGPASSWORD`, `PGHOST`, `PGPORT`

## Django database behavior

`core/settings.py` now supports both Railway styles:

1. If `DATABASE_URL` is present, Django uses it via `dj_database_url`.
2. If `DATABASE_URL` is missing, Django falls back to:
   - `PGDATABASE`, `PGUSER`, `PGPASSWORD`, `PGHOST`, `PGPORT`
3. If `PG*` vars are missing, it still supports legacy local:
   - `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_HOST`, `POSTGRES_PORT`

## Example variables

### Option A: `DATABASE_URL`

```env
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/design1
```

### Option B: `PG*` vars

```env
PGDATABASE=design1
PGUSER=postgres
PGPASSWORD=postgres
PGHOST=localhost
PGPORT=5432
```

## Requirements

`requirements.txt` includes `dj-database-url` and `psycopg2-binary`.

Install dependencies:

```bash
pip install -r requirements.txt
```
