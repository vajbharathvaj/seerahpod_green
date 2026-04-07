# Railway Hosting Checklist (Django Backend)

## 1) Add PostgreSQL in Railway

In Railway project:

1. Click `New`
2. Add `PostgreSQL`

Railway creates DB variables automatically.

## 2) Environment variables expected by this backend

This backend supports both styles:

1. `DATABASE_URL` (preferred if available)
2. `PGDATABASE`, `PGUSER`, `PGPASSWORD`, `PGHOST`, `PGPORT`

It also supports legacy local fallback:

- `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_HOST`, `POSTGRES_PORT`

## 3) Verify variables in Railway

In Railway backend service -> `Variables`, confirm either:

- `DATABASE_URL`

or:

- `PGDATABASE`
- `PGUSER`
- `PGPASSWORD`
- `PGHOST`
- `PGPORT`

## 4) Dependency support

`requirements.txt` already includes:

- `dj-database-url`
- `psycopg2-binary`

Install with:

```bash
pip install -r requirements.txt
```

## 5) Run migrations after deploy

```bash
python manage.py migrate
```
