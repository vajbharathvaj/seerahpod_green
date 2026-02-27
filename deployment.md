# Deployment Notes

## Database config uses `DATABASE_URL`

`core/settings.py` now uses `dj_database_url`:

```python
import os
import dj_database_url

DATABASES = {
    "default": dj_database_url.config(
        default=os.environ.get("DATABASE_URL")
    )
}
```

The previous `DATABASES = {...}` block is still present in `core/settings.py` as commented code for reference.

## Required environment variable

Set `DATABASE_URL` before starting Django.

Example PostgreSQL value:

```env
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/design1
```

## Dependency

`requirements.txt` includes:

```txt
dj-database-url>=2.2
```

Install/update dependencies:

```bash
pip install -r requirements.txt
```

## How to reverse this change

1. Open `core/settings.py`.
2. Remove or comment out the new `dj_database_url` import and `DATABASES` block.
3. Uncomment the old `DATABASES = {...}` block that uses `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_HOST`, and `POSTGRES_PORT`.
4. Optionally remove `dj-database-url` from `requirements.txt` if no longer needed.

After rollback, Django will again use the old environment-variable-based host/user/password database settings.
