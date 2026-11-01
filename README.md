# Secure Records API

A FastAPI backend for loading and querying a table of **sensitive customer records**
safely. Admins upload CSV snapshots; analysts search and export them with personal data
masked; every sensitive action is logged.

**All data in this repository is synthetic.** Names, emails, phone numbers and ID numbers
are generated at random (`secure_records/synthetic.py`) and belong to no one. Emails use
the reserved `example.com/.org/.net` domains.

## What it demonstrates

| Concern | How it is handled |
|---|---|
| Authentication | Email and password, bcrypt-hashed. Short-lived access tokens and longer refresh tokens (JWT, HS256). Refresh issues a new pair (sliding window). Token type is checked, so a refresh token cannot be used as an access token. |
| Authorisation | Role-based: `admin` and `analyst`, enforced by a dependency on each route. |
| Brute force | Login is rate limited (default 5 per minute per IP). Unknown email and wrong password return the same message and take about the same time. |
| Personal data | Name, email, phone and national ID are **masked in one place** (`masking.py`) before any response is built. Only admins can request unmasked data, and each such view is written to the audit log. |
| History | Every upload is a new **snapshot**. Nothing is overwritten, so earlier loads stay queryable. |
| Large files | Uploads are validated row by row and inserted in batches of 5,000. Bad rows are skipped and reported by line number; a file with no valid rows is rejected and creates no snapshot. |
| Money | Balances are exact decimals (`NUMERIC(14,2)`), parsed strictly (NaN, infinity and out-of-range values are rejected) and returned as strings, never floats. |
| Exports | Streamed as CSV, masked, with **formula-injection protection** (cells starting with `=`, `+`, `-`, `@` are prefixed so spreadsheet apps do not run them). |
| Audit | Logins (ok and failed), uploads, user creation, exports and unmasked views are logged with user, time and IP. Passwords never reach the log. |
| Schema changes | Alembic migrations, with a test proving they build exactly the schema the models describe. |

## Run it

```bash
pip install -r requirements.txt

export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export DATABASE_URL="sqlite:///./records.db"      # default; any SQLAlchemy URL works

alembic upgrade head                               # create the tables
python -m secure_records.cli create-user --email you@example.com --role admin
python -m secure_records.synthetic sample.csv 2000 # make demo data

uvicorn secure_records.main:create_app --factory --port 8000
```

The app refuses to start without a `SECRET_KEY` of at least 32 characters. Interactive docs
are at `http://localhost:8000/docs`.

```bash
TOKEN=$(curl -s -X POST localhost:8000/auth/login -H 'content-type: application/json' \
  -d '{"email":"you@example.com","password":"..."}' | python -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

curl -H "Authorization: Bearer $TOKEN" -F file=@sample.csv localhost:8000/snapshots
curl -H "Authorization: Bearer $TOKEN" 'localhost:8000/records?q=jaipur&limit=5'
curl -H "Authorization: Bearer $TOKEN" localhost:8000/records/export -o export.csv
```

### Endpoints

| Method and path | Who | Purpose |
|---|---|---|
| `POST /auth/login`, `/auth/refresh` | anyone | get tokens |
| `GET /auth/me` | any user | who am I |
| `POST /users` | admin | create a user |
| `POST /snapshots` | admin | upload a CSV as a new snapshot |
| `GET /snapshots` | any user | upload history |
| `GET /records` | any user | search and page through records (masked) |
| `GET /records/export` | any user | streamed CSV (masked) |
| `GET /records?unmasked=true` and export | admin | unmasked data, audited |
| `GET /audit` | admin | audit log |

Input columns: `external_id, full_name, email, phone, national_id, city, balance`.

## Tests

```bash
pytest
```

45 tests cover the points above, including: raw personal data never appearing in any
analyst response or export, role checks on every restricted route, expired and forged
tokens, the login rate limit, batch loading of 12,000 rows, bad-row reporting, search
wildcards treated literally, and the migration-versus-models check. That last check
caught a real mismatch while this was being written.

I also confirmed the tests can fail: switching masking off makes the leak tests fail.

## Limitations (what I would change for production)

- **Tests run on SQLite.** The models use plain SQLAlchemy types and are written to work
  on PostgreSQL too, but I have not run the suite against PostgreSQL here. SQLite has no
  native decimal type, so exact `NUMERIC` behaviour comes from PostgreSQL.
- **Refresh tokens are not revocable.** A stolen refresh token works until it expires.
  The fix is to store token IDs and rotate them.
- **The login rate limit is in memory,** so it is per process. With several workers,
  use a shared store such as Redis.
- **No HTTPS in the app.** Run it behind a TLS-terminating proxy such as NGINX.
- **Masking hides values; it does not anonymise.** Combined fields such as city and
  balance can still identify someone in a small dataset.
