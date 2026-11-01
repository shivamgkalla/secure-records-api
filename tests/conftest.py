import io

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from secure_records.config import Settings
from secure_records.main import create_app, init_schema
from secure_records.models import User
from secure_records.security import hash_password
from secure_records.synthetic import generate_rows

SECRET = "test-secret-" + "x" * 40
ADMIN = ("admin@example.com", "admin-password-123")
ANALYST = ("analyst@example.com", "analyst-password-123")


def csv_bytes(rows, header=None) -> bytes:
    import csv

    rows = list(rows)
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=header or list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue().encode()


def make_app(**overrides):
    settings = Settings(
        secret_key=SECRET, database_url="sqlite:///:memory:", rate_limit_enabled=False, **overrides
    )
    app = create_app(settings)
    init_schema(app)
    with app.state.sessionmaker() as db:
        db.add(User(email=ADMIN[0], password_hash=hash_password(ADMIN[1]), role="admin"))
        db.add(User(email=ANALYST[0], password_hash=hash_password(ANALYST[1]), role="analyst"))
        db.commit()
    return app


@pytest.fixture()
def app():
    return make_app()


@pytest.fixture()
def client(app):
    return TestClient(app)


def login(client, creds):
    r = client.post("/auth/login", json={"email": creds[0], "password": creds[1]})
    assert r.status_code == 200, r.text
    return r.json()


def auth(client, creds):
    return {"Authorization": f"Bearer {login(client, creds)['access_token']}"}


@pytest.fixture()
def admin_h(client):
    return auth(client, ADMIN)


@pytest.fixture()
def analyst_h(client):
    return auth(client, ANALYST)


@pytest.fixture()
def loaded(client, admin_h):
    """A snapshot of 300 synthetic records, uploaded by the admin."""
    rows = list(generate_rows(300, seed=5))
    r = client.post("/snapshots", headers=admin_h, files={"file": ("a.csv", csv_bytes(rows), "text/csv")})
    assert r.status_code == 201, r.text
    return {"rows": rows, "snapshot_id": r.json()["snapshot_id"]}
