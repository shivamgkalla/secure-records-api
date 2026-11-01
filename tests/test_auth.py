from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from secure_records.models import User
from secure_records.security import create_token
from tests.conftest import ADMIN, ANALYST, SECRET, auth, login, make_app


def test_login_returns_working_tokens(client):
    tokens = login(client, ADMIN)
    me = client.get("/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert me.json()["email"] == ADMIN[0] and me.json()["role"] == "admin"


@pytest.mark.parametrize("email, password", [(ADMIN[0], "wrong-password-1"), ("nobody@example.com", "whatever-123456")])
def test_bad_credentials_give_the_same_error(client, email, password):
    r = client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 401
    assert r.json()["detail"] == "Incorrect email or password."   # does not reveal which part was wrong


def test_protected_routes_need_a_token(client):
    for path in ("/auth/me", "/records", "/snapshots", "/audit"):
        assert client.get(path).status_code == 401


def test_garbage_and_wrong_type_tokens_are_rejected(client):
    assert client.get("/auth/me", headers={"Authorization": "Bearer not.a.token"}).status_code == 401
    refresh = login(client, ADMIN)["refresh_token"]
    r = client.get("/auth/me", headers={"Authorization": f"Bearer {refresh}"})
    assert r.status_code == 401 and "access token" in r.json()["detail"]    # refresh token cannot be used as access


def test_expired_token_is_rejected(app, client):
    user = User(id=1, email="x", password_hash="x", role="admin")
    old = create_token(user, "access", SECRET, timedelta(seconds=-5))
    r = client.get("/auth/me", headers={"Authorization": f"Bearer {old}"})
    assert r.status_code == 401 and "expired" in r.json()["detail"]


def test_token_signed_with_another_key_is_rejected(client):
    forged = create_token(User(id=1, email="x", password_hash="x", role="admin"), "access", "z" * 40, timedelta(minutes=5))
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_refresh_issues_a_new_working_pair(client):
    tokens = login(client, ANALYST)
    r = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 200
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {r.json()['access_token']}"}).status_code == 200
    # an access token is not accepted by the refresh endpoint
    assert client.post("/auth/refresh", json={"refresh_token": tokens["access_token"]}).status_code == 401


def test_disabled_user_loses_access_immediately(app, client):
    headers = auth(client, ANALYST)
    with app.state.sessionmaker() as db:
        db.query(User).filter_by(email=ANALYST[0]).update({"is_active": False})
        db.commit()
    assert client.get("/auth/me", headers=headers).status_code == 401
    assert client.post("/auth/login", json={"email": ANALYST[0], "password": ANALYST[1]}).status_code == 401


def test_only_admins_can_create_users_and_roles_are_checked(client, admin_h, analyst_h):
    body = {"email": "new@example.com", "password": "a-long-enough-password", "role": "analyst"}
    assert client.post("/users", json=body, headers=analyst_h).status_code == 403
    assert client.post("/users", json=body, headers=admin_h).status_code == 201
    assert client.post("/users", json=body, headers=admin_h).status_code == 409           # duplicate
    assert client.post("/users", json={**body, "email": "b@example.com", "role": "root"}, headers=admin_h).status_code == 422
    assert client.post("/users", json={**body, "email": "c@example.com", "password": "short"}, headers=admin_h).status_code == 422
    assert client.post("/users", json={**body, "email": "d@example.com", "password": "é" * 40}, headers=admin_h).status_code == 422  # > 72 bytes


def test_login_is_rate_limited():
    limited = TestClient(make_app.__wrapped__() if hasattr(make_app, "__wrapped__") else _limited_app())
    codes = [
        limited.post("/auth/login", json={"email": ADMIN[0], "password": "wrong-password-1"}).status_code
        for _ in range(7)
    ]
    assert codes[:5] == [401] * 5 and codes[5:] == [429, 429]


def _limited_app():
    from secure_records.config import Settings
    from secure_records.main import create_app, init_schema

    app = create_app(Settings(secret_key=SECRET, database_url="sqlite:///:memory:", rate_limit_enabled=True))
    init_schema(app)
    return app


def test_failed_and_successful_logins_are_audited(client, admin_h):
    client.post("/auth/login", json={"email": ADMIN[0], "password": "wrong-password-1"})
    log = client.get("/audit", headers=admin_h).json()
    actions = [a["action"] for a in log]
    assert "login_ok" in actions and "login_failed" in actions
    assert all("wrong-password" not in a["detail"] for a in log)       # passwords never reach the log
