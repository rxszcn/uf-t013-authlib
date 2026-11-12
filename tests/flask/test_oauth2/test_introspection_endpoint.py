import pytest
from flask import json

from authlib.integrations.sqla_oauth2 import create_query_token_func
from authlib.oauth2.rfc7662 import IntrospectionEndpoint

from .models import Token
from .models import User
from .models import db
from .oauth2_server import create_basic_header

query_token = create_query_token_func(db.session, Token)


class MyIntrospectionEndpoint(IntrospectionEndpoint):
    def check_permission(self, token, client, request):
        return True

    def query_token(self, token, token_type_hint):
        return query_token(token, token_type_hint)

    def introspect_token(self, token):
        user = db.session.get(User, token.user_id)
        return {
            "active": True,
            "client_id": token.client_id,
            "username": user.username,
            "scope": token.scope,
            "sub": user.get_user_id(),
            "aud": token.client_id,
            "iss": "https://provider.test/",
            "exp": token.issued_at + token.expires_in,
            "iat": token.issued_at,
        }


@pytest.fixture(autouse=True)
def server(server, app):
    server.register_endpoint(MyIntrospectionEndpoint)

    @app.route("/oauth/introspect", methods=["POST"])
    def introspect_token():
        return server.create_endpoint_response("introspection")

    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["https://client.test/callback"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def test_invalid_client(test_client):
    rv = test_client.post("/oauth/introspect")
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"

    headers = {"Authorization": "invalid token_string"}
    rv = test_client.post("/oauth/introspect", headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"

    headers = create_basic_header("invalid-client", "client-secret")
    rv = test_client.post("/oauth/introspect", headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"

    headers = create_basic_header("client-id", "invalid-secret")
    rv = test_client.post("/oauth/introspect", headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"


def test_invalid_token(test_client):
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post("/oauth/introspect", headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"

    rv = test_client.post(
        "/oauth/introspect",
        data={
            "token_type_hint": "refresh_token",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"

    rv = test_client.post(
        "/oauth/introspect",
        data={
            "token": "a1",
            "token_type_hint": "unsupported_token_type",
        },
        headers=headers,
    )
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert "error" not in resp

    rv = test_client.post(
        "/oauth/introspect",
        data={
            "token": "invalid-token",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["active"] is False

    rv = test_client.post(
        "/oauth/introspect",
        data={
            "token": "a1",
            "token_type_hint": "refresh_token",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["active"] is False


def test_introspect_token_with_hint(test_client, token):
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/introspect",
        data={
            "token": "a1",
            "token_type_hint": "access_token",
        },
        headers=headers,
    )
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert resp["client_id"] == "client-id"


def test_introspect_token_without_hint(test_client, token):
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/introspect",
        data={
            "token": "a1",
        },
        headers=headers,
    )
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert resp["client_id"] == "client-id"


def test_introspect_token_with_wrong_hint(test_client, token):
    """Per RFC 7662 §2.1, the search is extended when the hint does not match."""
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/introspect",
        data={"token": token.refresh_token, "token_type_hint": "access_token"},
        headers=headers,
    )
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert resp["active"]


def test_introspect_token_with_unknown_hint(test_client, token):
    """Per RFC 7662 §2.1, an unknown token type hint is ignored."""
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/introspect",
        data={"token": "a1", "token_type_hint": "unknown"},
        headers=headers,
    )
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert resp["active"]


@pytest.fixture
def expired_access_token(db, monkeypatch):
    """A token record whose access token is expired while its refresh
    token is still valid."""
    issued_at = 1700000000
    monkeypatch.setattr("time.time", lambda: issued_at)
    token = Token(
        user_id=1,
        client_id="client-id",
        token_type="bearer",
        access_token="a2",
        refresh_token="r2",
        scope="profile",
        expires_in=3600,
    )
    db.session.add(token)
    db.session.commit()
    # move the clock past the access token lifetime
    monkeypatch.setattr("time.time", lambda: issued_at + 3601)
    yield token
    db.session.delete(token)
    db.session.commit()


def test_introspect_expired_access_token(test_client, expired_access_token):
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/introspect",
        data={"token": "a2"},
        headers=headers,
    )
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert resp["active"] is False


def test_introspect_refresh_token_with_expired_access_token(
    test_client, expired_access_token
):
    """An expired access token must not make its still valid refresh token
    introspect as inactive."""
    headers = create_basic_header("client-id", "client-secret")
    for data in (
        {"token": "r2"},
        {"token": "r2", "token_type_hint": "refresh_token"},
    ):
        rv = test_client.post(
            "/oauth/introspect",
            data=data,
            headers=headers,
        )
        assert rv.status_code == 200
        resp = json.loads(rv.data)
        assert resp["active"] is True
        assert resp["client_id"] == "client-id"


def test_introspect_revoked_refresh_token(test_client, db, expired_access_token):
    """A revoked refresh token introspects as inactive, even though refresh
    tokens have no lifetime of their own."""
    expired_access_token.refresh_token_revoked_at = 1700003601
    db.session.add(expired_access_token)
    db.session.commit()

    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/introspect",
        data={"token": "r2"},
        headers=headers,
    )
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert resp["active"] is False


def test_introspect_access_token_with_revoked_refresh_token(
    test_client, db, expired_access_token
):
    """The revocation cascade is unchanged: revoking the refresh token also
    invalidates the access token."""
    expired_access_token.refresh_token_revoked_at = 1700003601
    db.session.add(expired_access_token)
    db.session.commit()

    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/introspect",
        data={"token": "a2"},
        headers=headers,
    )
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert resp["active"] is False


def test_introspect_refresh_token_with_revoked_access_token(
    test_client, db, expired_access_token
):
    """The revocation semantics are unchanged: a record revoked on the
    access token side introspects as inactive."""
    expired_access_token.access_token_revoked_at = 1700003601
    db.session.add(expired_access_token)
    db.session.commit()

    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/introspect",
        data={"token": "r2"},
        headers=headers,
    )
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert resp["active"] is False
