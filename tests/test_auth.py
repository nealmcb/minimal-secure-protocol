"""
Tests for the Authorization Server (auth.py) and Resource Server (server.py).

These tests use Flask test clients (no real TLS / TCP) to exercise the
ACE-OAuth token issuance, introspection, revocation, and the telescope API
endpoints with scope enforcement.
"""

from __future__ import annotations

import time

import pytest

from telescope.auth import issue_token, verify_token, revoke_token, is_revoked, _REVOKED_JTIS


# ===========================================================================
# Authorization Server tests
# ===========================================================================

class TestTokenEndpoint:
    def test_issue_token_read_scope(self, auth_client):
        resp = auth_client.post("/token", json={
            "grant_type": "client_credentials",
            "client_id": "tracker-read",
            "client_secret": "tracker-read-secret-00",
            "scope": "telescope:read",
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert "access_token" in data
        assert data["scope"] == "telescope:read"
        assert data["token_type"] == "Bearer"
        assert data["expires_in"] == 3600

    def test_issue_token_full_scope(self, auth_client):
        resp = auth_client.post("/token", json={
            "grant_type": "client_credentials",
            "client_id": "tracker-full",
            "client_secret": "tracker-full-secret-01",
            "scope": "telescope:read telescope:slew",
        })
        assert resp.status_code == 200

    def test_wrong_client_secret(self, auth_client):
        resp = auth_client.post("/token", json={
            "grant_type": "client_credentials",
            "client_id": "tracker-read",
            "client_secret": "wrong-secret",
            "scope": "telescope:read",
        })
        assert resp.status_code == 401
        assert resp.get_json()["error"] == "invalid_client"

    def test_unknown_client(self, auth_client):
        resp = auth_client.post("/token", json={
            "grant_type": "client_credentials",
            "client_id": "nobody",
            "client_secret": "doesnotmatter",
            "scope": "telescope:read",
        })
        assert resp.status_code == 401

    def test_scope_exceeds_client_permissions(self, auth_client):
        # tracker-read is not allowed telescope:slew
        resp = auth_client.post("/token", json={
            "grant_type": "client_credentials",
            "client_id": "tracker-read",
            "client_secret": "tracker-read-secret-00",
            "scope": "telescope:read telescope:slew",
        })
        assert resp.status_code == 403
        assert resp.get_json()["error"] == "invalid_scope"

    def test_missing_grant_type(self, auth_client):
        resp = auth_client.post("/token", json={
            "client_id": "tracker-read",
            "client_secret": "tracker-read-secret-00",
        })
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "invalid_request"

    def test_unknown_scope_in_request(self, auth_client):
        resp = auth_client.post("/token", json={
            "grant_type": "client_credentials",
            "client_id": "admin-client",
            "client_secret": "admin-client-secret-02",
            "scope": "telescope:destroy",
        })
        assert resp.status_code == 400  # ValidationError in TokenRequest


class TestIntrospectionEndpoint:
    def test_active_token(self, auth_client, as_signing_key, as_url, rs_url):
        token = issue_token("test", "telescope:read", as_signing_key, as_url, rs_url)
        resp = auth_client.post("/introspect", json={"token": token})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["active"] is True
        assert data["scope"] == "telescope:read"
        assert data["client_id"] == "test"

    def test_invalid_token(self, auth_client):
        resp = auth_client.post("/introspect", json={"token": "not.a.token"})
        assert resp.status_code == 200
        assert resp.get_json()["active"] is False

    def test_missing_token(self, auth_client):
        resp = auth_client.post("/introspect", json={})
        assert resp.status_code == 200
        assert resp.get_json()["active"] is False


class TestRevocationEndpoint:
    def test_revoke_token(self, auth_client, as_signing_key, as_url, rs_url):
        token = issue_token("test-revoke", "telescope:read", as_signing_key, as_url, rs_url)

        # Before revocation: active
        resp = auth_client.post("/introspect", json={"token": token})
        assert resp.get_json()["active"] is True

        # Revoke
        rev_resp = auth_client.post("/revoke", json={"token": token})
        assert rev_resp.status_code == 200

        # After revocation: inactive
        resp2 = auth_client.post("/introspect", json={"token": token})
        assert resp2.get_json()["active"] is False

    def test_revoke_invalid_token_returns_200(self, auth_client):
        # RFC 7009: always return 200 even for invalid tokens
        resp = auth_client.post("/revoke", json={"token": "garbage"})
        assert resp.status_code == 200


class TestASMetadata:
    def test_metadata_endpoint(self, auth_client, as_url):
        resp = auth_client.get("/.well-known/oauth-authorization-server")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["issuer"] == as_url
        assert "token_endpoint" in data
        assert "grant_types_supported" in data
        assert "client_credentials" in data["grant_types_supported"]


# ===========================================================================
# Resource Server tests
# ===========================================================================

def _get_token(auth_client, client_id, secret, scope):
    resp = auth_client.post("/token", json={
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": secret,
        "scope": scope,
    })
    assert resp.status_code == 200
    return resp.get_json()["access_token"]


class TestPositionEndpoint:
    def test_get_position_with_read_token(self, auth_client, rs_client):
        client, mount = rs_client
        token = _get_token(auth_client, "tracker-read", "tracker-read-secret-00", "telescope:read")
        resp = client.get("/api/v1/position", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert "ra" in data
        assert "dec" in data
        assert 0.0 <= data["ra"] < 24.0
        assert -90.0 <= data["dec"] <= 90.0

    def test_get_position_no_token(self, rs_client):
        client, _ = rs_client
        resp = client.get("/api/v1/position")
        assert resp.status_code == 401

    def test_get_position_bad_token(self, rs_client):
        client, _ = rs_client
        resp = client.get("/api/v1/position", headers={"Authorization": "Bearer bad.token.here"})
        assert resp.status_code == 401


class TestSlewEndpoint:
    def test_slew_with_slew_scope(self, auth_client, rs_client):
        client, mount = rs_client
        token = _get_token(
            auth_client, "tracker-full", "tracker-full-secret-01",
            "telescope:read telescope:slew"
        )
        resp = client.post(
            "/api/v1/slew",
            json={"ra": 10.68, "dec": 41.27},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["accepted"] is True
        assert data["target_ra"] == pytest.approx(10.68)
        assert data["target_dec"] == pytest.approx(41.27)
        # Mount state updated
        assert mount.ra == pytest.approx(10.68)
        assert mount.dec == pytest.approx(41.27)

    def test_slew_requires_slew_scope(self, auth_client, rs_client):
        client, _ = rs_client
        # tracker-read has only telescope:read – not telescope:slew
        token = _get_token(auth_client, "tracker-read", "tracker-read-secret-00", "telescope:read")
        resp = client.post(
            "/api/v1/slew",
            json={"ra": 5.0, "dec": 0.0},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403
        assert "insufficient_scope" in resp.get_json()["error"]

    def test_slew_invalid_coordinates(self, auth_client, rs_client):
        client, _ = rs_client
        token = _get_token(
            auth_client, "tracker-full", "tracker-full-secret-01",
            "telescope:read telescope:slew"
        )
        resp = client.post(
            "/api/v1/slew",
            json={"ra": 25.0, "dec": 0.0},  # RA out of range
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 400

    def test_slew_missing_fields(self, auth_client, rs_client):
        client, _ = rs_client
        token = _get_token(
            auth_client, "tracker-full", "tracker-full-secret-01",
            "telescope:read telescope:slew"
        )
        resp = client.post(
            "/api/v1/slew",
            json={"ra": 5.0},  # missing dec
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 400


class TestStatusEndpoint:
    def test_get_status(self, auth_client, rs_client):
        client, mount = rs_client
        token = _get_token(auth_client, "tracker-read", "tracker-read-secret-00", "telescope:read")
        resp = client.get("/api/v1/status", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["device_id"] == "test-mount"
        assert "firmware_version" in data
        assert "tracking_mode" in data


class TestAdminEndpoints:
    def test_admin_connections_requires_admin_scope(self, auth_client, rs_client):
        client, _ = rs_client
        # tracker-read does not have telescope:admin
        token = _get_token(auth_client, "tracker-read", "tracker-read-secret-00", "telescope:read")
        resp = client.get(
            "/api/v1/admin/connections",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    def test_admin_connections_with_admin_token(self, auth_client, rs_client):
        client, _ = rs_client
        token = _get_token(
            auth_client, "admin-client", "admin-client-secret-02",
            "telescope:read telescope:slew telescope:admin"
        )
        resp = client.get(
            "/api/v1/admin/connections",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert "connections" in resp.get_json()

    def test_admin_reset(self, as_signing_key, as_url, rs_url, rs_client):
        client, mount = rs_client
        # Issue tokens directly (avoids interleaving two Flask test clients)
        slew_token = issue_token(
            "tracker-full", "telescope:read telescope:slew", as_signing_key, as_url, rs_url
        )
        client.post(
            "/api/v1/slew",
            json={"ra": 5.0, "dec": 30.0},
            headers={"Authorization": f"Bearer {slew_token}"},
        )
        assert mount.ra == pytest.approx(5.0)

        admin_token = issue_token(
            "admin-client", "telescope:read telescope:slew telescope:admin",
            as_signing_key, as_url, rs_url
        )
        resp = client.post(
            "/api/v1/admin/reset",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        assert mount.ra == 0.0
        assert mount.dec == 0.0


class TestMUDEndpoint:
    def test_mud_endpoint_no_auth_required(self, rs_client):
        client, _ = rs_client
        resp = client.get("/mud")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "mud_url" in data


class TestRevokedTokenRejected:
    def test_revoked_token_rejected_by_rs(self, as_signing_key, as_url, rs_url, rs_client):
        client, _ = rs_client
        # Issue and immediately revoke a token using module functions directly
        # (avoids interleaving two Flask test clients in the same context)
        token = issue_token("tracker-read", "telescope:read", as_signing_key, as_url, rs_url)

        # Token works before revocation
        resp = client.get("/api/v1/position", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200

        # Revoke the token by its JTI
        import jwt as _jwt
        claims = _jwt.decode(token, options={"verify_signature": False})
        revoke_token(claims["jti"])

        # Token should now be rejected by RS (shared in-memory revocation list)
        resp2 = client.get("/api/v1/position", headers={"Authorization": f"Bearer {token}"})
        assert resp2.status_code == 401
        assert "revoked" in resp2.get_json()["error"]
