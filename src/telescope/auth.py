"""
Authorization Server – ACE-OAuth inspired (RFC 9200).

This module implements a minimal Authorization Server (AS) that:
  * Authenticates clients using client_id + client_secret.
  * Issues JWT access tokens (RFC 7519) signed with ES256 (ECDSA P-256).
  * Supports token introspection (RFC 7662).
  * Maintains an in-memory revocation list (jti-based).

ACE-OAuth (RFC 9200) adapts OAuth 2.0 for constrained environments.  The full
ACE framework also defines a CBOR-encoded CWT (RFC 8392) for smaller tokens;
this implementation uses JSON JWTs for readability, but the same security
properties hold.

Scopes (telescope-specific):
  telescope:read   – read current RA/Dec position and device status
  telescope:slew   – issue slew-to-position commands
  telescope:admin  – manage device configuration; list active connections

Usage (standalone):
  python -m telescope.auth --port 8444 --cert certs/as.crt --key certs/as.key
"""

from __future__ import annotations

import logging
import time
import uuid
from pathlib import Path
from typing import Optional

import click
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from flask import Flask, jsonify, request

from telescope.protocol import TokenRequest, TokenResponse, IntrospectionResponse, VALID_SCOPES
from telescope.tls_config import server_tls_context

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory client registry (replace with a database in production)
# ---------------------------------------------------------------------------

# Clients: {client_id: {"secret": str, "allowed_scopes": set[str]}}
_REGISTERED_CLIENTS: dict[str, dict] = {
    "tracker-read": {
        "secret": "tracker-read-secret-00",
        "allowed_scopes": {"telescope:read"},
    },
    "tracker-full": {
        "secret": "tracker-full-secret-01",
        "allowed_scopes": {"telescope:read", "telescope:slew"},
    },
    "admin-client": {
        "secret": "admin-client-secret-02",
        "allowed_scopes": {"telescope:read", "telescope:slew", "telescope:admin"},
    },
}

# Revoked token JTIs (in-memory; cleared on restart)
_REVOKED_JTIS: set[str] = set()


# ---------------------------------------------------------------------------
# Token logic
# ---------------------------------------------------------------------------

def issue_token(
    client_id: str,
    scope: str,
    signing_key: EllipticCurvePrivateKey,
    as_url: str,
    rs_url: str,
    lifetime: int = 3600,
) -> str:
    """
    Issue a JWT access token for the given client and scope.

    The token is signed with ES256 (ECDSA P-256 + SHA-256) as recommended by
    RFC 7518 §3.4 for use in constrained environments.
    """
    now = int(time.time())
    jti = str(uuid.uuid4())
    payload = {
        "iss": as_url,
        "aud": rs_url,
        "sub": client_id,
        "scope": scope,
        "iat": now,
        "exp": now + lifetime,
        "jti": jti,
    }
    return jwt.encode(payload, signing_key, algorithm="ES256")


def verify_token(
    token: str,
    public_key: EllipticCurvePublicKey,
    as_url: str,
    rs_url: str,
) -> dict:
    """
    Verify and decode a JWT access token.

    Raises jwt.InvalidTokenError (or a subclass) on failure.
    """
    return jwt.decode(
        token,
        public_key,
        algorithms=["ES256"],
        audience=rs_url,
        issuer=as_url,
    )


def revoke_token(jti: str) -> None:
    """Add a token JTI to the revocation list."""
    _REVOKED_JTIS.add(jti)


def is_revoked(jti: str) -> bool:
    return jti in _REVOKED_JTIS


# ---------------------------------------------------------------------------
# Flask application factory
# ---------------------------------------------------------------------------

def create_auth_app(
    signing_key: EllipticCurvePrivateKey,
    as_url: str,
    rs_url: str,
    token_lifetime: int = 3600,
) -> Flask:
    """Create and configure the Authorization Server Flask app."""
    app = Flask(__name__)
    app.config["as_url"] = as_url
    app.config["rs_url"] = rs_url
    app.config["signing_key"] = signing_key
    app.config["token_lifetime"] = token_lifetime
    public_key = signing_key.public_key()

    # ------------------------------------------------------------------
    # POST /token  (RFC 6749 §4.4 – client credentials grant)
    # ------------------------------------------------------------------
    @app.post("/token")
    def token_endpoint():
        data = request.get_json(silent=True) or {}

        # Validate request
        try:
            req = TokenRequest(**data)
        except Exception:
            return jsonify({"error": "invalid_request", "error_description": "Malformed token request"}), 400

        # Authenticate client
        client = _REGISTERED_CLIENTS.get(req.client_id)
        if client is None or client["secret"] != req.client_secret:
            return jsonify({"error": "invalid_client"}), 401

        # Check requested scopes are allowed for this client
        requested = set(req.scope.split())
        if not requested.issubset(client["allowed_scopes"]):
            denied = requested - client["allowed_scopes"]
            return jsonify(
                {"error": "invalid_scope", "denied": list(denied)}
            ), 403

        token = issue_token(
            client_id=req.client_id,
            scope=req.scope,
            signing_key=app.config["signing_key"],
            as_url=app.config["as_url"],
            rs_url=app.config["rs_url"],
            lifetime=app.config["token_lifetime"],
        )
        resp = TokenResponse(access_token=token, scope=req.scope)
        return jsonify(resp.model_dump())

    # ------------------------------------------------------------------
    # POST /introspect  (RFC 7662)
    # ------------------------------------------------------------------
    @app.post("/introspect")
    def introspect_endpoint():
        token = (request.get_json(silent=True) or {}).get("token", "")
        if not token:
            return jsonify({"active": False}), 200

        try:
            claims = verify_token(token, public_key, app.config["as_url"], app.config["rs_url"])
        except jwt.InvalidTokenError:
            return jsonify({"active": False}), 200

        if is_revoked(claims.get("jti", "")):
            return jsonify({"active": False}), 200

        resp = IntrospectionResponse(
            active=True,
            scope=claims.get("scope"),
            client_id=claims.get("sub"),
            exp=claims.get("exp"),
            iat=claims.get("iat"),
            iss=claims.get("iss"),
            aud=claims.get("aud"),
            jti=claims.get("jti"),
        )
        return jsonify(resp.model_dump(exclude_none=True))

    # ------------------------------------------------------------------
    # POST /revoke  (RFC 7009 – token revocation)
    # ------------------------------------------------------------------
    @app.post("/revoke")
    def revoke_endpoint():
        token = (request.get_json(silent=True) or {}).get("token", "")
        if not token:
            return jsonify({"error": "invalid_request"}), 400
        try:
            claims = verify_token(token, public_key, app.config["as_url"], app.config["rs_url"])
            revoke_token(claims.get("jti", token))
        except jwt.InvalidTokenError:
            pass  # RFC 7009: always return 200
        return jsonify({}), 200

    # ------------------------------------------------------------------
    # GET /.well-known/oauth-authorization-server  (RFC 8414)
    # ------------------------------------------------------------------
    @app.get("/.well-known/oauth-authorization-server")
    def metadata():
        return jsonify({
            "issuer": app.config["as_url"],
            "token_endpoint": f"{app.config['as_url']}/token",
            "introspection_endpoint": f"{app.config['as_url']}/introspect",
            "revocation_endpoint": f"{app.config['as_url']}/revoke",
            "grant_types_supported": ["client_credentials"],
            "token_endpoint_auth_methods_supported": ["client_secret_post"],
            "scopes_supported": sorted(VALID_SCOPES),
        })

    return app


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

@click.command(name="auth-server")
@click.option("--port", default=8444, show_default=True, help="Listening port")
@click.option("--host", default="localhost", show_default=True)
@click.option("--cert", required=True, type=click.Path(exists=True), help="AS TLS certificate (PEM)")
@click.option("--key", required=True, type=click.Path(exists=True), help="AS TLS private key (PEM)")
@click.option("--rs-url", default="https://localhost:8443", show_default=True,
              help="Resource server URL (audience claim)")
@click.option("--token-lifetime", default=3600, show_default=True, help="Token lifetime in seconds")
def main(port, host, cert, key, rs_url, token_lifetime):
    """Run the ACE-OAuth Authorization Server (RFC 9200)."""
    logging.basicConfig(level=logging.INFO)

    # Load the signing key from the TLS certificate's private key
    key_bytes = Path(key).read_bytes()
    from cryptography.hazmat.serialization import load_pem_private_key  # type: ignore
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    signing_key = load_pem_private_key(key_bytes, password=None)

    as_url = f"https://{host}:{port}"
    app = create_auth_app(signing_key, as_url, rs_url, token_lifetime)

    tls_ctx = server_tls_context(cert, key)
    logger.info("Authorization Server listening on %s (TLS 1.3)", as_url)
    app.run(host=host, port=port, ssl_context=tls_ctx, debug=False)


if __name__ == "__main__":
    main()
