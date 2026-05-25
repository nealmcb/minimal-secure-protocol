"""
Telescope Resource Server (RFC 9200 RS) over TLS 1.3 (RFC 8446).

This is the telescope mount side: it exposes a small REST API for reading
the current pointing position and issuing slew commands.  All endpoints
(except /mud) require a valid Bearer token issued by the Authorization Server.

API
---
  GET  /api/v1/position          – read current RA/Dec  (scope: telescope:read)
  POST /api/v1/slew              – slew to RA/Dec target (scope: telescope:slew)
  GET  /api/v1/status            – device status         (scope: telescope:read)
  POST /api/v1/admin/reset       – reset to home pos     (scope: telescope:admin)
  GET  /api/v1/admin/connections – list connections      (scope: telescope:admin)
  GET  /mud                      – MUD file URL redirect  (unauthenticated, RFC 8520)

Security
--------
* Transport: TLS 1.3 minimum (server_tls_context from tls_config.py).
* Auth: Bearer JWT validated locally with the AS public key (no round-trip
  introspection needed – good for constrained links).
* Privacy: RA/Dec values are NOT logged (RFC 6973 §6.1).

Usage:
  python -m telescope.server --port 8443 --cert certs/rs.crt --key certs/rs.key \\
      --as-cert certs/as.crt --as-url https://localhost:8444
"""

from __future__ import annotations

import logging
import time
from collections import deque
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Optional

import click
import jwt
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from flask import Flask, jsonify, request, g

from telescope.auth import verify_token, is_revoked
from telescope.protocol import (
    DeviceStatus,
    Position,
    SlewCommand,
    SlewResponse,
    TrackingMode,
)
from telescope.tls_config import server_tls_context

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Simulated telescope mount state
# ---------------------------------------------------------------------------

class TelescopeMountState:
    """In-memory simulation of a telescope mount."""

    def __init__(self, device_id: str = "mount-001"):
        self.device_id = device_id
        self.ra: float = 5.575  # Orion Nebula M42 RA (hours)
        self.dec: float = -5.39  # Orion Nebula M42 Dec (degrees)
        self.is_slewing: bool = False
        self.is_tracking: bool = True
        self.tracking_mode: TrackingMode = TrackingMode.SIDEREAL
        self.firmware_version: str = "0.1.0"
        self._start_time: float = time.time()
        self._connection_log: deque = deque(maxlen=100)

    @property
    def uptime_seconds(self) -> float:
        return time.time() - self._start_time

    def get_position(self) -> Position:
        return Position(ra=self.ra, dec=self.dec)

    def slew_to(self, ra: float, dec: float) -> None:
        # Simulate instant slew (no sleep needed for testing)
        self.is_slewing = True
        self.ra = ra
        self.dec = dec
        self.is_slewing = False

    def get_status(self) -> DeviceStatus:
        return DeviceStatus(
            device_id=self.device_id,
            is_slewing=self.is_slewing,
            is_tracking=self.is_tracking,
            tracking_mode=self.tracking_mode,
            position=self.get_position(),
            firmware_version=self.firmware_version,
            uptime_seconds=self.uptime_seconds,
        )

    def log_connection(self, client_id: str, endpoint: str) -> None:
        self._connection_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "client_id": client_id,
            "endpoint": endpoint,
        })

    def list_connections(self) -> list:
        return list(self._connection_log)

    def reset(self) -> None:
        self.ra = 0.0
        self.dec = 0.0
        self.is_slewing = False
        self.is_tracking = False


# ---------------------------------------------------------------------------
# Flask application factory
# ---------------------------------------------------------------------------

def create_resource_server_app(
    mount: TelescopeMountState,
    as_public_key,
    as_url: str,
    rs_url: str,
    mud_url: str = "",
) -> Flask:
    """Create and configure the telescope Resource Server Flask app."""
    app = Flask(__name__)
    app.config["as_public_key"] = as_public_key
    app.config["as_url"] = as_url
    app.config["rs_url"] = rs_url
    app.config["mud_url"] = mud_url
    app.config["mount"] = mount

    # ------------------------------------------------------------------
    # Bearer token authentication decorator
    # ------------------------------------------------------------------

    def require_scope(*required_scopes: str):
        """Decorator: verify Bearer token and check that a scope is present."""
        def decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                auth_header = request.headers.get("Authorization", "")
                if not auth_header.startswith("Bearer "):
                    return jsonify({"error": "unauthorized", "description": "Missing Bearer token"}), 401
                token = auth_header.removeprefix("Bearer ").strip()
                try:
                    claims = verify_token(
                        token,
                        app.config["as_public_key"],
                        app.config["as_url"],
                        app.config["rs_url"],
                    )
                except jwt.ExpiredSignatureError:
                    return jsonify({"error": "token_expired"}), 401
                except jwt.InvalidTokenError:
                    return jsonify({"error": "invalid_token", "description": "Token validation failed"}), 401

                if is_revoked(claims.get("jti", "")):
                    return jsonify({"error": "token_revoked"}), 401

                token_scopes = set(claims.get("scope", "").split())
                for scope in required_scopes:
                    if scope not in token_scopes:
                        return jsonify({"error": "insufficient_scope", "required": scope}), 403

                g.claims = claims
                g.client_id = claims.get("sub", "unknown")
                return f(*args, **kwargs)
            return wrapper
        return decorator

    # ------------------------------------------------------------------
    # Telescope API endpoints
    # ------------------------------------------------------------------

    @app.get("/api/v1/position")
    @require_scope("telescope:read")
    def get_position():
        """
        Read the current telescope pointing position.

        Returns RA (decimal hours) and Dec (decimal degrees).
        Privacy note (RFC 6973): position values are not logged server-side.
        """
        mount.log_connection(g.client_id, "GET /position")
        pos = mount.get_position()
        return jsonify(pos.model_dump())

    @app.post("/api/v1/slew")
    @require_scope("telescope:slew")
    def post_slew():
        """
        Issue a slew command to move the telescope to a new RA/Dec target.

        Body (JSON): {"ra": <hours>, "dec": <degrees>}
        """
        data = request.get_json(silent=True) or {}
        try:
            cmd = SlewCommand(**data)
        except Exception:
            return jsonify({"error": "invalid_request", "description": "Invalid slew parameters"}), 400

        mount.log_connection(g.client_id, "POST /slew")
        mount.slew_to(cmd.ra, cmd.dec)
        resp = SlewResponse(
            accepted=True,
            message=f"Slewing to RA={cmd.ra:.4f}h Dec={cmd.dec:.4f}°",
            target_ra=cmd.ra,
            target_dec=cmd.dec,
        )
        return jsonify(resp.model_dump())

    @app.get("/api/v1/status")
    @require_scope("telescope:read")
    def get_status():
        """Return device status (slewing, tracking mode, firmware version, etc.)."""
        mount.log_connection(g.client_id, "GET /status")
        status = mount.get_status()
        return jsonify(status.model_dump())

    @app.post("/api/v1/admin/reset")
    @require_scope("telescope:admin")
    def post_admin_reset():
        """Reset the telescope to the home position (RA=0, Dec=0)."""
        mount.log_connection(g.client_id, "POST /admin/reset")
        mount.reset()
        return jsonify({"message": "Mount reset to home position (RA=0, Dec=0)"})

    @app.get("/api/v1/admin/connections")
    @require_scope("telescope:admin")
    def get_admin_connections():
        """Return a log of recent API connections (client_id + endpoint only)."""
        mount.log_connection(g.client_id, "GET /admin/connections")
        return jsonify({"connections": mount.list_connections()})

    # ------------------------------------------------------------------
    # MUD URL redirect (RFC 8520 §2 – device self-description)
    # ------------------------------------------------------------------

    @app.get("/mud")
    def mud_redirect():
        """
        Return the MUD file URL for this device (RFC 8520 §1.9).

        The MUD URL is typically embedded in a DHCP option (option 161) or
        TLS extension (RFC 8520 §3.3); this endpoint provides it via HTTP
        as a fallback for networks that don't support DHCP MUD options.
        """
        mud = app.config.get("mud_url", "")
        if mud:
            return jsonify({"mud_url": mud})
        return jsonify({"mud_url": f"{rs_url}/mud/telescope-mount.mud.json"})

    return app


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

@click.command(name="telescope-server")
@click.option("--port", default=8443, show_default=True, help="Listening port")
@click.option("--host", default="localhost", show_default=True)
@click.option("--cert", required=True, type=click.Path(exists=True), help="RS TLS certificate (PEM)")
@click.option("--key", required=True, type=click.Path(exists=True), help="RS TLS private key (PEM)")
@click.option("--as-cert", required=True, type=click.Path(exists=True), help="AS certificate (for token verification)")
@click.option("--as-url", default="https://localhost:8444", show_default=True, help="Authorization server URL")
@click.option("--device-id", default="mount-001", show_default=True)
@click.option("--mud-url", default="", help="MUD file URL (RFC 8520)")
def main(port, host, cert, key, as_cert, as_url, device_id, mud_url):
    """Run the telescope Resource Server over TLS 1.3."""
    logging.basicConfig(level=logging.INFO)

    # Load AS public key from its certificate
    from cryptography import x509
    as_cert_data = Path(as_cert).read_bytes()
    as_x509 = x509.load_pem_x509_certificate(as_cert_data)
    as_public_key = as_x509.public_key()

    rs_url = f"https://{host}:{port}"
    mount = TelescopeMountState(device_id=device_id)
    app = create_resource_server_app(mount, as_public_key, as_url, rs_url, mud_url)
    tls_ctx = server_tls_context(cert, key)

    logger.info("Telescope Resource Server listening on %s (TLS 1.3)", rs_url)
    app.run(host=host, port=port, ssl_context=tls_ctx, debug=False)


if __name__ == "__main__":
    main()
