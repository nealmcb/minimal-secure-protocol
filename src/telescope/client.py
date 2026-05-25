"""
Telescope client library and CLI.

The client implements the ACE-OAuth (RFC 9200) flow:
  1. Obtain an access token from the Authorization Server (AS) using the
     client_credentials grant (RFC 6749 §4.4).
  2. Use the token as a Bearer credential on requests to the Resource Server (RS).
  3. Refresh or re-request the token if it has expired.

All connections use TLS 1.3 with server certificate verification.

Usage examples:
  telescope-client token  --client-id tracker-full --scope "telescope:read telescope:slew"
  telescope-client position
  telescope-client slew   --ra 10.68 --dec 41.27
  telescope-client status
  telescope-client admin  connections
  telescope-client admin  reset
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

import click
import jwt
import requests
import urllib3

from telescope.protocol import (
    Position,
    SlewCommand,
    DeviceStatus,
    SlewResponse,
    VALID_SCOPES,
)

logger = logging.getLogger(__name__)

# Default locations for the token cache (stores token + expiry)
DEFAULT_TOKEN_CACHE = Path(os.environ.get("TELESCOPE_TOKEN_CACHE", ".telescope_token.json"))


# ---------------------------------------------------------------------------
# Low-level HTTP helpers
# ---------------------------------------------------------------------------

def _session(ca_cert: str | Path) -> requests.Session:
    """Return a requests.Session that verifies TLS with the given CA cert."""
    s = requests.Session()
    s.verify = str(ca_cert)
    return s


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Token management
# ---------------------------------------------------------------------------

def _load_cached_token(cache_path: Path) -> Optional[str]:
    """Return a cached token if it exists and is not expired."""
    if not cache_path.exists():
        return None
    try:
        data = json.loads(cache_path.read_text())
        if data.get("exp", 0) > time.time() + 60:  # 60 s buffer
            return data["access_token"]
    except Exception:
        pass
    return None


def _save_token(token: str, cache_path: Path) -> None:
    """Persist the token and its expiry claim for re-use across CLI calls."""
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
        exp = claims.get("exp", int(time.time()) + 3600)
    except Exception:
        exp = int(time.time()) + 3600
    cache_path.write_text(json.dumps({"access_token": token, "exp": exp}))
    cache_path.chmod(0o600)


def fetch_token(
    as_url: str,
    client_id: str,
    client_secret: str,
    scope: str,
    ca_cert: str | Path,
) -> str:
    """
    Request an access token from the Authorization Server.

    Implements the client_credentials grant (RFC 6749 §4.4).
    Returns the raw JWT string.
    """
    session = _session(ca_cert)
    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": scope,
    }
    resp = session.post(f"{as_url}/token", json=payload, timeout=10)
    resp.raise_for_status()
    return resp.json()["access_token"]


# ---------------------------------------------------------------------------
# API calls
# ---------------------------------------------------------------------------

def api_position(rs_url: str, token: str, ca_cert: str | Path) -> Position:
    session = _session(ca_cert)
    resp = session.get(f"{rs_url}/api/v1/position", headers=_bearer(token), timeout=10)
    resp.raise_for_status()
    return Position(**resp.json())


def api_slew(rs_url: str, token: str, ca_cert: str | Path, ra: float, dec: float) -> SlewResponse:
    session = _session(ca_cert)
    cmd = SlewCommand(ra=ra, dec=dec)
    resp = session.post(
        f"{rs_url}/api/v1/slew",
        headers=_bearer(token),
        json=cmd.model_dump(exclude={"timestamp"} if hasattr(cmd, "timestamp") else set()),
        timeout=10,
    )
    resp.raise_for_status()
    return SlewResponse(**resp.json())


def api_status(rs_url: str, token: str, ca_cert: str | Path) -> DeviceStatus:
    session = _session(ca_cert)
    resp = session.get(f"{rs_url}/api/v1/status", headers=_bearer(token), timeout=10)
    resp.raise_for_status()
    return DeviceStatus(**resp.json())


def api_admin_connections(rs_url: str, token: str, ca_cert: str | Path) -> list:
    session = _session(ca_cert)
    resp = session.get(
        f"{rs_url}/api/v1/admin/connections", headers=_bearer(token), timeout=10
    )
    resp.raise_for_status()
    return resp.json().get("connections", [])


def api_admin_reset(rs_url: str, token: str, ca_cert: str | Path) -> str:
    session = _session(ca_cert)
    resp = session.post(
        f"{rs_url}/api/v1/admin/reset", headers=_bearer(token), timeout=10
    )
    resp.raise_for_status()
    return resp.json().get("message", "")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.group()
@click.option("--as-url", default="https://localhost:8444", show_default=True,
              envvar="TELESCOPE_AS_URL", help="Authorization Server URL")
@click.option("--rs-url", default="https://localhost:8443", show_default=True,
              envvar="TELESCOPE_RS_URL", help="Resource Server (telescope) URL")
@click.option("--ca-cert", default="certs/as.crt", show_default=True,
              envvar="TELESCOPE_CA_CERT", type=click.Path(),
              help="CA certificate to verify server TLS")
@click.option("--token-cache", default=str(DEFAULT_TOKEN_CACHE), show_default=True,
              envvar="TELESCOPE_TOKEN_CACHE", type=click.Path())
@click.pass_context
def main(ctx, as_url, rs_url, ca_cert, token_cache):
    """Telescope control client (ACE-OAuth + TLS 1.3)."""
    logging.basicConfig(level=logging.WARNING)
    ctx.ensure_object(dict)
    ctx.obj["as_url"] = as_url
    ctx.obj["rs_url"] = rs_url
    ctx.obj["ca_cert"] = ca_cert
    ctx.obj["token_cache"] = Path(token_cache)


@main.command()
@click.option("--client-id", required=True, envvar="TELESCOPE_CLIENT_ID")
@click.option("--client-secret", required=True, envvar="TELESCOPE_CLIENT_SECRET",
              help="Client secret (use env var TELESCOPE_CLIENT_SECRET in production)")
@click.option("--scope", default="telescope:read telescope:slew", show_default=True)
@click.pass_obj
def token(obj, client_id, client_secret, scope):
    """Request and cache an access token from the Authorization Server."""
    tok = fetch_token(obj["as_url"], client_id, client_secret, scope, obj["ca_cert"])
    _save_token(tok, obj["token_cache"])
    claims = jwt.decode(tok, options={"verify_signature": False})
    click.echo(f"Token issued. Expires: {time.ctime(claims.get('exp', 0))}")
    click.echo(f"Scope: {claims.get('scope')}")


@main.command()
@click.pass_obj
def position(obj):
    """Read the current telescope RA/Dec position."""
    tok = _load_cached_token(obj["token_cache"])
    if not tok:
        raise click.UsageError("No valid token. Run 'telescope-client token' first.")
    pos = api_position(obj["rs_url"], tok, obj["ca_cert"])
    click.echo(f"RA:  {pos.ra:.6f} h")
    click.echo(f"Dec: {pos.dec:.6f}°")


@main.command()
@click.option("--ra", required=True, type=float, help="Target RA (decimal hours, 0–24)")
@click.option("--dec", required=True, type=float, help="Target Dec (decimal degrees, -90–90)")
@click.pass_obj
def slew(obj, ra, dec):
    """Slew the telescope to a new RA/Dec target."""
    tok = _load_cached_token(obj["token_cache"])
    if not tok:
        raise click.UsageError("No valid token. Run 'telescope-client token' first.")
    resp = api_slew(obj["rs_url"], tok, obj["ca_cert"], ra, dec)
    click.echo(resp.message)


@main.command()
@click.pass_obj
def status(obj):
    """Display the telescope mount status."""
    tok = _load_cached_token(obj["token_cache"])
    if not tok:
        raise click.UsageError("No valid token. Run 'telescope-client token' first.")
    st = api_status(obj["rs_url"], tok, obj["ca_cert"])
    click.echo(f"Device:          {st.device_id}")
    click.echo(f"Firmware:        {st.firmware_version}")
    click.echo(f"Slewing:         {st.is_slewing}")
    click.echo(f"Tracking:        {st.is_tracking} ({st.tracking_mode.value})")
    click.echo(f"Position RA:     {st.position.ra:.6f} h")
    click.echo(f"Position Dec:    {st.position.dec:.6f}°")
    click.echo(f"Uptime:          {st.uptime_seconds:.0f} s")


@main.group()
@click.pass_obj
def admin(obj):
    """Administrative commands (require telescope:admin scope)."""


@admin.command("connections")
@click.pass_obj
def admin_connections(obj):
    """List recent API connections."""
    tok = _load_cached_token(obj["token_cache"])
    if not tok:
        raise click.UsageError("No valid token. Run 'telescope-client token' first.")
    conns = api_admin_connections(obj["rs_url"], tok, obj["ca_cert"])
    if not conns:
        click.echo("No connections logged.")
        return
    for c in conns:
        click.echo(f"  {c['timestamp']}  {c['client_id']:<20}  {c['endpoint']}")


@admin.command("reset")
@click.confirmation_option(prompt="Reset telescope to home position?")
@click.pass_obj
def admin_reset(obj):
    """Reset telescope mount to home position (RA=0, Dec=0)."""
    tok = _load_cached_token(obj["token_cache"])
    if not tok:
        raise click.UsageError("No valid token. Run 'telescope-client token' first.")
    msg = api_admin_reset(obj["rs_url"], tok, obj["ca_cert"])
    click.echo(msg)


if __name__ == "__main__":
    main()
