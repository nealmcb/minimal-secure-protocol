"""
Admin CLI for the telescope authorization server.

Provides administrative operations:
  - List registered clients
  - Revoke a token by JTI or raw token
  - Check token introspection
  - View the AS metadata (RFC 8414)

Usage:
  python scripts/admin.py --as-url https://localhost:8444 --ca-cert certs/ca.crt <command>

Security note: admin operations that mutate server state (revoke) require the
  admin-client credentials (telescope:admin scope).  Read-only introspection
  requires telescope:read.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import click
import requests


def _session(ca_cert: str) -> requests.Session:
    s = requests.Session()
    s.verify = ca_cert
    return s


@click.group()
@click.option("--as-url", default="https://localhost:8444", show_default=True,
              envvar="TELESCOPE_AS_URL")
@click.option("--rs-url", default="https://localhost:8443", show_default=True,
              envvar="TELESCOPE_RS_URL")
@click.option("--ca-cert", default="certs/ca.crt", show_default=True,
              envvar="TELESCOPE_CA_CERT", type=click.Path())
@click.pass_context
def main(ctx, as_url, rs_url, ca_cert):
    """Admin interface for the telescope authorization and resource servers."""
    ctx.ensure_object(dict)
    ctx.obj["as_url"] = as_url
    ctx.obj["rs_url"] = rs_url
    ctx.obj["ca_cert"] = ca_cert


# ---------------------------------------------------------------------------
# AS metadata
# ---------------------------------------------------------------------------

@main.command()
@click.pass_obj
def metadata(obj):
    """Display the Authorization Server metadata (RFC 8414)."""
    s = _session(obj["ca_cert"])
    resp = s.get(f"{obj['as_url']}/.well-known/oauth-authorization-server", timeout=10)
    resp.raise_for_status()
    click.echo(json.dumps(resp.json(), indent=2))


# ---------------------------------------------------------------------------
# Token operations
# ---------------------------------------------------------------------------

@main.command()
@click.argument("client_id")
@click.argument("client_secret")
@click.option("--scope", default="telescope:admin", show_default=True)
@click.pass_obj
def issue_token(obj, client_id, client_secret, scope):
    """Issue an access token for CLIENT_ID using CLIENT_SECRET."""
    s = _session(obj["ca_cert"])
    resp = s.post(
        f"{obj['as_url']}/token",
        json={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope,
        },
        timeout=10,
    )
    if resp.ok:
        data = resp.json()
        click.echo(f"access_token: {data['access_token']}")
        click.echo(f"scope:        {data.get('scope')}")
        click.echo(f"expires_in:   {data.get('expires_in')} s")
    else:
        click.echo(f"Error {resp.status_code}: {resp.text}", err=True)


@main.command()
@click.argument("token")
@click.pass_obj
def introspect(obj, token):
    """Introspect a token (RFC 7662)."""
    s = _session(obj["ca_cert"])
    resp = s.post(
        f"{obj['as_url']}/introspect",
        json={"token": token},
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    click.echo(json.dumps(data, indent=2))


@main.command()
@click.argument("token")
@click.pass_obj
def revoke(obj, token):
    """Revoke a token (RFC 7009)."""
    s = _session(obj["ca_cert"])
    resp = s.post(
        f"{obj['as_url']}/revoke",
        json={"token": token},
        timeout=10,
    )
    if resp.ok:
        click.echo("Token revoked.")
    else:
        click.echo(f"Error {resp.status_code}: {resp.text}", err=True)


# ---------------------------------------------------------------------------
# Resource server admin
# ---------------------------------------------------------------------------

@main.command()
@click.argument("token")
@click.pass_obj
def connections(obj, token):
    """List recent API connections on the Resource Server."""
    s = _session(obj["ca_cert"])
    resp = s.get(
        f"{obj['rs_url']}/api/v1/admin/connections",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    resp.raise_for_status()
    conns = resp.json().get("connections", [])
    if not conns:
        click.echo("No connections logged.")
        return
    for c in conns:
        click.echo(f"  {c['timestamp']}  {c['client_id']:<20}  {c['endpoint']}")


if __name__ == "__main__":
    main()
