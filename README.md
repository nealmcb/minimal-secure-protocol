# minimal-secure-protocol

Toy telescope-control protocol using ACE-OAuth-style tokens, TLS 1.3, and related IETF security patterns.

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)

## Setup (uv)

```bash
uv sync --extra dev
```

Generate local demo certificates:

```bash
uv run python scripts/generate_certs.py
```

Optional device bootstrap flow:

```bash
uv run python scripts/setup_device.py \
  --device-id mount-001 \
  --idevid-cert certs/idevid.crt \
  --idevid-key certs/idevid.key \
  --ca-cert certs/ca.crt \
  --ca-key certs/ca.key \
  --as-url https://localhost:8444 \
  --rs-url https://localhost:8443
```

## Run tests

```bash
uv run pytest
```

## Try it out

Start the authorization server:

```bash
uv run python -m telescope.auth \
  --port 8444 \
  --cert certs/as.crt \
  --key certs/as.key \
  --rs-url https://localhost:8443
```

In another terminal, start the telescope resource server:

```bash
uv run python -m telescope.server \
  --port 8443 \
  --cert certs/rs.crt \
  --key certs/rs.key \
  --as-cert certs/as.crt \
  --as-url https://localhost:8444
```

In a third terminal, request a token and call APIs:

```bash
uv run telescope-client --ca-cert certs/ca.crt token \
  --client-id tracker-full \
  --client-secret tracker-full-secret-01 \
  --scope "telescope:read telescope:slew"

uv run telescope-client --ca-cert certs/ca.crt position
uv run telescope-client --ca-cert certs/ca.crt status
uv run telescope-client --ca-cert certs/ca.crt slew --ra 10.68 --dec 41.27
```
