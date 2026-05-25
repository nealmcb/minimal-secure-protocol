# Minimal Secure Protocol – Security Design Plan

## Goal

Python implementation of best-practice IETF security protocols for a **toy telescope
control protocol** between:

* **Client** – astronomy tracking software (e.g. a laptop running Stellarium)
* **Device** – a telescope mount (e.g. an ESP32-based motor controller)

The motivating concern: existing amateur-astronomy protocols such as
[Alpaca/ASCOM](https://ascom-standards.org/AlpacaDeveloper/Index.htm) ship no
meaningful security, despite operating over IP networks.

---

## Philosophical starting points

| RFC | Title | Role in this project |
|-----|-------|----------------------|
| RFC 3365 | Strong Security Requirements for IETF Standard Protocols | Mandate for why security is non-optional |
| RFC 3552 | Guidelines for Writing RFC Text on Security Considerations | Threat-modelling checklist |
| RFC 7228 | Terminology for Constrained-Node Networks | Vocabulary for "the ESP32 can't do X" claims |
| RFC 8576 | IoT Security: State of the Art and Challenges | Umbrella survey; justifies each protocol choice |
| RFC 6973 | Privacy Considerations for Internet Protocols | Minimal RA/Dec logging, no user tracking |

---

## Threat model (RFC 3552 §3)

Attacker capabilities assumed:
* **Network eavesdropper** – passive capture of all packets.
* **Active attacker (on-path)** – can inject, replay, or modify packets.
* **Compromised credential** – a token or key may be stolen after issuance.
* **Rogue device** – an attacker may present a fake telescope.

Goals:
1. **Confidentiality** – slew targets and positions are not exposed to eavesdroppers.
2. **Integrity** – commands cannot be modified in transit.
3. **Authentication** – both sides know who they are talking to.
4. **Authorisation** – not every client may issue a slew; read-only clients exist.
5. **Privacy** – minimal logging; no persistent position history (RFC 6973 §6.1).

---

## Protocol stack

```
┌─────────────────────────────────────────────────────┐
│  Telescope Application Protocol (JSON/REST)         │
│  Operations: position, slew, status, admin          │
├─────────────────────────────────────────────────────┤
│  ACE-OAuth (RFC 9200) – access tokens               │
│  Scopes: telescope:read  telescope:slew             │
│          telescope:admin                            │
├─────────────────────────────────────────────────────┤
│  HTTP/1.1 over TLS 1.3 (RFC 8446)                   │
│  Cipher suites per BCP 195 / RFC 9325               │
├─────────────────────────────────────────────────────┤
│  TCP/IP                                             │
└─────────────────────────────────────────────────────┘
```

For constrained devices (RFC 7228 Class 1–2, e.g. ESP32) the stack would be:

```
┌─────────────────────────────────────────────────────┐
│  CoAP application (RFC 7252)                        │
├─────────────────────────────────────────────────────┤
│  OSCORE (RFC 8613) – object-level security          │
├─────────────────────────────────────────────────────┤
│  EDHOC (RFC 9528) – key exchange                    │
├─────────────────────────────────────────────────────┤
│  UDP / DTLS 1.3                                     │
└─────────────────────────────────────────────────────┘
```

This Python implementation uses the HTTP/TLS stack but documents where OSCORE/EDHOC
or CoAP would replace components on a Class-1 device.

---

## TLS 1.3 configuration (RFC 8446 + BCP 195 / RFC 9325)

* Minimum protocol version: **TLS 1.3** (TLS 1.2 and below disabled).
* Allowed cipher suites (TLS 1.3 mandatory set):
  * `TLS_AES_128_GCM_SHA256`
  * `TLS_AES_256_GCM_SHA384`
  * `TLS_CHACHA20_POLY1305_SHA256`
* Server certificate: ECDSA P-256 (or Ed25519) – avoids RSA key-transport weaknesses.
* Client certificate authentication **optional** (mTLS for admin role).
* Certificate must carry a `subjectAltName`; CN alone is rejected per RFC 2818.
* Key usage: `digitalSignature` only (no `keyEncipherment`).

See `src/telescope/tls_config.py`.

---

## ACE-OAuth (RFC 9200) – Authorization

The Authorization Server (AS), Resource Server (RS), and Client follow the
ACE framework:

```
Client ──── POST /token ──→ AS (port 8444, TLS 1.3)
Client ←─── access_token ──
Client ──── GET /api/… + Bearer token ──→ RS (port 8443, TLS 1.3)
RS     ──── introspect / local verify ──→ valid / invalid
```

Token format: **JWT** (RFC 7519) signed with the AS's EC key (ES256).

Token claims:
| Claim | Meaning |
|-------|---------|
| `iss` | AS URL |
| `aud` | RS URL |
| `sub` | client identifier |
| `scope` | space-separated OAuth 2.0 scopes |
| `iat` | issued-at |
| `exp` | expiry (1 hour default) |
| `jti` | unique token ID (for revocation list) |

Scopes:
* `telescope:read` – read position and status.
* `telescope:slew` – issue slew commands.
* `telescope:admin` – manage device configuration and connections.

Client credentials grant (RFC 6749 §4.4) is used because the device acts as an
autonomous agent, not on behalf of an end-user.

---

## BRSKI-inspired device bootstrap (RFC 8995)

BRSKI (Bootstrapping Remote Secure Key Infrastructure) addresses the "first-contact"
problem: how does a new device securely join a domain without pre-shared secrets?

Simplified flow implemented in `scripts/setup_device.py`:

1. **Pledge** (new device) holds a manufacturer-issued certificate (IDevID).
2. **Registrar** (domain controller) verifies the IDevID against a simulated MASA.
3. Registrar issues a **locally signed operational certificate** (LDevID).
4. Device replaces IDevID with LDevID for ongoing TLS connections.

In this implementation the MASA (Manufacturer Authorized Signing Authority) is
simulated locally; the IDevID is a self-signed cert created by `generate_certs.py`.

---

## MUD (RFC 8520) – Manufacturer Usage Description

The file `mud/telescope-mount.mud.json` describes the **expected network behaviour**
of the telescope mount:

* Allows inbound TCP on port 8443 (telescope API).
* Allows outbound UDP 123 (NTP for time sync).
* Denies everything else.

A network gateway that honours MUD can enforce this policy automatically, providing
defence-in-depth.

---

## OSCORE + EDHOC (RFC 8613, RFC 9528) – future / constrained path

On a Class-1 device (e.g. ESP32 with ~50 KB RAM):

* **EDHOC** performs a 3-message asymmetric key exchange (≈1 KB messages).
* The resulting **OSCORE security context** protects CoAP messages at the
  application layer (end-to-end, surviving NAT/proxies).
* This is lighter than TLS 1.3 + HTTP but provides equivalent security.

Python libraries: `aiocoap` (CoAP), `lakers-python` (EDHOC) are available but
not included in this minimal implementation; the architecture is designed to allow
their substitution for the HTTP/TLS layer.

---

## Privacy (RFC 6973)

* **Minimal logging**: the server logs connection events but not RA/Dec values.
* **No persistent history**: position log is disabled by default.
* **Token opacity**: tokens contain only the scope, not user identity details.
* **Short token lifetime**: 1-hour expiry limits exposure of stolen tokens.

---

## Operations reference

### Start authorization server
```bash
python -m telescope.auth --port 8444 --cert certs/as.crt --key certs/as.key
```

### Start telescope resource server
```bash
python -m telescope.server --port 8443 --cert certs/rs.crt --key certs/rs.key \
    --as-cert certs/as.crt --as-url https://localhost:8444
```

### Request an access token (client credentials)
```bash
python -m telescope.client token --client-id my-tracker --scope "telescope:read telescope:slew"
```

### Read telescope position
```bash
python -m telescope.client position
```

### Slew to a new position
```bash
python -m telescope.client slew --ra 10.68 --dec 41.27
```

### Admin: list active connections
```bash
python -m scripts.admin connections
```

### Setup a new device (BRSKI-inspired)
```bash
python scripts/setup_device.py --device-id mount-001
```
