# Server Configuration Reference

Complete reference for all environment variables and settings for the OpenSSL Encrypt Server.

## Table of Contents

- [Quick Start](#quick-start)
- [Application Settings](#application-settings)
- [Server Settings](#server-settings)
- [Database Settings](#database-settings)
- [Module Enable Flags](#module-enable-flags)
- [Keyserver Module](#keyserver-module)
- [Telemetry Module](#telemetry-module)
- [Pepper Module](#pepper-module)
- [Integrity Module](#integrity-module)
- [Authentication & Registration](#authentication--registration)
- [SMTP Settings](#smtp-settings)
- [CORS Settings](#cors-settings)
- [Security Settings](#security-settings)
- [Docker Compose Mapping](#docker-compose-mapping)
- [Startup Validation](#startup-validation)
- [Example .env File](#example-env-file)

---

## Quick Start

1. Copy `.env.example` to `.env`
2. Set required values: `POSTGRES_PASSWORD`, `KEYSERVER_TOKEN_SECRET`, `TELEMETRY_TOKEN_SECRET`
3. Run `docker-compose up -d`
4. Verify: `curl http://localhost:8080/health`

Minimum required configuration:

```bash
POSTGRES_PASSWORD=your-strong-database-password
KEYSERVER_TOKEN_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
TELEMETRY_TOKEN_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
```

---

## Application Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `APP_NAME` | str | `OpenSSL Encrypt Server` | Application name (displayed in logs and info endpoint) |
| `VERSION` | str | `1.0.0` | Application version |
| `DEBUG` | bool | `false` | Enable debug mode (exposes /docs and /redoc endpoints) |
| `LOG_LEVEL` | str | `INFO` | Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL |

**Note:** `DEBUG` only controls API documentation exposure. It does **not** affect security validation. See `ALLOW_INSECURE_DEFAULTS` for development security bypasses.

---

## Server Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SERVER_HOST` | str | `0.0.0.0` | Bind address |
| `SERVER_PORT` | int | `8080` | Bind port |

---

## Database Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `DATABASE_URL` | str | *none* | Full connection string (overrides POSTGRES_* variables if set) |
| `POSTGRES_USER` | str | `openssl_server` | PostgreSQL username |
| `POSTGRES_PASSWORD` | str | **required** | PostgreSQL password |
| `POSTGRES_DB` | str | `openssl_encrypt` | Database name |
| `POSTGRES_HOST` | str | `localhost` | PostgreSQL hostname |
| `POSTGRES_PORT` | int | `5432` | PostgreSQL port |
| `DATABASE_QUERY_TIMEOUT` | int | `30` | Query timeout in seconds |
| `DATABASE_POOL_SIZE` | int | `20` | Connection pool size |
| `DATABASE_MAX_OVERFLOW` | int | `10` | Max connections above pool size |

### Connection String

If `DATABASE_URL` is not set, the connection string is built from individual variables:

```
postgresql+asyncpg://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}
```

### Validation

- `POSTGRES_PASSWORD` must not be empty when `ALLOW_INSECURE_DEFAULTS=false`
- Password cannot contain insecure markers (e.g., `change-me`, `changeme`, `not-for-production`)

---

## Module Enable Flags

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `KEYSERVER_ENABLED` | bool | `true` | Enable keyserver module (public key distribution) |
| `TELEMETRY_ENABLED` | bool | `true` | Enable telemetry module (usage statistics) |
| `PEPPER_ENABLED` | bool | `false` | Enable pepper module (requires mTLS or proxy) |
| `INTEGRITY_ENABLED` | bool | `false` | Enable integrity module (requires mTLS or proxy) |

Public modules (Keyserver, Telemetry) use JWT authentication.
Private modules (Pepper, Integrity) use mTLS certificate authentication.

---

## Keyserver Module

### Token Authentication

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `KEYSERVER_TOKEN_SECRET` | str | **required** | JWT signing secret (min 32 chars, must differ from telemetry secret) |

Generate a secure secret:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

### Email Registration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `KEYSERVER_REQUIRE_EMAIL_VERIFICATION` | bool | `false` | Require email confirmation for registration |
| `KEYSERVER_BASE_URL` | str | `""` | Base URL for confirmation email links (required if email verification enabled) |

Example: `KEYSERVER_BASE_URL=https://keyserver.example.com`

### Registration Gating

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `REGISTRATION_SECRET` | str | *none* | If set, `X-Registration-Secret` header must match for registration |

### Internal Configuration

These are compiled from the environment at startup:

| Setting | Value | Description |
|---------|-------|-------------|
| Token algorithm | HS256 | JWT signing algorithm |
| Access token TTL | 60 minutes | Access token lifetime |
| Refresh token TTL | 7 days | Refresh token lifetime |
| Token issuer | `openssl_encrypt_keyserver` | Issuer claim (module isolation) |
| Max key size | 100 KB | Maximum key bundle size |
| Require self-signature | true | PQC signature verification on upload |
| Allowed KEM algorithms | ML-KEM-512, ML-KEM-768, ML-KEM-1024 | Encryption algorithm whitelist |
| Allowed DSA algorithms | ML-DSA-44, ML-DSA-65, ML-DSA-87 | Signing algorithm whitelist |

---

## Telemetry Module

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `TELEMETRY_TOKEN_SECRET` | str | **required** | JWT signing secret (min 32 chars, must differ from keyserver secret) |

### Internal Configuration

| Setting | Value | Description |
|---------|-------|-------------|
| Token algorithm | HS256 | JWT signing algorithm |
| Access token TTL | 60 minutes | Access token lifetime |
| Refresh token TTL | 7 days | Refresh token lifetime |
| Token issuer | `openssl_encrypt_telemetry` | Issuer claim (module isolation) |
| Retention | 365 days | Event data retention period |
| Max events per request | 1000 | Batch event submission limit |
| Rate limit | 10000 events/day | Per-client daily limit |

---

## Pepper Module

### Authentication

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `PEPPER_AUTH_MODE` | str | `proxy` | Authentication mode: `proxy` or `mtls` |

### TOTP Encryption

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `PEPPER_TOTP_SECRET_KEY` | str | **required** | Fernet encryption key for TOTP secrets (exactly 44 chars) |

Generate a Fernet key:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### Deadman Switch

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `PEPPER_DEADMAN_ENABLED` | bool | `true` | Enable automatic pepper wipe on missed check-ins |

### mTLS Settings (when `PEPPER_AUTH_MODE=mtls`)

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `PEPPER_MTLS_PORT` | int | `8444` | mTLS listener port |
| `PEPPER_MTLS_CERT` | str | `/certs/pepper-server.crt` | Server certificate path |
| `PEPPER_MTLS_KEY` | str | `/certs/pepper-server.key` | Server private key path |
| `PEPPER_MTLS_CLIENT_CA` | str | `/certs/client-ca.crt` | Client CA certificate path |

### Proxy Settings (when `PEPPER_AUTH_MODE=proxy`)

| Setting | Default | Description |
|---------|---------|-------------|
| Fingerprint header | `X-Client-Cert-Fingerprint` | Header containing client cert SHA-256 fingerprint |
| DN header | `X-Client-Cert-DN` | Header containing client cert Distinguished Name |
| Verify header | `X-Client-Cert-Verify` | Header containing cert verification status |
| Trusted proxies | `127.0.0.1`, `::1` | IPs trusted to forward cert headers |

### Internal Configuration

| Setting | Value | Description |
|---------|-------|-------------|
| Max peppers per client | 100 | Per-client pepper limit |
| TOTP max attempts | 5 per 5 minutes | Failed TOTP attempt limit |
| TOTP lockout duration | 15 minutes | Lockout after exceeding attempt limit |
| Deadman default interval | 7 days | Default check-in interval |
| Deadman grace period | 24 hours | Grace period before wipe |
| Deadman check interval | 1 hour | Background watcher frequency |

---

## Integrity Module

### Authentication

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `INTEGRITY_AUTH_MODE` | str | `proxy` | Authentication mode: `proxy` or `mtls` |

### mTLS Settings (when `INTEGRITY_AUTH_MODE=mtls`)

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `INTEGRITY_MTLS_PORT` | int | `8445` | mTLS listener port |
| `INTEGRITY_MTLS_CERT` | str | `/certs/integrity-server.crt` | Server certificate path |
| `INTEGRITY_MTLS_KEY` | str | `/certs/integrity-server.key` | Server private key path |
| `INTEGRITY_MTLS_CLIENT_CA` | str | `/certs/client-ca.crt` | Client CA certificate path |

### Proxy Settings

Same structure as Pepper proxy settings with separate trusted proxy list.

---

## Authentication & Registration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `REGISTRATION_SECRET` | str | *none* | Optional pre-shared secret for gating registration |

When set, the `X-Registration-Secret` header must match on register endpoints. Applies to both Keyserver and Telemetry modules.

---

## SMTP Settings

Required when `KEYSERVER_REQUIRE_EMAIL_VERIFICATION=true`.

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SMTP_HOST` | str | `""` | SMTP server hostname |
| `SMTP_PORT` | int | `587` | SMTP server port (587 = STARTTLS, 465 = SMTPS, 25 = plain) |
| `SMTP_USERNAME` | str | *none* | SMTP authentication username |
| `SMTP_PASSWORD` | str | *none* | SMTP authentication password |
| `SMTP_USE_TLS` | bool | `true` | Use STARTTLS for SMTP connection |
| `SMTP_VERIFY_TLS` | bool | `true` | Verify TLS certificate (set `false` for internal servers with self-signed certs) |
| `SMTP_FROM_ADDRESS` | str | `""` | Sender email address for confirmation/welcome emails |

### Example SMTP Configurations

**Gmail:**

```bash
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_USE_TLS=true
SMTP_VERIFY_TLS=true
SMTP_FROM_ADDRESS=your-email@gmail.com
```

**Internal server (self-signed cert):**

```bash
SMTP_HOST=10.0.0.22
SMTP_PORT=2525
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_USE_TLS=true
SMTP_VERIFY_TLS=false
SMTP_FROM_ADDRESS=keyserver@internal.example.com
```

---

## CORS Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `CORS_ORIGINS` | str | `""` | Comma-separated allowed origins (empty = CORS disabled) |
| `CORS_ALLOW_CREDENTIALS` | bool | `false` | Allow credentials in cross-origin requests |
| `CORS_ALLOW_METHODS` | str | `GET,POST,PUT,DELETE` | Allowed HTTP methods |
| `CORS_ALLOW_HEADERS` | str | `Authorization,Content-Type` | Allowed request headers |
| `CORS_MAX_AGE` | int | `600` | Preflight cache duration in seconds |

### Examples

**Disabled (default, most secure):**

```bash
CORS_ORIGINS=
```

**Specific origin:**

```bash
CORS_ORIGINS=https://app.example.com
```

**Multiple origins:**

```bash
CORS_ORIGINS=https://app.example.com,https://admin.example.com
```

**Wildcard (not recommended):**

```bash
CORS_ORIGINS=*
# WARNING: This allows any origin. Use specific origins in production.
```

---

## Security Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `ALLOW_INSECURE_DEFAULTS` | bool | `false` | Allow insecure defaults for local development |

### What `ALLOW_INSECURE_DEFAULTS` Controls

When `false` (production, default):
- `POSTGRES_PASSWORD` must not be empty
- Token secrets must not contain insecure markers (`change-me`, `changeme`, `change_this`, `secret-change`, `not-for-production`)
- Server refuses to start if validation fails

When `true` (development only):
- Empty passwords and insecure markers are permitted
- Warnings are logged
- **Never use in production**

### Separation of Debug and Security

`DEBUG` and `ALLOW_INSECURE_DEFAULTS` are independent:

| DEBUG | ALLOW_INSECURE_DEFAULTS | Effect |
|-------|------------------------|--------|
| false | false | Production: strict security, no docs |
| true | false | Staging: docs enabled, strict security |
| false | true | Invalid: insecure without docs |
| true | true | Development: docs enabled, relaxed security |

---

## Docker Compose Mapping

The `docker-compose.yml` maps environment variables from `.env` to the API container:

```yaml
environment:
  # Database
  POSTGRES_USER: ${POSTGRES_USER:-openssl_server}
  POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?POSTGRES_PASSWORD must be set}
  POSTGRES_DB: ${POSTGRES_DB:-openssl_encrypt}
  POSTGRES_HOST: db
  POSTGRES_PORT: 5432

  # Server
  SERVER_HOST: 0.0.0.0
  SERVER_PORT: 8080
  DEBUG: ${DEBUG:-false}
  LOG_LEVEL: ${LOG_LEVEL:-INFO}

  # Auth Secrets
  KEYSERVER_TOKEN_SECRET: ${KEYSERVER_TOKEN_SECRET:?required}
  TELEMETRY_TOKEN_SECRET: ${TELEMETRY_TOKEN_SECRET:?required}

  # Modules
  KEYSERVER_ENABLED: ${KEYSERVER_ENABLED:-true}
  TELEMETRY_ENABLED: ${TELEMETRY_ENABLED:-true}
  PEPPER_ENABLED: ${PEPPER_ENABLED:-false}
  INTEGRITY_ENABLED: ${INTEGRITY_ENABLED:-false}

  # Pepper
  PEPPER_AUTH_MODE: ${PEPPER_AUTH_MODE:-proxy}
  PEPPER_TOTP_SECRET_KEY: ${PEPPER_TOTP_SECRET_KEY}
  PEPPER_DEADMAN_ENABLED: ${PEPPER_DEADMAN_ENABLED:-true}

  # Integrity
  INTEGRITY_AUTH_MODE: ${INTEGRITY_AUTH_MODE:-proxy}

  # Keyserver Email Registration
  KEYSERVER_BASE_URL: ${KEYSERVER_BASE_URL:-}

  # SMTP
  SMTP_HOST: ${SMTP_HOST:-}
  SMTP_PORT: ${SMTP_PORT:-587}
  SMTP_USERNAME: ${SMTP_USERNAME:-}
  SMTP_PASSWORD: ${SMTP_PASSWORD:-}
  SMTP_USE_TLS: ${SMTP_USE_TLS:-true}
  SMTP_VERIFY_TLS: ${SMTP_VERIFY_TLS:-true}
  SMTP_FROM_ADDRESS: ${SMTP_FROM_ADDRESS:-}

  # CORS
  CORS_ORIGINS: ${CORS_ORIGINS:-}
```

### Docker Services

| Service | Image | Address | Health Check |
|---------|-------|---------|-------------|
| db | postgres:16-alpine | 172.28.0.2:5432 | `pg_isready` |
| api | Built from Dockerfile | 172.28.0.3:8080 | `curl http://localhost:8080/health` |

### Standalone Port Exposure

By default, the API container does not expose ports (designed for reverse proxy). For standalone use:

```bash
docker-compose -f docker-compose.yml -f docker-compose.standalone.yml up
```

This exposes `${SERVER_PORT:-8080}:8080` on the host.

---

## Startup Validation

The server performs these checks at startup:

1. **Configuration parsing**: All environment variables loaded and validated by Pydantic
2. **Secret validation**: Token secrets checked for minimum length, uniqueness, and insecure markers
3. **Database password**: Must be non-empty in production mode
4. **TOTP key validation**: If pepper enabled, Fernet key must be exactly 44 characters
5. **Email verification deps**: If email verification enabled, SMTP_HOST, SMTP_FROM_ADDRESS, and KEYSERVER_BASE_URL must be set
6. **Database connection**: Connection pool initialized and tables created
7. **liboqs check**: Post-quantum library availability verified (warning if unavailable)
8. **Module loading**: Each enabled module loaded and registered

If any required validation fails, the server logs the error and refuses to start.

---

## Example .env File

```bash
# ============================================================
# PostgreSQL Configuration
# ============================================================
POSTGRES_USER=openssl_server
POSTGRES_PASSWORD=your-strong-database-password
POSTGRES_DB=openssl_encrypt

# ============================================================
# Server Configuration
# ============================================================
DEBUG=false
LOG_LEVEL=INFO

# ============================================================
# Authentication Secrets (REQUIRED, min 32 chars, MUST differ)
# Generate: python -c "import secrets; print(secrets.token_urlsafe(48))"
# ============================================================
KEYSERVER_TOKEN_SECRET=your-keyserver-secret-min-32-chars-here
TELEMETRY_TOKEN_SECRET=your-telemetry-secret-min-32-chars-here

# ============================================================
# Module Enable Flags
# ============================================================
KEYSERVER_ENABLED=true
TELEMETRY_ENABLED=true
PEPPER_ENABLED=false
INTEGRITY_ENABLED=false

# ============================================================
# Keyserver Email Registration (optional)
# ============================================================
KEYSERVER_BASE_URL=https://keyserver.example.com
# KEYSERVER_REQUIRE_EMAIL_VERIFICATION=true
# REGISTRATION_SECRET=optional-registration-gate-secret

# ============================================================
# SMTP (required if email verification enabled)
# ============================================================
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_USE_TLS=true
SMTP_VERIFY_TLS=true
SMTP_FROM_ADDRESS=keyserver@example.com

# ============================================================
# Pepper Module (if enabled)
# Generate: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# ============================================================
# PEPPER_AUTH_MODE=proxy
# PEPPER_TOTP_SECRET_KEY=your-44-char-fernet-key
# PEPPER_DEADMAN_ENABLED=true

# ============================================================
# Integrity Module (if enabled)
# ============================================================
# INTEGRITY_AUTH_MODE=proxy

# ============================================================
# CORS (empty = disabled, most secure)
# ============================================================
CORS_ORIGINS=

# ============================================================
# Security
# ============================================================
# ALLOW_INSECURE_DEFAULTS=false
```
