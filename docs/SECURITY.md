# Security Best Practices

Hardening guide and security reference for the OpenSSL Encrypt Server.

## Table of Contents

- [Security Architecture Overview](#security-architecture-overview)
- [Authentication](#authentication)
  - [JWT Token Authentication](#jwt-token-authentication)
  - [mTLS Certificate Authentication](#mtls-certificate-authentication)
  - [Proxy Authentication](#proxy-authentication)
  - [Registration Gating](#registration-gating)
- [Token Security](#token-security)
  - [Token Isolation](#token-isolation)
  - [Token Lifecycle](#token-lifecycle)
  - [Refresh Token Security](#refresh-token-security)
  - [Token Revocation](#token-revocation)
- [Secret Management](#secret-management)
  - [Required Secrets](#required-secrets)
  - [Secret Generation](#secret-generation)
  - [Secret Validation](#secret-validation)
  - [Insecure Defaults Protection](#insecure-defaults-protection)
- [Rate Limiting](#rate-limiting)
- [Input Validation](#input-validation)
  - [Schema Validation](#schema-validation)
  - [Algorithm Whitelists](#algorithm-whitelists)
  - [PQC Signature Verification](#pqc-signature-verification)
- [Network Security](#network-security)
  - [CORS Configuration](#cors-configuration)
  - [Trusted Proxy Validation](#trusted-proxy-validation)
  - [Docker Network Isolation](#docker-network-isolation)
  - [TLS Configuration](#tls-configuration)
- [Database Security](#database-security)
- [Information Disclosure Prevention](#information-disclosure-prevention)
- [Cryptographic Security](#cryptographic-security)
  - [Constant-Time Comparisons](#constant-time-comparisons)
  - [Post-Quantum Cryptography](#post-quantum-cryptography)
  - [TOTP and Backup Codes](#totp-and-backup-codes)
  - [Pepper Encryption](#pepper-encryption)
- [Audit Logging](#audit-logging)
  - [Security Event Types](#security-event-types)
  - [Log Format](#log-format)
  - [Sensitive Data Masking](#sensitive-data-masking)
- [Deadman Switch](#deadman-switch)
- [Container Security](#container-security)
- [Operational Security](#operational-security)
  - [Production Deployment Checklist](#production-deployment-checklist)
  - [Monitoring](#monitoring)
  - [Incident Response](#incident-response)
  - [Backup and Recovery](#backup-and-recovery)

---

## Security Architecture Overview

The server implements defense-in-depth with multiple security layers:

```
                    Internet
                       |
                   [Firewall]
                       |
                [Reverse Proxy]     ← TLS termination, mTLS for private modules
                       |
              [Docker Network]      ← Isolated 172.28.0.0/16 subnet
                  /        \
            [API Server]  [PostgreSQL]
            172.28.0.3    172.28.0.2
```

**Public modules** (Keyserver, Telemetry):
- JWT Bearer token authentication
- Per-module secret isolation
- Rate limiting per endpoint

**Private modules** (Pepper, Integrity):
- mTLS client certificate authentication
- Trusted proxy validation
- TOTP 2FA (Pepper module)

---

## Authentication

### JWT Token Authentication

Used by: Keyserver, Telemetry modules

**Token structure:**

| Claim | Purpose |
|-------|---------|
| `sub` | Client ID (32 hex chars) |
| `iss` | Module issuer (prevents cross-module use) |
| `exp` | Expiration timestamp (UTC) |
| `iat` | Issued-at timestamp (UTC) |
| `jti` | Unique token ID (replay prevention) |
| `type` | Token type (`access` or `refresh`) |

**Verification chain:**

1. Signature verification (HMAC-SHA256 with module-specific secret)
2. Expiration check
3. Issuer validation (must match expected module)
4. JTI revocation check
5. Token type validation (access vs refresh)

### mTLS Certificate Authentication

Used by: Pepper, Integrity modules (when auth_mode=mtls)

**Direct mTLS mode:**
- Server terminates TLS on dedicated port (8444/8445)
- Client must present certificate signed by configured CA
- Certificate fingerprint (SHA-256) used as client identifier
- No passwords involved

**Proxy mTLS mode:**
- Reverse proxy (Nginx) terminates mTLS
- Proxy forwards certificate data in HTTP headers
- Server validates request came from trusted proxy IP

### Proxy Authentication

Used by: Pepper, Integrity modules (when auth_mode=proxy)

**Headers consumed:**

| Header | Purpose | Strategy |
|--------|---------|----------|
| `X-Client-Cert` | Full PEM certificate (URL-encoded) | Preferred: server computes fingerprint |
| `X-Client-Cert-Fingerprint` | Pre-computed SHA-256 fingerprint | Fallback if raw cert unavailable |
| `X-Client-Cert-DN` | Client Distinguished Name | Identity metadata |
| `X-Client-Cert-Verify` | Verification status (`SUCCESS`) | Proxy's verification result |

**Trusted proxy enforcement:**
- Only configured proxy IPs can forward certificate headers
- Default: localhost only (`127.0.0.1`, `::1`)
- CIDR notation supported (e.g., `192.168.1.0/24`)
- Networks larger than /24 are rejected (prevents overly broad trust)
- Untrusted proxy attempts are logged as security events

**Fingerprint normalization:**
- SHA-256, lowercase hex, 64 characters
- Colons, spaces, and hyphens stripped
- Hex-only content validated
- Prevents bypass via formatting variations

### Registration Gating

Optional pre-shared secret for controlling who can register:

```bash
REGISTRATION_SECRET=your-secret-here
```

When set:
- `X-Registration-Secret` header must match exactly
- Applies to both Keyserver and Telemetry register endpoints
- Returns generic 403 on mismatch (no secret disclosure)

---

## Token Security

### Token Isolation

Each module has its own:

| Module | Issuer Claim | Secret Variable |
|--------|-------------|-----------------|
| Keyserver | `openssl_encrypt_keyserver` | `KEYSERVER_TOKEN_SECRET` |
| Telemetry | `openssl_encrypt_telemetry` | `TELEMETRY_TOKEN_SECRET` |

**Effects:**
- Keyserver token rejected by Telemetry endpoints (and vice versa)
- Compromising one secret does not affect the other module
- Secrets must differ (startup validation enforces this)

### Token Lifecycle

| Token Type | Lifetime | Use |
|------------|----------|-----|
| Access token | 60 minutes | Bearer header for API calls |
| Refresh token | 7 days | POST body to obtain new token pair |

### Refresh Token Security

- Refresh token sent in POST body (not query parameters or headers)
- Query parameter usage is explicitly blocked and returns 401
- Each refresh returns a **new** token pair (both access and refresh)
- Old refresh token is revoked immediately (single-use)
- Token type claim (`type: refresh`) validated (prevents access token as refresh)

### Token Revocation

- In-memory JTI revocation set (thread-safe with lock)
- Refresh tokens revoked on use (prevents replay)
- Revocation persists for server lifetime
- Server restart clears revocation set (tokens expire naturally via `exp` claim)

---

## Secret Management

### Required Secrets

| Secret | Min Length | Module | Purpose |
|--------|-----------|--------|---------|
| `KEYSERVER_TOKEN_SECRET` | 32 chars | Keyserver | JWT signing |
| `TELEMETRY_TOKEN_SECRET` | 32 chars | Telemetry | JWT signing |
| `PEPPER_TOTP_SECRET_KEY` | 44 chars (Fernet) | Pepper | TOTP secret encryption |
| `POSTGRES_PASSWORD` | Non-empty | Database | Database authentication |

### Secret Generation

```bash
# JWT secrets (min 32 chars)
python -c "import secrets; print(secrets.token_urlsafe(48))"

# Fernet key (exactly 44 chars)
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Registration secret (optional)
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### Secret Validation

At startup, the server validates:

1. **Minimum length**: Token secrets must be >= 32 characters
2. **Uniqueness**: Keyserver and Telemetry secrets must differ
3. **No insecure markers**: Rejects secrets containing: `change-me`, `changeme`, `change_me`, `change_this`, `secret-change`, `not-for-production`
4. **Fernet format**: TOTP secret key must be exactly 44 characters

### Insecure Defaults Protection

`ALLOW_INSECURE_DEFAULTS` controls startup validation strictness:

| Value | Effect |
|-------|--------|
| `false` (default) | Strict: rejects empty passwords, insecure markers. Server refuses to start. |
| `true` | Permissive: allows insecure values with warnings. **Development only.** |

This is intentionally **separate** from `DEBUG` to prevent accidentally disabling security when enabling documentation endpoints.

---

## Rate Limiting

All rate limits are per-client-IP using the `slowapi` library.

### Keyserver Endpoints

| Endpoint | Limit | Rationale |
|----------|-------|-----------|
| `POST /register` | 10/hour | Prevent mass registration |
| `POST /login` | 5/minute | Prevent brute force credential attacks |
| `POST /register/email` | 5/hour | Prevent email spam |
| `GET /confirm/{token}` | 20/hour | Reasonable for email link clicks |
| `GET /register/status/{id}` | 60/hour | Allow polling without overload |
| `POST /` (upload) | 60/minute | Normal key uploads |
| `GET /search` | 100/minute | Public key lookups |
| `POST /{fp}/revoke` | 60/minute | Key revocation |
| `POST /refresh` | 60/hour | Periodic token refresh |

### Telemetry Endpoints

| Endpoint | Limit |
|----------|-------|
| `POST /register` | 10/hour |
| `POST /refresh` | 60/hour |
| `POST /events` | 1000/hour |
| `GET /stats` | 100/minute |

### Integrity Endpoints

| Endpoint | Limit |
|----------|-------|
| All endpoints | 60/minute |

### Pepper TOTP Rate Limiting

Separate from HTTP rate limiting — protects against TOTP brute force:

| Setting | Value |
|---------|-------|
| Max failed attempts | 5 per 5-minute window |
| Lockout duration | 15 minutes |
| Backend | In-memory (default) or database-backed |

After lockout, the client receives `429 Too Many Requests` for all TOTP-protected operations. Lockout events are logged as `TOTP_LOCKOUT` security events.

---

## Input Validation

### Schema Validation

All request bodies are validated by Pydantic schemas:

- **Type enforcement**: Strict type checking (str, int, bool, etc.)
- **Length constraints**: `min_length`, `max_length` on string fields
- **Email validation**: `EmailStr` type for email fields
- **Required vs optional**: Clearly defined per schema

### Algorithm Whitelists

Key upload bundles are validated against post-quantum algorithm whitelists:

**Encryption (KEM):**
- `ML-KEM-512` (NIST Category 1)
- `ML-KEM-768` (NIST Category 3)
- `ML-KEM-1024` (NIST Category 5)

**Signing (DSA):**
- `ML-DSA-44` (NIST Category 2)
- `ML-DSA-65` (NIST Category 3)
- `ML-DSA-87` (NIST Category 5)

Any other algorithm values are rejected with 400 Bad Request.

### PQC Signature Verification

Before storing any key bundle, the server performs:

1. **Self-signature verification**: The bundle's `self_signature` is verified against the `signing_public_key` using liboqs (ML-DSA). The signed message is a deterministic JSON serialization of all bundle fields (sorted keys, compact separators).

2. **Fingerprint verification**: The fingerprint is recalculated as `SHA-256(encryption_public_key || signing_public_key)` and compared against the provided fingerprint.

3. **Algorithm validation**: Both algorithms checked against whitelist.

Bundles failing any check are rejected with 400 Bad Request.

---

## Network Security

### CORS Configuration

**Default: Disabled** (empty `CORS_ORIGINS`). This is the most secure configuration.

Recommendations:
- Use specific origins, never `*` in production
- Enable only the HTTP methods your frontend needs
- Restrict allowed headers to those actually used
- Keep `CORS_ALLOW_CREDENTIALS=false` unless specifically needed

### Trusted Proxy Validation

When using proxy authentication mode (Pepper/Integrity):

- **Default trust**: Localhost only (`127.0.0.1`, `::1`)
- **CIDR support**: e.g., `192.168.1.0/24`
- **Maximum prefix**: Networks larger than /24 are rejected (except localhost ranges)
- **Validation**: Every request checked against trusted proxy list
- **Logging**: Untrusted proxy attempts logged as `UNTRUSTED_PROXY` security events

**Why /24 maximum?** Trusting large network ranges (e.g., /16) drastically increases attack surface. If any host in the trusted range is compromised, certificate headers can be forged. Keep trust ranges as narrow as possible.

### Docker Network Isolation

- **Fixed subnet**: `172.28.0.0/16`
- **Internal only**: Database not exposed to host (no port mapping)
- **API exposure**: Controlled via `docker-compose.standalone.yml` override
- **No port exposure by default**: Designed for reverse proxy architecture

### TLS Configuration

- **API server**: Does not terminate TLS (designed behind reverse proxy)
- **mTLS ports**: Terminate TLS directly (Pepper: 8444, Integrity: 8445)
- **SMTP**: STARTTLS by default, optional certificate verification bypass for internal servers
- **Reverse proxy**: Configure TLS in Nginx/Caddy/Traefik (see docs/MTLS_SETUP.md)

---

## Database Security

### Connection Security

- **Async driver**: asyncpg with SQLAlchemy (parameterized queries, no SQL injection)
- **Connection pool**: Bounded (default: 20 + 10 overflow) to prevent resource exhaustion
- **Query timeout**: 30 seconds default prevents long-running query DoS
- **Password required**: Non-empty password enforced in production mode

### Table Isolation

Module-prefixed tables prevent name collisions:

| Module | Prefix | Example Tables |
|--------|--------|---------------|
| Keyserver | `ks_` | `ks_clients`, `ks_keys`, `ks_pending_registrations`, `ks_access_log` |
| Telemetry | `tm_` | `tm_clients`, `tm_events` |
| Pepper | `pp_` | `pp_clients`, `pp_peppers`, `pp_panic_log` |
| Integrity | `in_` | `in_clients`, `in_hashes` |

### Sensitive Data at Rest

| Data | Protection | Storage |
|------|-----------|---------|
| TOTP secrets | Fernet encryption (AES-128-CBC) | `pp_clients.totp_secret` |
| Backup codes | Argon2id hashing (irreversible) | `pp_totp_backup_codes.code_hash` |
| JWT secrets | Environment variable only | Never stored in database |
| Peppers | Stored as-is (client-encrypted) | `pp_peppers.value` |

Peppers are encrypted client-side before transmission. The server stores encrypted blobs and never sees plaintext pepper values.

---

## Information Disclosure Prevention

### Generic Error Messages

All error responses use generic messages that prevent enumeration:

| Endpoint | Error Condition | Response Message |
|----------|----------------|-----------------|
| `/login` | Invalid client_id | `"Invalid credentials"` |
| `/confirm/{token}` | Invalid token | `"Invalid confirmation token"` |
| `/register/status/{id}` | Not found | `"Registration not found"` |
| `/register` | Bad secret | `"Invalid or missing registration secret"` |
| Authenticated endpoints | Bad token | `"Invalid or malformed token"` |
| Proxy auth | Untrusted source | `"Forbidden"` (generic 403) |

### Debug Mode Separation

- `DEBUG=true` only exposes `/docs` and `/redoc` (OpenAPI documentation)
- Security validation is controlled separately by `ALLOW_INSECURE_DEFAULTS`
- Enabling debug mode does **not** weaken security checks

### Log Sensitivity

- Detailed error information logged server-side only (not in HTTP responses)
- Client IDs truncated in logs (first 8 characters)
- Hash values masked (first 16 characters) in integrity mismatch logs
- Security logger handles sensitive data masking automatically

---

## Cryptographic Security

### Constant-Time Comparisons

| Operation | Implementation | Library |
|-----------|---------------|---------|
| JWT signature verification | `jwt.decode()` | PyJWT |
| Client ID lookup (login) | `hmac.compare_digest()` | Python stdlib |
| TOTP code verification | `pyotp.TOTP.verify()` | pyotp |
| Backup code verification | `argon2.PasswordHasher.verify()` | argon2-cffi |
| Integrity hash comparison | `hmac.compare_digest()` | Python stdlib |

### Post-Quantum Cryptography

The keyserver verifies post-quantum signatures using [liboqs](https://github.com/open-quantum-safe/liboqs):

| Algorithm | liboqs Name | NIST Level | Use |
|-----------|-------------|------------|-----|
| ML-KEM-512 | Kyber512 | 1 | Key encapsulation |
| ML-KEM-768 | Kyber768 | 3 | Key encapsulation |
| ML-KEM-1024 | Kyber1024 | 5 | Key encapsulation |
| ML-DSA-44 | Dilithium2 | 2 | Digital signatures |
| ML-DSA-65 | Dilithium3 | 3 | Digital signatures |
| ML-DSA-87 | Dilithium5 | 5 | Digital signatures |

If liboqs is unavailable, signature verification fails (safe default — bundles are rejected, not accepted unverified).

### TOTP and Backup Codes

**TOTP (Time-based One-Time Password):**
- 6-digit codes, 30-second window
- Secrets encrypted with Fernet (AES-128-CBC + HMAC-SHA256)
- Rate limited: 5 attempts per 5 minutes, 15-minute lockout
- Used for pepper update and delete operations

**Backup codes:**
- 10 codes generated per TOTP setup
- 8 characters each (base32 alphabet, no confusing characters)
- Hashed with Argon2id (irreversible)
- Single-use (marked `used_at` on verification)
- Plaintext shown once during setup, then discarded

### Pepper Encryption

Peppers stored on the server are encrypted client-side:
- Client encrypts pepper value before upload
- Server stores encrypted blob in `pp_peppers.value`
- Server never sees or handles plaintext pepper data
- Decryption happens exclusively on the client

---

## Audit Logging

### Security Event Types

| Event | Severity | Trigger |
|-------|----------|---------|
| `AUTH_SUCCESS` | INFO | Successful authentication |
| `AUTH_FAILURE` | WARNING | Failed authentication attempt |
| `TOTP_FAILURE` | WARNING | Failed TOTP verification |
| `TOTP_LOCKOUT` | WARNING | TOTP rate limit exceeded |
| `RATE_LIMIT_EXCEEDED` | WARNING | HTTP rate limit hit |
| `INTEGRITY_MISMATCH` | WARNING | File integrity check failed |
| `INTEGRITY_CHECK_FAILED` | ERROR | Integrity verification error |
| `PANIC_TRIGGERED` | CRITICAL | Manual panic wipe initiated |
| `PANIC_ACTIVATED` | CRITICAL | Deadman switch auto-wipe |
| `KEY_REVOKED` | INFO | Public key revoked |
| `CERT_VERIFICATION_FAILED` | WARNING | mTLS certificate verification failure |
| `SUSPICIOUS_ACTIVITY` | WARNING | Unusual behavior detected |
| `UNTRUSTED_PROXY` | WARNING | Request from untrusted proxy IP |

### Log Format

Security events are logged in JSON format:

```json
{
  "timestamp": "2026-03-26T10:30:00.000Z",
  "event": "AUTH_FAILURE",
  "severity": "WARNING",
  "client_id": "cd94f345",
  "details": {
    "reason": "Token expired",
    "ip": "192.168.1.100",
    "endpoint": "/api/v1/keys"
  }
}
```

### Log Locations

| Log | Path | Fallback |
|-----|------|----------|
| Security log | `/var/log/openssl-encrypt/security.log` | `/tmp/openssl-encrypt/security.log` |
| Application log | Console (stdout/stderr) | Configurable via LOG_LEVEL |

### Sensitive Data Masking

The security logger automatically masks sensitive data:
- Client IDs: First 8 characters only
- Hash values: First 16 characters only
- Tokens: Never logged
- Passwords: Never logged
- Peppers: Never logged

---

## Deadman Switch

The pepper module includes an automatic wipe mechanism for inactive clients.

### How It Works

1. Client configures deadman switch with check-in interval and grace period
2. Client must call the check-in endpoint before the deadline
3. Background watcher runs every hour (configurable)
4. If deadline + grace period passed without check-in:
   - All client peppers are permanently deleted
   - Event logged as `PANIC_ACTIVATED` (CRITICAL)
   - Wipe recorded in `pp_panic_log`

### Configuration

| Setting | Default | Minimum | Description |
|---------|---------|---------|-------------|
| Check-in interval | 7 days | 1 hour | How often the client must check in |
| Grace period | 24 hours | 1 hour | Extra time before wipe after missed deadline |
| Watcher frequency | 1 hour | - | How often the background task checks |

### Security Implications

- **Protects against**: Device compromise, coercion, extended unavailability
- **Irreversible**: Wipe cannot be undone — peppers are permanently deleted
- **Client responsibility**: Client must maintain regular check-ins
- **Failure mode**: If server is unreachable, deadline continues ticking
- **Opt-in**: Deadman switch is disabled per-client until configured

---

## Container Security

### Non-Root Execution

The Docker container runs as a non-root user:

```dockerfile
RUN useradd -m -u 1000 appuser
USER appuser
```

- UID 1000 (standard non-privileged user)
- No sudo or privilege escalation
- Application files owned by appuser

### Multi-Stage Build

The Dockerfile uses multi-stage builds:

1. **Builder stage**: Compiles liboqs from source (requires build tools)
2. **Runtime stage**: Minimal Python image with only runtime dependencies
3. Build tools, source code, and intermediate artifacts are not in the final image

### Health Check

```yaml
healthcheck:
  test: ["CMD-SHELL", "curl -f http://localhost:8080/health || exit 1"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 30s
```

---

## Operational Security

### Production Deployment Checklist

**Before deploying:**

- [ ] Generate unique token secrets (min 32 chars each)
- [ ] Set a strong `POSTGRES_PASSWORD`
- [ ] Verify `ALLOW_INSECURE_DEFAULTS=false` (or not set)
- [ ] Configure `CORS_ORIGINS` with specific origins (not `*`)
- [ ] Set `DEBUG=false`
- [ ] Configure reverse proxy with TLS termination
- [ ] Set up log rotation for security logs
- [ ] Configure firewall rules (only expose reverse proxy port)
- [ ] Set `KEYSERVER_BASE_URL` to public URL (if using email registration)
- [ ] Test SMTP configuration
- [ ] Run database migrations
- [ ] Verify health endpoint: `curl https://your-server/health`

**For mTLS modules (Pepper/Integrity):**

- [ ] Generate CA certificate and client certificates
- [ ] Configure Nginx with mTLS (see docs/MTLS_SETUP.md)
- [ ] Set trusted proxy IPs (as narrow as possible)
- [ ] Generate Fernet key for TOTP encryption (Pepper)
- [ ] Test mTLS authentication end-to-end

### Monitoring

**Endpoints to monitor:**

| Endpoint | Expected | Meaning |
|----------|----------|---------|
| `GET /health` | `{"status": "healthy"}` | Server is running |
| `GET /ready` | `{"status": "ready"}` | Server can accept requests |
| `GET /info` | Module list | Shows enabled modules |

**Metrics to watch:**
- Security log volume (spikes may indicate attack)
- TOTP lockout events (brute force attempts)
- Rate limit hits (429 responses)
- Authentication failures (401 responses)
- Database connection pool utilization
- Response latency (may indicate resource exhaustion)

### Incident Response

**Token compromise:**
1. Rotate the affected module's token secret
2. Restart the server (invalidates all existing tokens)
3. All clients must re-register or re-login

**Database compromise:**
1. Rotate `POSTGRES_PASSWORD`
2. Rotate all token secrets
3. Rotate `PEPPER_TOTP_SECRET_KEY` (if Pepper module used)
4. Invalidate all TOTP secrets (clients must re-setup)
5. Review access logs for unauthorized operations

**Certificate compromise (mTLS):**
1. Revoke the compromised client certificate
2. Re-generate CA if CA key compromised
3. Distribute new certificates to legitimate clients
4. Review security logs for the compromised fingerprint

### Backup and Recovery

**What to back up:**
- PostgreSQL database (contains all client data, keys, peppers)
- `.env` file (contains all secrets)
- Certificate files (CA cert, server certs, client certs)
- Security logs (audit trail)

**What NOT to back up to shared storage:**
- Token secrets (keep in secure vault or `.env` only)
- TOTP encryption key (keep in secure vault or `.env` only)
- Client private keys (clients manage their own)

**Recovery:**
1. Restore PostgreSQL from backup
2. Restore `.env` with same secrets (or rotate and have clients re-authenticate)
3. Restore certificates
4. Start server and verify health endpoint
5. If secrets were rotated, notify clients to re-register/re-login
