# Keyserver API Reference

Complete API documentation for the OpenSSL Encrypt Keyserver module.

## Table of Contents

- [Overview](#overview)
- [Authentication](#authentication)
- [Token Lifecycle](#token-lifecycle)
- [Endpoints](#endpoints)
  - [Registration](#registration)
  - [Login](#login)
  - [Email Registration](#email-registration)
  - [Email Confirmation](#email-confirmation)
  - [Registration Status (Polling)](#registration-status-polling)
  - [Upload Key](#upload-key)
  - [Search Key](#search-key)
  - [Revoke Key](#revoke-key)
  - [Refresh Token](#refresh-token)
- [Schemas](#schemas)
- [Registration Flows](#registration-flows)
  - [Anonymous Registration](#anonymous-registration-flow)
  - [Email-Confirmed Registration](#email-confirmed-registration-flow)
  - [Login with Client ID](#login-with-client-id-flow)
- [Search Logic](#search-logic)
- [Post-Quantum Cryptography](#post-quantum-cryptography)
- [Rate Limits](#rate-limits)
- [Error Handling](#error-handling)
- [Configuration](#configuration)
- [Database Models](#database-models)
- [Security Controls](#security-controls)

---

## Overview

The keyserver provides a public key directory for post-quantum cryptographic key bundles. It supports:

- **Key distribution**: Upload and search for PQC public keys (ML-KEM + ML-DSA)
- **Email-confirmed registration**: Verified account creation with email confirmation
- **JWT authentication**: Stateless token-based auth with sliding expiration
- **Module isolation**: Keyserver tokens cannot be used for other server modules
- **Audit logging**: All key operations logged with client IP

Base URL: `https://<your-server>/api/v1/keys`

---

## Authentication

The keyserver uses JWT Bearer tokens for authenticated operations.

### Public Endpoints (no authentication)

| Endpoint | Purpose |
|----------|---------|
| `POST /register` | Anonymous registration |
| `POST /login` | Login with client_id + password |
| `POST /register/email` | Email registration |
| `GET /confirm/{token}` | Validate token, show password form |
| `POST /confirm/{token}` | Complete registration with password |
| `GET /register/status/{id}` | Poll registration status |
| `GET /search` | Search for public keys |
| `POST /refresh` | Refresh expired token |

### Authenticated Endpoints (Bearer token required)

| Endpoint | Purpose |
|----------|---------|
| `POST /` | Upload public key |
| `POST /{fingerprint}/revoke` | Revoke public key |

**Header format:**

```
Authorization: Bearer <access_token>
```

### Module Isolation

Each server module uses a separate JWT secret and issuer:

| Module | Issuer Claim | Secret Variable |
|--------|-------------|-----------------|
| Keyserver | `openssl_encrypt_keyserver` | `KEYSERVER_TOKEN_SECRET` |
| Telemetry | `openssl_encrypt_telemetry` | `TELEMETRY_TOKEN_SECRET` |

A keyserver token **cannot** be used for telemetry endpoints, and vice versa.

---

## Token Lifecycle

### Token Types

| Token | TTL | Purpose |
|-------|-----|---------|
| Access token | 60 minutes | API authentication (Bearer header) |
| Refresh token | 7 days | Obtain new token pair (sliding expiration) |

### JWT Claims

Every token contains:

| Claim | Description | Example |
|-------|-------------|---------|
| `sub` | Client ID (subject) | `cd94f345a0067203e01212fb4fa9ff8b` |
| `iss` | Issuer | `openssl_encrypt_keyserver` |
| `exp` | Expiration (UTC) | `1774527177` |
| `iat` | Issued at (UTC) | `1774523577` |
| `jti` | Unique token ID (16 hex chars) | `964cfc5dc2a7b76e` |
| `type` | Token type | `access` or `refresh` |

### Sliding Expiration

Active clients are never locked out:

1. Client uses access token (60 min) for API calls
2. Before expiry, client sends refresh token to `POST /refresh`
3. Server returns **new** access token (60 min) + **new** refresh token (7 days)
4. Old refresh token is revoked (replay prevention)
5. Repeat indefinitely while active

### Token Expiry Scenarios

| Scenario | Result | Resolution |
|----------|--------|------------|
| Access token expired, refresh token valid | Refresh succeeds | Automatic (plugin handles this) |
| Both tokens expired (7+ days inactive) | 401 on all requests | `POST /login` with client_id + password |
| Refresh token reused (replay) | 401 Unauthorized | `POST /login` with client_id + password |

---

## Endpoints

### Registration

Create a new client account with immediate token issuance.

```
POST /api/v1/keys/register
```

**Rate limit:** 10/hour

**Headers:**

| Header | Required | Description |
|--------|----------|-------------|
| `X-Registration-Secret` | Only if `REGISTRATION_SECRET` is configured | Registration gate secret |

**Request body:** None

**Response:** `200 OK`

```json
{
  "client_id": "cd94f345a0067203e01212fb4fa9ff8b",
  "token": "eyJhbGciOiJIUzI1NiI...",
  "access_token": "eyJhbGciOiJIUzI1NiI...",
  "refresh_token": "eyJhbGciOiJIUzI1NiI...",
  "expires_at": "2026-03-26T12:00:00Z",
  "refresh_expires_at": "2026-04-02T11:00:00Z",
  "token_type": "Bearer"
}
```

**Errors:**

| Status | Condition | Detail |
|--------|-----------|--------|
| 403 | Invalid or missing registration secret | `"Invalid or missing registration secret"` |

---

### Login

Exchange a client_id and password for JWT access and refresh tokens.

```
POST /api/v1/keys/login
```

**Rate limit:** 5/minute

**Request body:**

```json
{
  "client_id": "cd94f345a0067203e01212fb4fa9ff8b",
  "password": "your-secure-password"
}
```

The `password` field is required for accounts registered with a password (email-confirmed registration). Legacy accounts registered without a password will receive a `403` prompting them to set one.

**Response:** `200 OK`

```json
{
  "client_id": "cd94f345a0067203e01212fb4fa9ff8b",
  "token": "eyJhbGciOiJIUzI1NiI...",
  "access_token": "eyJhbGciOiJIUzI1NiI...",
  "refresh_token": "eyJhbGciOiJIUzI1NiI...",
  "expires_at": "2026-03-26T12:00:00Z",
  "refresh_expires_at": "2026-04-02T11:00:00Z",
  "token_type": "Bearer"
}
```

**Errors:**

| Status | Condition | Detail |
|--------|-----------|--------|
| 401 | Invalid client_id or wrong password | `"Invalid credentials"` |
| 403 | Legacy account without password | `"Password required"` (with instructions to set one) |

**Security:**
- Strict rate limiting (5/min) prevents brute force
- Constant-time comparison via `hmac.compare_digest`
- Password verified with Argon2id (time-hard, memory-hard KDF)
- Generic error message prevents client_id/password enumeration

---

### Email Registration

Register with email confirmation. Sends a verification link valid for 30 minutes.

```
POST /api/v1/keys/register/email
```

**Rate limit:** 5/hour

**Request body:**

```json
{
  "email": "alice@example.com"
}
```

**Response:** `202 Accepted`

```json
{
  "registration_id": "0Y_juYjsglgjPqokTJqqLINS8ZeST5bM1WTA8fJVTr0",
  "message": "Confirmation email sent. Please check your inbox and click the link within 30 minutes."
}
```

**Errors:**

| Status | Condition | Detail |
|--------|-----------|--------|
| 409 | Email already registered | `"An account with this email already exists"` |

**Notes:**
- If a pending registration exists for the same email, it is replaced (new token, new expiry)
- The `registration_id` is used to poll for completion via the status endpoint

---

### Email Confirmation (Step 1: Validate Token)

Validate the confirmation token from the email link. For browsers, renders a password form. For API clients, returns a JSON status indicating the token is valid.

```
GET /api/v1/keys/confirm/{token}
```

**Rate limit:** 20/hour

**Response (API client, token valid):** `200 OK`

```json
{
  "status": "valid",
  "message": "Token valid. Submit POST with password to complete registration."
}
```

**Response (browser):** HTML page with a password form.

**Response (already confirmed):** `200 OK`

```json
{
  "client_id": "cd94f345a0067203e01212fb4fa9ff8b",
  "message": "Account already activated."
}
```

**Errors:**

| Status | Condition | Detail |
|--------|-----------|--------|
| 404 | Invalid token | `"Invalid confirmation token"` |
| 410 | Token expired (>30 min) | `"Confirmation link has expired. Please register again."` |

---

### Email Confirmation (Step 2: Set Password)

Complete email registration by submitting a password. Creates the account with Argon2id-hashed password.

```
POST /api/v1/keys/confirm/{token}
```

**Rate limit:** 20/hour

**Request body:**

```json
{
  "password": "your-secure-password-min-12-chars"
}
```

**Response (API client):** `200 OK`

```json
{
  "client_id": "cd94f345a0067203e01212fb4fa9ff8b",
  "message": "Account activated successfully. Your client ID has also been sent to your email."
}
```

**Response (browser):** HTML page displaying the client_id with copy-to-clipboard button.

**Errors:**

| Status | Condition | Detail |
|--------|-----------|--------|
| 404 | Invalid token | `"Invalid confirmation token"` |
| 410 | Token expired (>30 min) | `"Confirmation link has expired. Please register again."` |
| 422 | Password too short/long | Validation error (min 12, max 128 chars) |

**Notes:**
- Browser detection via `Accept: text/html` header
- Sends a welcome email containing the client_id
- Password is hashed with Argon2id before storage
- The client plugin obtains JWT tokens by polling the status endpoint (not from this response)

---

### Registration Status (Polling)

Poll for email registration completion. Used by the CLI plugin to wait for confirmation.

```
GET /api/v1/keys/register/status/{registration_id}
```

**Rate limit:** 60/hour

**Response (pending):** `200 OK`

```json
{
  "status": "pending"
}
```

**Response (confirmed):** `200 OK`

```json
{
  "status": "confirmed",
  "client_id": "cd94f345a0067203e01212fb4fa9ff8b",
  "access_token": "eyJhbGciOiJIUzI1NiI...",
  "refresh_token": "eyJhbGciOiJIUzI1NiI...",
  "expires_at": "2026-03-26T12:00:00Z",
  "refresh_expires_at": "2026-04-02T11:00:00Z",
  "token_type": "Bearer"
}
```

**Errors:**

| Status | Condition | Detail |
|--------|-----------|--------|
| 404 | Registration not found | `"Registration not found"` |
| 410 | Registration expired | `"Registration has expired. Please register again."` |

**Notes:**
- JWT tokens are only delivered once. After delivery, the pending record is deleted.
- Confirmed records are kept for 5 minutes as a grace period for late polling.

---

### Upload Key

Upload a post-quantum public key bundle to the keyserver.

```
POST /api/v1/keys
```

**Rate limit:** 60/minute
**Authentication:** Required (Bearer token)

**Request body:**

```json
{
  "name": "Alice Smith",
  "email": "alice@example.com",
  "fingerprint": "3a:4b:5c:d1:e2:f6:...",
  "created_at": "2026-03-26T11:00:00Z",
  "encryption_public_key": "<base64-encoded ML-KEM public key>",
  "signing_public_key": "<base64-encoded ML-DSA public key>",
  "encryption_algorithm": "ML-KEM-768",
  "signing_algorithm": "ML-DSA-65",
  "self_signature": "<base64-encoded self-signature>"
}
```

**Algorithm whitelist:**

| Type | Allowed Values |
|------|---------------|
| Encryption (KEM) | `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024` |
| Signing (DSA) | `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87` |

**Response:** `200 OK`

```json
{
  "success": true,
  "fingerprint": "3a:4b:5c:d1:e2:f6:...",
  "message": "Key uploaded successfully"
}
```

**Errors:**

| Status | Condition | Detail |
|--------|-----------|--------|
| 400 | Signature or fingerprint verification failed | `"Verification failed"` |
| 401 | Missing or invalid JWT token | `"Authorization required"` |
| 409 | Key with fingerprint already exists | `"Key with fingerprint X already exists"` |

**Server-side verification before storage:**
1. Self-signature verified using liboqs ML-DSA
2. Fingerprint recalculated as `SHA-256(encryption_key + signing_key)` and compared
3. Algorithm checked against whitelist
4. Re-uploading a revoked key un-revokes it

---

### Search Key

Search for a public key by fingerprint, name, or email. **Public endpoint** (no authentication).

```
GET /api/v1/keys/search?q=<query>
```

**Rate limit:** 100/minute

**Query parameters:**

| Param | Required | Description |
|-------|----------|-------------|
| `q` | Yes | Search query: fingerprint, fingerprint prefix, name, or email |

**Response (found):** `200 OK`

```json
{
  "key": {
    "name": "Alice Smith",
    "email": "alice@example.com",
    "fingerprint": "3a:4b:5c:d1:e2:f6:...",
    "created_at": "2026-03-26T11:00:00Z",
    "encryption_public_key": "<base64>",
    "signing_public_key": "<base64>",
    "encryption_algorithm": "ML-KEM-768",
    "signing_algorithm": "ML-DSA-65",
    "self_signature": "<base64>"
  },
  "message": "Key found"
}
```

**Errors:**

| Status | Condition | Detail |
|--------|-----------|--------|
| 404 | No matching key | `"Key not found"` |

**Notes:**
- Only returns non-revoked keys
- Returns most recently created key if multiple matches

---

### Revoke Key

Revoke a public key. Requires proof of ownership via revocation signature.

```
POST /api/v1/keys/{fingerprint}/revoke
```

**Rate limit:** 60/minute
**Authentication:** Required (Bearer token)

**Request body:**

```json
{
  "signature": "<hex-encoded revocation signature>"
}
```

The revocation signature is created by signing the fingerprint string with the key's ML-DSA private key.

**Response:** `200 OK`

```json
{
  "success": true,
  "fingerprint": "3a:4b:5c:d1:e2:f6:...",
  "message": "Key revoked successfully"
}
```

**Errors:**

| Status | Condition | Detail |
|--------|-----------|--------|
| 400 | Invalid revocation signature | `"Invalid revocation signature: ..."` |
| 401 | Missing or invalid JWT token | `"Authorization required"` |
| 404 | Key not found | `"Key not found"` |

**Notes:**
- Revoked keys are marked but not deleted
- Revoked keys are excluded from search results
- Re-uploading a revoked key un-revokes it

---

### Refresh Token

Exchange a refresh token for a new access + refresh token pair (sliding expiration).

```
POST /api/v1/keys/refresh
```

**Rate limit:** 60/hour

**Request body:**

```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiI..."
}
```

**Response:** `200 OK`

```json
{
  "client_id": "cd94f345a0067203e01212fb4fa9ff8b",
  "token": "eyJhbGciOiJIUzI1NiI...",
  "access_token": "eyJhbGciOiJIUzI1NiI...",
  "refresh_token": "eyJhbGciOiJIUzI1NiI...",
  "expires_at": "2026-03-26T13:00:00Z",
  "refresh_expires_at": "2026-04-03T12:00:00Z",
  "token_type": "Bearer"
}
```

**Errors:**

| Status | Condition | Detail |
|--------|-----------|--------|
| 401 | Invalid, expired, or already-used refresh token | `"Invalid or expired refresh token"` |
| 401 | Access token sent instead of refresh token | `"Invalid token type. Refresh token required."` |

**Security:**
- Refresh token is sent in POST body (not query params or headers)
- Old refresh token is revoked after use (replay prevention)
- Both tokens in the response are new

---

## Schemas

### RegisterResponse

```json
{
  "client_id": "string",
  "token": "string",
  "access_token": "string | null",
  "refresh_token": "string | null",
  "expires_at": "string (ISO 8601)",
  "refresh_expires_at": "string | null (ISO 8601)",
  "token_type": "string (default: Bearer)"
}
```

### LoginRequest

```json
{
  "client_id": "string (1-255 chars)",
  "password": "string (8-128 chars, optional for legacy accounts)"
}
```

### ConfirmWithPasswordRequest

```json
{
  "password": "string (12-128 chars, required)"
}
```

### RefreshRequest

```json
{
  "refresh_token": "string"
}
```

### EmailRegisterRequest

```json
{
  "email": "string (valid email, max 255 chars)"
}
```

### EmailRegisterResponse

```json
{
  "registration_id": "string",
  "message": "string"
}
```

### ConfirmationResponse

```json
{
  "client_id": "string",
  "message": "string"
}
```

### RegistrationStatusResponse

```json
{
  "status": "string (pending | confirmed)",
  "client_id": "string | null",
  "access_token": "string | null",
  "refresh_token": "string | null",
  "expires_at": "string | null",
  "refresh_expires_at": "string | null",
  "token_type": "string | null"
}
```

### KeyBundleSchema

```json
{
  "name": "string (1-255 chars)",
  "email": "string | null (max 255 chars)",
  "fingerprint": "string (1-255 chars)",
  "created_at": "string (ISO 8601)",
  "encryption_public_key": "string (base64)",
  "signing_public_key": "string (base64)",
  "encryption_algorithm": "ML-KEM-512 | ML-KEM-768 | ML-KEM-1024",
  "signing_algorithm": "ML-DSA-44 | ML-DSA-65 | ML-DSA-87",
  "self_signature": "string (base64)"
}
```

### KeyUploadResponse

```json
{
  "success": true,
  "fingerprint": "string",
  "message": "string"
}
```

### KeySearchResponse

```json
{
  "key": "KeyBundleSchema | null",
  "message": "string | null"
}
```

### RevocationRequest

```json
{
  "signature": "string (hex-encoded)"
}
```

### RevocationResponse

```json
{
  "success": true,
  "fingerprint": "string",
  "message": "string"
}
```

### ErrorResponse

```json
{
  "detail": "string",
  "success": false
}
```

---

## Registration Flows

### Anonymous Registration Flow

```
Client                                Server
  |                                      |
  |  POST /register                      |
  |  [X-Registration-Secret: optional]   |
  |------------------------------------->|
  |                                      |  Generate client_id
  |                                      |  Create KSClient record
  |                                      |  Generate token pair
  |  200 OK                              |
  |  {client_id, access_token,           |
  |   refresh_token, expires_at}         |
  |<-------------------------------------|
  |                                      |
  |  Ready for authenticated operations  |
```

### Email-Confirmed Registration Flow

```
Client (Plugin)          Server                    User (Browser/Email)
  |                        |                           |
  |  POST /register/email  |                           |
  |  {"email": "..."}      |                           |
  |----------------------->|                           |
  |                        |  Create pending record    |
  |                        |  Send confirmation email  |
  |  202 Accepted          |        ------------------>|
  |  {registration_id}     |                           |
  |<-----------------------|                           |
  |                        |                           |
  |  GET /register/status/{id}                         |
  |----------------------->|                           |
  |  {"status": "pending"} |                           |
  |<-----------------------|                           |
  |                        |                           |
  |  ... polling ...       |   GET /confirm/{token}    |
  |                        |<--------------------------|
  |                        |  Validate token           |
  |                        |  200 OK (password form)-->|
  |                        |                           |
  |                        |   POST /confirm/{token}   |
  |                        |   {"password": "..."}     |
  |                        |<--------------------------|
  |                        |  Hash password (Argon2id) |
  |                        |  Create KSClient          |
  |                        |  Mark confirmed           |
  |                        |  Send welcome email       |
  |                        |  200 OK (HTML/JSON)------>|
  |                        |                           |
  |  GET /register/status/{id}                         |
  |----------------------->|                           |
  |  {"status":"confirmed",|                           |
  |   client_id,           |                           |
  |   access_token,        |                           |
  |   refresh_token}       |                           |
  |<-----------------------|                           |
  |                        |  Delete pending record    |
  |                        |                           |
  |  Tokens saved locally  |                           |
```

### Login with Client ID Flow

For users who registered via email and confirmed in a browser:

```
Client                                Server
  |                                      |
  |  POST /login                         |
  |  {"client_id": "cd94f345...",        |
  |   "password": "..."}                 |
  |------------------------------------->|
  |                                      |  Constant-time lookup
  |                                      |  Verify password (Argon2id)
  |                                      |  Generate token pair
  |  200 OK                              |  Update last_seen
  |  {client_id, access_token,           |
  |   refresh_token, expires_at}         |
  |<-------------------------------------|
  |                                      |
  |  Tokens saved locally                |
```

### Token Refresh Flow

```
Client                                Server
  |                                      |
  |  POST /upload (Bearer: access_token) |
  |------------------------------------->|
  |  401 Unauthorized (token expired)    |
  |<-------------------------------------|
  |                                      |
  |  POST /refresh                       |
  |  {"refresh_token": "eyJ..."}         |
  |------------------------------------->|
  |                                      |  Revoke old refresh token
  |                                      |  Generate new token pair
  |  200 OK                              |
  |  {new access_token,                  |
  |   new refresh_token}                 |
  |<-------------------------------------|
  |                                      |
  |  POST /upload (Bearer: new token)    |
  |------------------------------------->|
  |  200 OK                              |
  |<-------------------------------------|
```

---

## Search Logic

When searching with query `q`, the server checks in priority order:

| Priority | Match Type | Condition |
|----------|-----------|-----------|
| 1 | Exact fingerprint | `fingerprint == q` |
| 2 | Fingerprint prefix | `fingerprint.startswith(q)` |
| 3 | Exact name | `name == q` |
| 4 | Exact email | `email == q` |

**Additional conditions:**
- Only non-revoked keys are returned (`WHERE revoked IS FALSE`)
- Results ordered by creation date (newest first)
- First match by priority order is returned

**Examples:**

| Query | Matches | Priority |
|-------|---------|----------|
| `3a:4b:5c:d1:e2:f6:...` (full) | Exact fingerprint | 1 |
| `3a:4b:5c` (partial) | Fingerprint prefix | 2 |
| `Alice Smith` | Key name | 3 |
| `alice@example.com` | Key email | 4 |

---

## Post-Quantum Cryptography

The keyserver uses [liboqs](https://github.com/open-quantum-safe/liboqs) (Open Quantum Safe) for signature verification.

### Supported Algorithms

**Key Encapsulation (Encryption):**

| Algorithm | Security Level | NIST Category |
|-----------|---------------|---------------|
| ML-KEM-512 | 128-bit | Category 1 |
| ML-KEM-768 | 192-bit (recommended) | Category 3 |
| ML-KEM-1024 | 256-bit | Category 5 |

**Digital Signatures (Signing):**

| Algorithm | Security Level | NIST Category |
|-----------|---------------|---------------|
| ML-DSA-44 | 128-bit | Category 2 |
| ML-DSA-65 | 192-bit (recommended) | Category 3 |
| ML-DSA-87 | 256-bit | Category 5 |

### Upload Verification

When a key bundle is uploaded, the server performs:

1. **Self-signature verification**: The `self_signature` is verified against the `signing_public_key` using liboqs. The signed message is a deterministic JSON serialization of all bundle fields (except the signature itself), with `sort_keys=True` and compact separators.

2. **Fingerprint verification**: The fingerprint is recalculated as `SHA-256(encryption_public_key + signing_public_key)` formatted as colon-separated hex. Must match the provided fingerprint.

3. **Algorithm validation**: Both `encryption_algorithm` and `signing_algorithm` must be in the whitelist above.

### Revocation Verification

For key revocation, the server verifies:

- The revocation signature is over the fingerprint string (UTF-8 encoded)
- Verified using the key's `signing_public_key` and `signing_algorithm`
- Proves the requester has access to the private signing key

---

## Rate Limits

All rate limits are per-client-IP using the `slowapi` library.

| Endpoint | Method | Limit | Purpose |
|----------|--------|-------|---------|
| `/register` | POST | 10/hour | Prevent mass registration |
| `/login` | POST | 5/minute | Prevent brute force |
| `/register/email` | POST | 5/hour | Prevent email spam |
| `/confirm/{token}` | GET | 20/hour | Reasonable for email clicks |
| `/confirm/{token}` | POST | 20/hour | Password submission |
| `/register/status/{id}` | GET | 60/hour | Allow polling |
| `/` (upload) | POST | 60/minute | Allow normal uploads |
| `/search` | GET | 100/minute | Allow public lookups |
| `/{fp}/revoke` | POST | 60/minute | Allow revocation |
| `/refresh` | POST | 60/hour | Periodic refresh |

When exceeded, the server returns `429 Too Many Requests`.

---

## Error Handling

### HTTP Status Codes

| Status | Meaning | Used By |
|--------|---------|---------|
| 200 | Success | Most endpoints |
| 202 | Accepted (async) | Email registration |
| 400 | Bad request / validation error | Upload (bad signature/fingerprint) |
| 401 | Unauthorized | Login, authenticated endpoints, refresh |
| 403 | Forbidden | Registration (bad secret) |
| 404 | Not found | Search, confirm, status, revoke |
| 409 | Conflict | Upload (duplicate), email register (duplicate) |
| 410 | Gone (expired) | Confirm, status |
| 429 | Rate limit exceeded | All endpoints |

### Information Disclosure Prevention

All error messages are generic to prevent enumeration:

| Endpoint | Error | Message |
|----------|-------|---------|
| `/login` | Invalid client_id | `"Invalid credentials"` |
| `/confirm/{token}` | Invalid token | `"Invalid confirmation token"` |
| `/register/status/{id}` | Not found | `"Registration not found"` |

---

## Configuration

### Environment Variables

#### Keyserver Module

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `KEYSERVER_ENABLED` | bool | `true` | Enable/disable keyserver module |
| `KEYSERVER_TOKEN_SECRET` | str | **required** | JWT signing secret (min 32 chars, must be unique) |
| `KEYSERVER_BASE_URL` | str | `""` | Base URL for email confirmation links |
| `KEYSERVER_REQUIRE_EMAIL_VERIFICATION` | bool | `false` | Require email confirmation for registration |
| `REGISTRATION_SECRET` | str | `null` | Optional secret for gating registration |

#### SMTP (for email registration)

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SMTP_HOST` | str | `""` | SMTP server hostname |
| `SMTP_PORT` | int | `587` | SMTP server port |
| `SMTP_USERNAME` | str | `null` | SMTP username |
| `SMTP_PASSWORD` | str | `null` | SMTP password |
| `SMTP_USE_TLS` | bool | `true` | Use STARTTLS |
| `SMTP_VERIFY_TLS` | bool | `true` | Verify TLS certificate (set `false` for internal servers) |
| `SMTP_FROM_ADDRESS` | str | `""` | Sender email address |

---

## Database Models

### ks_clients

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID | Primary key |
| `client_id` | VARCHAR(64) | Unique client identifier (indexed) |
| `email` | VARCHAR(255) | Email address (unique, nullable, indexed) |
| `created_at` | TIMESTAMPTZ | Registration timestamp |
| `last_seen_at` | TIMESTAMPTZ | Last API activity (nullable) |
| `client_metadata` | JSON | Optional metadata |

### ks_keys

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID | Primary key |
| `fingerprint` | VARCHAR(100) | SHA-256 fingerprint (unique, indexed) |
| `name` | VARCHAR(255) | Key owner name (indexed) |
| `email` | VARCHAR(255) | Key owner email (nullable, indexed) |
| `bundle_json` | TEXT | Full KeyBundleSchema as JSON |
| `encryption_algorithm` | VARCHAR(50) | e.g., `ML-KEM-768` |
| `signing_algorithm` | VARCHAR(50) | e.g., `ML-DSA-65` |
| `revoked` | BOOLEAN | Revocation status (default: false) |
| `revoked_at` | TIMESTAMPTZ | Revocation timestamp (nullable) |
| `owner_client_id` | VARCHAR(64) | Uploader's client_id |
| `created_at` | TIMESTAMPTZ | Upload timestamp |
| `updated_at` | TIMESTAMPTZ | Last update timestamp |
| `upload_count` | INTEGER | Re-upload counter (default: 1) |

### ks_pending_registrations

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID | Primary key |
| `email` | VARCHAR(255) | Registrant email (unique, indexed) |
| `confirmation_token` | VARCHAR(64) | Token for email link (unique, indexed) |
| `registration_id` | VARCHAR(64) | ID for status polling (unique, indexed) |
| `status` | VARCHAR(20) | `pending` or `confirmed` |
| `client_id` | VARCHAR(64) | Assigned after confirmation (nullable) |
| `created_at` | TIMESTAMPTZ | Registration timestamp |
| `expires_at` | TIMESTAMPTZ | Confirmation deadline (30 min) |
| `confirmed_at` | TIMESTAMPTZ | Confirmation timestamp (nullable) |

### ks_access_log

| Column | Type | Description |
|--------|------|-------------|
| `id` | SERIAL | Primary key |
| `key_fingerprint` | VARCHAR(100) | Key involved |
| `action` | VARCHAR(20) | `upload`, `search`, or `revoke` |
| `client_id` | VARCHAR(64) | Acting client (nullable) |
| `ip_address` | VARCHAR(45) | Client IP (nullable) |
| `timestamp` | TIMESTAMPTZ | Action timestamp (indexed) |

---

## Security Controls

| Control | Mechanism | Purpose |
|---------|-----------|---------|
| PQC signature verification | liboqs ML-DSA | Ensure key authenticity |
| Fingerprint validation | SHA-256 recalculation | Ensure key integrity |
| Token isolation | Separate issuer per module | Prevent cross-module attacks |
| Revocation signatures | ML-DSA over fingerprint | Prove key ownership |
| Rate limiting | slowapi per-endpoint | Prevent brute force / DoS |
| Constant-time comparison | `hmac.compare_digest` | Prevent timing attacks |
| Algorithm whitelist | Schema validation | Prevent weak algorithms |
| Generic errors | Uniform messages | Prevent information disclosure |
| Audit logging | ks_access_log table | Forensic trail |
| Refresh token revocation | In-memory jti set | Prevent replay attacks |
