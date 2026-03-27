# Keyserver Security Review — Remaining Findings

     Reviewed: 2026-03-27
     Scope: commits cd0b704 through 311990e (token revocation, registration gating, email-confirmed registration, login endpoint, PoP challenges)

     ## Completed

     - [x] **#2 CRITICAL** — Registration secret comparison timing attack → `af22fd5`
     - [x] **#3 CRITICAL** — `get_client_by_id` full table scan DoS → `f691582`
     - [x] **#1 HIGH** — client_id as sole auth factor → `e3c99d5` (password as 2nd factor with Argon2id)
     - [x] **#4 HIGH** — Token revocation store in-memory only → `18ea650` (persistent DB store)
     - [x] **#5 HIGH** — Email enumeration via 409 on registration → `5064aa4` (opaque 202 response)
     - [x] **#6 HIGH** — Confirmation token lookup not constant-time → `582539b` (HMAC-indexed lookup)
     - [x] **#7 HIGH** — Email HTML injection in templates → `ba19b08` (html.escape on all values)

     ## Remaining

     ### MEDIUM

     #### #8 — SMTP TLS verification bypass lacks guardrails
     - **Location:** `config.py`, `core/email.py:71-74`
     - **Issue:** `SMTP_VERIFY_TLS=false` disables hostname and cert verification. No warning logged, no requirement that `ALLOW_INSECURE_DEFAULTS=true` is also set.
     - **Recommendation:** Log security warning when `smtp_verify_tls=False`. Consider requiring `ALLOW_INSECURE_DEFAULTS=true` to use it.

     #### #9 — Race condition in email registration
     - **Location:** `service.py` `create_pending_registration`
     - **Issue:** Check-then-act between checking for existing client/pending and insert is not atomic. Concurrent requests with same email → DB unique constraint violation (500) instead of opaque 202.
     - **Recommendation:** Catch `IntegrityError` and return opaque 202, or use `INSERT ... ON CONFLICT`.

     #### #10 — Confirmed registration tokens delivered only once
     - **Location:** `service.py` `check_registration_status`
     - **Issue:** On confirmation, tokens are issued and pending record deleted. Network drop before response = tokens lost, record gone. User has account but no tokens.
     - **Recommendation:** Acceptable since `/login` endpoint exists as recovery path. Document this.

     #### #11 — No owner check on key revocation
     - **Location:** `service.py` `revoke_key`
     - **Issue:** Any authenticated client can revoke any key if they provide a valid revocation signature. No check that `client_id == key.owner_client_id`. Cryptographic signature provides strong protection, but defense-in-depth would check ownership too.
     - **Recommendation:** Add `if key.owner_client_id and key.owner_client_id != client_id: raise 403` check.

     ### LOW

     #### #12 — Log injection via email address
     - **Location:** `service.py:357` — `logger.info(f"Pending registration created for {email}")`
     - **Issue:** Pydantic's `EmailStr` limits this, but structured logging would be safer.
     - **Recommendation:** Use structured logging with explicit fields instead of f-string interpolation.
