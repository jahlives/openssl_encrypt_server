# Keyserver Security Review — Remaining Findings

     Reviewed: 2026-03-27
     Scope: commits cd0b704 through 311990e (token revocation, registration gating, email-confirmed registration, login endpoint, PoP challenges)

     ## Completed

     - [x] **#2 CRITICAL** — Registration secret comparison timing attack → `af22fd5`
     - [x] **#3 CRITICAL** — `get_client_by_id` full table scan DoS → `f691582`

     ## Remaining

     ### HIGH

     #### #1 — client_id as sole auth factor (architectural)
     - **Location:** `routes.py` login endpoint, entire auth model
     - **Issue:** `client_id` is effectively a password — anyone who obtains it gets full access. It's sent in plaintext in the welcome email and displayed in the browser confirmation page. No second factor, no password change, no revocation path for compromised client_ids.
     - **Risk:** Email interception or account compromise = full account takeover with no mitigation.
     - **Recommendation:** Consider optional client-side key derivation or document this threat model clearly. Tighten per-IP rate limits on `/login`.

     #### #4 — Token revocation store is in-memory only
     - **Location:** `core/auth/token.py:84` — `self._revoked_jtis: Set[str] = set()`
     - **Issue:** Revoked JTIs stored in a Python set. On server restart, all revocation records lost. Revoked refresh tokens become usable again. 7-day refresh token lifetime makes this particularly dangerous.
     - **Recommendation:** Persist revoked JTIs to database or Redis. Clean up expired JTIs periodically.

     #### #5 — Email enumeration via 409 on registration
     - **Location:** `service.py` `create_pending_registration` — returns 409 if email exists
     - **Issue:** `/register/email` reveals whether an email is already registered. Rate limit of 5/hour helps but doesn't eliminate risk.
     - **Recommendation:** Always return 202 regardless. If email exists, send "someone tried to register" notification instead.

     #### #6 — Confirmation token lookup not constant-time
     - **Location:** `service.py` `confirm_registration` and `check_registration_status`
     - **Issue:** Direct SQL WHERE equality on confirmation_token and registration_id. 256-bit entropy makes practical exploitation extremely unlikely, but inconsistent with constant-time philosophy applied elsewhere.
     - **Recommendation:** Low priority given token entropy. Could apply same HMAC-column pattern if desired.

     #### #7 — Email HTML injection in welcome/confirmation emails
     - **Location:** `core/email.py:108-119` — `send_welcome_email` and `send_confirmation_email`
     - **Issue:** `client_id`, `token`, and `base_url` interpolated into HTML without escaping. Currently safe (hex values, admin-controlled base_url) but fragile.
     - **Recommendation:** Use `html.escape()` for all interpolated values in email templates, as already done in `_render_confirmation_html`.

     ### MEDIUM

     #### #8 — SMTP TLS verification bypass lacks guardrails
     - **Location:** `config.py`, `core/email.py:71-74`
     - **Issue:** `SMTP_VERIFY_TLS=false` disables hostname and cert verification. No warning logged, no requirement that `ALLOW_INSECURE_DEFAULTS=true` is also set.
     - **Recommendation:** Log security warning when `smtp_verify_tls=False`. Consider requiring `ALLOW_INSECURE_DEFAULTS=true` to use it.

     #### #9 — Race condition in email registration
     - **Location:** `service.py` `create_pending_registration`
     - **Issue:** Check-then-act between checking for existing client/pending and insert is not atomic. Concurrent requests with same email → DB unique constraint violation (500) instead of clean 409.
     - **Recommendation:** Catch `IntegrityError` and return 409, or use `INSERT ... ON CONFLICT`.

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
