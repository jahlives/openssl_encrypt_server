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
     - [x] **#8 MEDIUM** — SMTP TLS verification bypass lacks guardrails → `b96eba6` (require ALLOW_INSECURE_DEFAULTS, add SMTP_TLS_HOSTNAME)
     - [x] **#9 MEDIUM** — Race condition in email registration → `2c22320` (catch IntegrityError, return opaque 202)
     - [x] **#10 MEDIUM** — Confirmed registration tokens delivered only once → `e38a4cd` (documented recovery via /login)
     - [x] **#11 MEDIUM** — No owner check on key revocation → `81b1581` (owner_client_id check before signature verification)
     - [x] **#12 LOW** — Log injection via email address → `ea37c4b` (parameterized logging in service.py and email.py)

     ## Remaining

     All findings have been addressed.
