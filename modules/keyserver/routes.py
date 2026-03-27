#!/usr/bin/env python3
"""
Keyserver API Routes

Endpoints:
- POST /api/v1/keys/register - Register new client (no auth)
- POST /api/v1/keys/login - Login with client_id to get JWT tokens (no auth)
- POST /api/v1/keys - Upload key (auth required)
- GET /api/v1/keys/search - Search key (public)
- POST /api/v1/keys/{fingerprint}/revoke - Revoke key (auth required)
"""

import hmac
import logging

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query, Request, Security, status
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from slowapi import Limiter
from slowapi.util import get_remote_address

from ...config import settings
from ...core.database import get_db
from .auth import get_keyserver_auth
from .schemas import (
    ChallengeRequest,
    ChallengeResponse,
    ConfirmationResponse,
    ConfirmWithPasswordRequest,
    EmailRegisterRequest,
    EmailRegisterResponse,
    ErrorResponse,
    KeyListSearchResponse,
    KeySearchResponse,
    KeyUploadResponse,
    KeyUploadWithPoP,
    LoginRequest,
    RefreshRequest,
    RegisterResponse,
    RegistrationStatusResponse,
    RevocationRequest,
    RevocationResponse,
    SetPasswordRequest,
)
from .service import KeyserverService, _DUMMY_HASH, _ph

logger = logging.getLogger(__name__)

router = APIRouter(tags=["keyserver"])

security = HTTPBearer()

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)


# Dependency that lazily gets the auth instance
async def get_current_client(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Security(security),
) -> str:
    """Get current authenticated client ID"""
    auth = get_keyserver_auth()
    payload = auth.verify_token(credentials.credentials)

    # Update last seen (fire and forget)
    try:
        await auth.update_last_seen(payload.sub)
    except Exception:
        pass

    return payload.sub


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_200_OK,
    summary="Register new keyserver client",
)
@limiter.limit("10/hour")
async def register(
    request: Request,
    x_registration_secret: str | None = Header(None, alias="X-Registration-Secret"),
):
    """
    Register a new Keyserver client.

    Returns a JWT token that can ONLY be used for Keyserver endpoints.
    The token includes an issuer claim that prevents cross-module usage.

    If REGISTRATION_SECRET is configured, the X-Registration-Secret header
    must match to complete registration.

    Returns:
        RegisterResponse: Client ID, JWT token, expiration
    """
    if settings.registration_secret:
        if not x_registration_secret or not hmac.compare_digest(x_registration_secret, settings.registration_secret):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid or missing registration secret",
            )

    auth = get_keyserver_auth()
    return await auth.register_client()


@router.post(
    "/login",
    response_model=RegisterResponse,
    status_code=status.HTTP_200_OK,
    responses={
        401: {"model": ErrorResponse, "description": "Invalid credentials"},
        403: {"description": "Password setup required (legacy client)"},
    },
    summary="Login with client ID and password",
)
@limiter.limit("5/minute")
async def login(
    request: Request,
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Authenticate with client_id and password to obtain JWT tokens.

    SECURITY:
    - Strict rate limiting (5/minute) to prevent brute force
    - Returns generic error for invalid credentials (no enumeration)
    - Uses constant-time comparison internally
    - Dummy Argon2 verify on invalid client_id to prevent timing oracle

    Legacy clients (no password set):
    - If no password provided: returns 403 {"status": "password_required"}
    - If password provided: sets it as the account password and issues tokens

    Args:
        request: FastAPI request
        body: LoginRequest containing client_id and optional password
        db: Database session

    Returns:
        RegisterResponse: Access and refresh tokens
    """
    from argon2.exceptions import VerifyMismatchError as _VerifyMismatchError

    auth = get_keyserver_auth()
    service = KeyserverService(db)
    client = await service.get_client_by_id(body.client_id, auth.secret)

    if not client:
        # Dummy Argon2 verify to prevent timing oracle
        if body.password:
            try:
                _ph.verify(_DUMMY_HASH, body.password)
            except _VerifyMismatchError:
                pass
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # Legacy client: no password_hash set yet
    if client.password_hash is None:
        if body.password is None:
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "status": "password_required",
                    "message": "Password setup required. Please set a password to continue.",
                },
            )
        else:
            # Legacy client providing password for first time — set it
            client.password_hash = _ph.hash(body.password)
            await db.commit()
    else:
        # Normal path: verify password
        if body.password is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )
        if not await service.verify_client_password(client, body.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )

    tokens = auth.create_token_pair(body.client_id)

    # Update last seen
    try:
        await auth.update_last_seen(body.client_id)
    except Exception:
        pass

    return RegisterResponse(
        client_id=body.client_id,
        token=tokens["access_token"],
        access_token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        expires_at=tokens["access_token_expires_at"],
        refresh_expires_at=tokens["refresh_token_expires_at"],
        token_type=tokens["token_type"],
    )


@router.post(
    "/register/email",
    response_model=EmailRegisterResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Register with email confirmation",
)
@limiter.limit("5/hour")
async def register_email(
    request: Request,
    body: EmailRegisterRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Register a new keyserver client with email confirmation.

    Sends a confirmation email with a link that expires in 30 minutes.
    The account is only created after the link is clicked.

    Args:
        body: EmailRegisterRequest containing the email address
        request: FastAPI request
        db: Database session

    Returns:
        EmailRegisterResponse: Confirmation message
    """
    service = KeyserverService(db)

    from ...core.email import EmailService
    email_service = EmailService(
        smtp_host=settings.smtp_host,
        smtp_port=settings.smtp_port,
        smtp_username=settings.smtp_username,
        smtp_password=settings.smtp_password,
        smtp_use_tls=settings.smtp_use_tls,
        smtp_verify_tls=settings.smtp_verify_tls,
        smtp_tls_hostname=settings.smtp_tls_hostname,
        from_address=settings.smtp_from_address,
    )

    auth = get_keyserver_auth()
    result = await service.create_pending_registration(
        body.email, settings.keyserver_base_url, email_service, auth.secret
    )

    return EmailRegisterResponse(
        registration_id=result["registration_id"],
        message="Confirmation email sent. Please check your inbox and click the link within 30 minutes.",
    )


@router.get(
    "/confirm/{token}",
    response_model=ConfirmationResponse,
    status_code=status.HTTP_200_OK,
    responses={
        404: {"model": ErrorResponse, "description": "Invalid token"},
        410: {"model": ErrorResponse, "description": "Token expired"},
    },
    summary="Confirm email registration (view password form)",
)
@limiter.limit("20/hour")
async def confirm_registration(
    request: Request,
    token: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Validate confirmation token and serve password form.

    For browsers: renders an HTML page with a password form.
    For API clients: returns JSON indicating the token is valid.

    The account is NOT created until the password is submitted via POST.

    Args:
        token: Confirmation token from the email link
        request: FastAPI request
        db: Database session

    Returns:
        HTML password form (browsers) or JSON validation response (API)
    """
    service = KeyserverService(db)

    auth = get_keyserver_auth()
    accept = request.headers.get("accept", "")
    is_browser = "text/html" in accept

    try:
        pending = await service.validate_confirmation_token(token, auth.secret)
    except HTTPException as e:
        if is_browser:
            return HTMLResponse(
                content=_render_error_html(e.status_code, e.detail),
                status_code=e.status_code,
            )
        raise

    # Already confirmed — show client_id
    if pending.status == "confirmed":
        if is_browser:
            return HTMLResponse(content=_render_confirmation_html(pending.client_id))
        return ConfirmationResponse(
            client_id=pending.client_id,
            message="Account already activated.",
        )

    # Pending — show password form
    if is_browser:
        return HTMLResponse(content=_render_password_form_html(token))

    return {"status": "valid", "message": "Token valid. Submit POST with password to complete registration."}


@router.post(
    "/confirm/{token}",
    response_model=ConfirmationResponse,
    status_code=status.HTTP_200_OK,
    responses={
        404: {"model": ErrorResponse, "description": "Invalid token"},
        410: {"model": ErrorResponse, "description": "Token expired"},
        422: {"model": ErrorResponse, "description": "Invalid password"},
    },
    summary="Complete registration with password",
)
@limiter.limit("20/hour")
async def confirm_registration_with_password(
    request: Request,
    token: str,
    body: ConfirmWithPasswordRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Complete email registration by setting a password.

    Creates the account with the provided password and returns the client_id.

    Args:
        token: Confirmation token from the email link
        body: ConfirmWithPasswordRequest containing the password
        request: FastAPI request
        db: Database session

    Returns:
        ConfirmationResponse: Client ID and confirmation message
    """
    service = KeyserverService(db)

    from ...core.email import EmailService
    email_service = EmailService(
        smtp_host=settings.smtp_host,
        smtp_port=settings.smtp_port,
        smtp_username=settings.smtp_username,
        smtp_password=settings.smtp_password,
        smtp_use_tls=settings.smtp_use_tls,
        smtp_verify_tls=settings.smtp_verify_tls,
        smtp_tls_hostname=settings.smtp_tls_hostname,
        from_address=settings.smtp_from_address,
    )

    auth = get_keyserver_auth()
    accept = request.headers.get("accept", "")
    is_browser = "text/html" in accept

    try:
        result = await service.confirm_registration_with_password(
            token, body.password, auth, email_service
        )
    except HTTPException as e:
        if is_browser:
            return HTMLResponse(
                content=_render_error_html(e.status_code, e.detail),
                status_code=e.status_code,
            )
        raise

    client_id = result["client_id"]

    if is_browser:
        return HTMLResponse(content=_render_confirmation_html(client_id))

    return ConfirmationResponse(
        client_id=client_id,
        message="Account activated successfully. Your client ID has also been sent to your email.",
    )


def _render_confirmation_html(client_id: str) -> str:
    """Render the browser-friendly confirmation page."""
    # Escape client_id for safe HTML embedding (it's hex, but defense in depth)
    import html
    safe_client_id = html.escape(client_id)

    return f"""\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Registration Confirmed</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            max-width: 520px;
            margin: 60px auto;
            padding: 0 20px;
            color: #1a1a1a;
            background: #f8f9fa;
        }}
        .card {{
            background: #fff;
            border-radius: 8px;
            padding: 32px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #16a34a;
            font-size: 24px;
            margin-top: 0;
        }}
        .client-id-box {{
            background: #f4f4f5;
            border: 1px solid #e4e4e7;
            border-radius: 6px;
            padding: 16px;
            font-family: "SF Mono", Monaco, "Cascadia Code", monospace;
            font-size: 15px;
            word-break: break-all;
            position: relative;
            margin: 16px 0;
        }}
        .copy-btn {{
            display: inline-block;
            margin-top: 12px;
            padding: 8px 20px;
            background: #2563eb;
            color: #fff;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
        }}
        .copy-btn:hover {{
            background: #1d4ed8;
        }}
        .copy-btn.copied {{
            background: #16a34a;
        }}
        .note {{
            color: #6b7280;
            font-size: 14px;
            margin-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="card">
        <h1>Registration Confirmed</h1>
        <p>Your keyserver account has been activated successfully.</p>
        <p><strong>Your Client ID:</strong></p>
        <div class="client-id-box" id="clientId">{safe_client_id}</div>
        <button class="copy-btn" onclick="copyClientId(this)">Copy to Clipboard</button>
        <p class="note">
            Add this client ID to your keyserver plugin configuration.
            A copy has also been sent to your email.
        </p>
    </div>
    <script>
        function copyClientId(btn) {{
            var text = document.getElementById('clientId').textContent;
            navigator.clipboard.writeText(text).then(function() {{
                btn.textContent = 'Copied!';
                btn.classList.add('copied');
                setTimeout(function() {{
                    btn.textContent = 'Copy to Clipboard';
                    btn.classList.remove('copied');
                }}, 2000);
            }});
        }}
    </script>
</body>
</html>"""


def _render_password_form_html(token: str) -> str:
    """Render the browser-friendly password form for registration confirmation."""
    import html as _html
    safe_token = _html.escape(token)

    return f"""\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Set Your Password</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            max-width: 520px;
            margin: 60px auto;
            padding: 0 20px;
            color: #1a1a1a;
            background: #f8f9fa;
        }}
        .card {{
            background: #fff;
            border-radius: 8px;
            padding: 32px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2563eb;
            font-size: 24px;
            margin-top: 0;
        }}
        label {{
            display: block;
            margin-top: 16px;
            font-weight: 600;
            font-size: 14px;
        }}
        input[type="password"] {{
            width: 100%;
            padding: 10px 12px;
            margin-top: 6px;
            border: 1px solid #d1d5db;
            border-radius: 6px;
            font-size: 15px;
            box-sizing: border-box;
        }}
        input[type="password"]:focus {{
            outline: none;
            border-color: #2563eb;
            box-shadow: 0 0 0 3px rgba(37,99,235,0.1);
        }}
        .submit-btn {{
            display: block;
            width: 100%;
            margin-top: 20px;
            padding: 12px;
            background: #2563eb;
            color: #fff;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 15px;
            font-weight: 600;
        }}
        .submit-btn:hover {{
            background: #1d4ed8;
        }}
        .submit-btn:disabled {{
            background: #9ca3af;
            cursor: not-allowed;
        }}
        .error {{
            color: #dc2626;
            font-size: 13px;
            margin-top: 6px;
            display: none;
        }}
        .hint {{
            color: #6b7280;
            font-size: 13px;
            margin-top: 4px;
        }}
    </style>
</head>
<body>
    <div class="card">
        <h1>Set Your Password</h1>
        <p>Choose a password to secure your keyserver account.</p>
        <form id="passwordForm" onsubmit="return submitForm(event)">
            <label for="password">Password</label>
            <input type="password" id="password" name="password"
                   minlength="12" maxlength="128" required
                   autocomplete="new-password"
                   placeholder="Minimum 12 characters">
            <p class="hint">Must be at least 12 characters.</p>

            <label for="confirmPassword">Confirm Password</label>
            <input type="password" id="confirmPassword" name="confirmPassword"
                   minlength="12" maxlength="128" required
                   autocomplete="new-password"
                   placeholder="Re-enter your password">
            <p class="error" id="matchError">Passwords do not match.</p>
            <p class="error" id="submitError"></p>

            <button type="submit" class="submit-btn" id="submitBtn">Create Account</button>
        </form>
    </div>
    <script>
        async function submitForm(e) {{
            e.preventDefault();
            var pw = document.getElementById('password').value;
            var cpw = document.getElementById('confirmPassword').value;
            var matchErr = document.getElementById('matchError');
            var submitErr = document.getElementById('submitError');
            var btn = document.getElementById('submitBtn');

            matchErr.style.display = 'none';
            submitErr.style.display = 'none';

            if (pw !== cpw) {{
                matchErr.style.display = 'block';
                return false;
            }}
            if (pw.length < 12) {{
                submitErr.textContent = 'Password must be at least 12 characters.';
                submitErr.style.display = 'block';
                return false;
            }}

            btn.disabled = true;
            btn.textContent = 'Creating account...';

            try {{
                var resp = await fetch('/api/v1/keys/confirm/{safe_token}', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json', 'Accept': 'text/html'}},
                    body: JSON.stringify({{password: pw}})
                }});
                if (resp.ok) {{
                    document.open();
                    document.write(await resp.text());
                    document.close();
                }} else {{
                    var data = await resp.json().catch(function() {{ return {{detail: 'Registration failed.'}}; }});
                    submitErr.textContent = data.detail || 'Registration failed.';
                    submitErr.style.display = 'block';
                    btn.disabled = false;
                    btn.textContent = 'Create Account';
                }}
            }} catch (err) {{
                submitErr.textContent = 'Network error. Please try again.';
                submitErr.style.display = 'block';
                btn.disabled = false;
                btn.textContent = 'Create Account';
            }}
            return false;
        }}
    </script>
</body>
</html>"""


def _render_error_html(status_code: int, detail: str) -> str:
    """Render a browser-friendly error page for confirmation failures."""
    import html
    safe_detail = html.escape(detail)

    if status_code == 410:
        title = "Link Expired"
        color = "#d97706"
    elif status_code == 404:
        title = "Invalid Link"
        color = "#dc2626"
    else:
        title = "Error"
        color = "#dc2626"

    return f"""\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{title}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            max-width: 520px;
            margin: 60px auto;
            padding: 0 20px;
            color: #1a1a1a;
            background: #f8f9fa;
        }}
        .card {{
            background: #fff;
            border-radius: 8px;
            padding: 32px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: {color};
            font-size: 24px;
            margin-top: 0;
        }}
    </style>
</head>
<body>
    <div class="card">
        <h1>{title}</h1>
        <p>{safe_detail}</p>
    </div>
</body>
</html>"""


@router.get(
    "/register/status/{registration_id}",
    response_model=RegistrationStatusResponse,
    status_code=status.HTTP_200_OK,
    responses={
        404: {"model": ErrorResponse, "description": "Registration not found"},
        410: {"model": ErrorResponse, "description": "Registration expired"},
    },
    summary="Check email registration status",
)
@limiter.limit("60/hour")
async def registration_status(
    request: Request,
    registration_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Poll registration status after email registration request.

    Used by the CLI plugin to wait for the user to confirm via email link.
    Returns "pending" while waiting, or "confirmed" with JWT tokens once confirmed.

    Args:
        registration_id: The registration ID from the email registration response
        request: FastAPI request
        db: Database session

    Returns:
        RegistrationStatusResponse: Status and optionally tokens
    """
    service = KeyserverService(db)
    auth = get_keyserver_auth()
    result = await service.check_registration_status(registration_id, auth)

    return RegistrationStatusResponse(**result)


@router.post(
    "/set-password",
    response_model=RegisterResponse,
    status_code=status.HTTP_200_OK,
    responses={
        401: {"model": ErrorResponse, "description": "Invalid client ID"},
        409: {"model": ErrorResponse, "description": "Password already set"},
    },
    summary="Set password for legacy account",
)
@limiter.limit("3/hour")
async def set_password(
    request: Request,
    body: SetPasswordRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Set a password for a legacy account that was created before password auth.

    This endpoint is for clients that received a 403 "password_required" from
    /login. It accepts client_id + new password, sets the password, and returns
    JWT tokens.

    Aggressively rate-limited (3/hour) since it accepts client_id without
    any prior authentication.

    Args:
        request: FastAPI request
        body: SetPasswordRequest with client_id and password
        db: Database session

    Returns:
        RegisterResponse: Access and refresh tokens
    """
    from argon2.exceptions import VerifyMismatchError as _VerifyMismatchError

    auth = get_keyserver_auth()
    service = KeyserverService(db)
    client = await service.get_client_by_id(body.client_id, auth.secret)

    if not client:
        # Dummy Argon2 verify for timing protection
        try:
            _ph.verify(_DUMMY_HASH, body.password)
        except _VerifyMismatchError:
            pass
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if client.password_hash is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Password already set. Use /change-password to update it.",
        )

    client.password_hash = _ph.hash(body.password)
    await db.commit()

    tokens = auth.create_token_pair(body.client_id)

    return RegisterResponse(
        client_id=body.client_id,
        token=tokens["access_token"],
        access_token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        expires_at=tokens["access_token_expires_at"],
        refresh_expires_at=tokens["refresh_token_expires_at"],
        token_type=tokens["token_type"],
    )


@router.post(
    "/challenge",
    response_model=ChallengeResponse,
    status_code=status.HTTP_200_OK,
    responses={
        401: {"model": ErrorResponse, "description": "Authentication required"},
    },
    summary="Request a Proof of Possession challenge",
)
@limiter.limit("30/minute")
async def request_challenge(
    request: Request,
    body: ChallengeRequest,
    db: AsyncSession = Depends(get_db),
    client_id: str = Depends(get_current_client),
):
    """
    Request a single-use challenge for Proof of Possession key upload.

    The returned nonce must be signed with the ML-DSA private key corresponding
    to the bundle being uploaded.  The challenge_id and pop_signature must then
    be included in the subsequent POST / (upload) request.

    Canonical message to sign:
        b"POP:" + nonce.encode("ascii") + b":" + fingerprint.encode("utf-8")

    Challenges expire after 10 minutes and are single-use.

    Args:
        body:      Optional fingerprint hint for operator logging.
        request:   FastAPI request.
        db:        Database session.
        client_id: Authenticated client ID.

    Returns:
        ChallengeResponse: challenge_id, nonce, expires_at
    """
    service = KeyserverService(db)
    result = await service.generate_challenge(
        client_id=client_id,
        fingerprint_hint=body.fingerprint,
        ttl_minutes=settings.keyserver_challenge_ttl_minutes,
    )
    return ChallengeResponse(**result)


@router.post(
    "",
    response_model=KeyUploadResponse,
    status_code=status.HTTP_200_OK,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid bundle or verification failed"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
        409: {"model": ErrorResponse, "description": "Key already exists"},
    },
    summary="Upload public key",
)
@limiter.limit("60/minute")
async def upload_key(
    request: Request,
    bundle: KeyUploadWithPoP,
    db: AsyncSession = Depends(get_db),
    client_id: str = Depends(get_current_client),
):
    """
    Upload public key bundle to keyserver (requires Proof of Possession).

    Two-step flow:
    1. Call POST /challenge to obtain a nonce and challenge_id.
    2. Sign the canonical message with your ML-DSA private key:
          b"POP:" + nonce.encode("ascii") + b":" + fingerprint.encode("utf-8")
    3. Include challenge_id and pop_signature (base64) in this request body.

    SECURITY:
    - Requires Keyserver JWT token
    - Requires valid single-use PoP challenge (proves private key access)
    - Verifies bundle self-signature after PoP
    - Validates fingerprint
    - Enforces algorithm whitelist

    Args:
        bundle: Public key bundle with PoP fields (validated by Pydantic)
        request: FastAPI request
        db: Database session
        client_id: Authenticated client ID

    Returns:
        KeyUploadResponse: Success status and fingerprint
    """
    service = KeyserverService(db)
    ip_address = request.client.host if request.client else None
    return await service.upload_key(client_id, bundle, ip_address)


@router.get(
    "/search",
    response_model=KeyListSearchResponse,
    status_code=status.HTTP_200_OK,
    responses={404: {"model": ErrorResponse, "description": "Key not found"}},
    summary="Search for public key",
)
@limiter.limit("100/minute")
async def search_key(
    request: Request,
    q: str = Query(..., description="Search query: fingerprint, name, or email"),
    db: AsyncSession = Depends(get_db),
):
    """
    Search for public key by fingerprint, name, or email.

    PUBLIC ENDPOINT: No authentication required.

    Search priority:
    1. Exact fingerprint match
    2. Fingerprint prefix match
    3. Exact name match
    4. Exact email match

    Args:
        q: Search query string
        request: FastAPI request
        db: Database session

    Returns:
        KeySearchResponse: Key bundle if found
    """
    service = KeyserverService(db)
    ip_address = request.client.host if request.client else None
    return await service.search_key(q, None, ip_address)


@router.get(
    "/{fingerprint}",
    response_model=KeySearchResponse,
    status_code=status.HTTP_200_OK,
    responses={404: {"model": ErrorResponse, "description": "Key not found"}},
    summary="Get public key by fingerprint",
)
@limiter.limit("100/minute")
async def get_key_by_fingerprint(
    request: Request,
    fingerprint: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Fetch a public key by exact fingerprint.

    PUBLIC ENDPOINT: No authentication required.

    Args:
        fingerprint: Exact fingerprint string
        request: FastAPI request
        db: Database session

    Returns:
        KeySearchResponse: Key bundle if found
    """
    service = KeyserverService(db)
    ip_address = request.client.host if request.client else None
    return await service.get_key_by_fingerprint(fingerprint, None, ip_address)


@router.post(
    "/{fingerprint}/revoke",
    response_model=RevocationResponse,
    status_code=status.HTTP_200_OK,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid revocation signature"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
        404: {"model": ErrorResponse, "description": "Key not found"},
    },
    summary="Revoke public key",
)
@limiter.limit("60/minute")
async def revoke_key(
    request: Request,
    fingerprint: str,
    revocation: RevocationRequest,
    db: AsyncSession = Depends(get_db),
    client_id: str = Depends(get_current_client),
):
    """
    Revoke public key.

    SECURITY:
    - Requires Keyserver JWT token
    - Requires revocation signature (proof of ownership)
    - Marks key as revoked (doesn't delete)

    Args:
        fingerprint: Fingerprint of key to revoke
        revocation: Revocation request with signature
        request: FastAPI request
        db: Database session
        client_id: Authenticated client ID

    Returns:
        RevocationResponse: Success status
    """
    service = KeyserverService(db)
    ip_address = request.client.host if request.client else None
    return await service.revoke_key(fingerprint, revocation, client_id, ip_address)


@router.post(
    "/refresh",
    response_model=RegisterResponse,
    status_code=status.HTTP_200_OK,
    responses={
        401: {"model": ErrorResponse, "description": "Invalid or expired refresh token"},
    },
    summary="Refresh access token",
)
@limiter.limit("60/hour")
async def refresh_token(
    request: Request,
    body: RefreshRequest = Body(...),
):
    """
    Use refresh token to get new access and refresh tokens (sliding expiration).

    SECURITY:
    - Requires valid refresh token (7-day expiry) in POST body (not query params)
    - Returns new token pair with extended expiration
    - Implements sliding expiration: tokens auto-extend on use within TTL

    Token Flow:
    1. Client uses access token (1-hour expiry) for API calls
    2. Before access token expires, client sends refresh token in POST body
    3. Server returns NEW access token (1 hour) + NEW refresh token (7 days)
    4. This provides sliding expiration - active clients never locked out

    Args:
        request: FastAPI request
        body: RefreshRequest containing the refresh token

    Returns:
        RegisterResponse: New access and refresh tokens
    """
    auth = get_keyserver_auth()
    result = auth.refresh_access_token(body.refresh_token)

    return RegisterResponse(
        client_id=result["client_id"],
        token=result["access_token"],  # For backward compatibility
        access_token=result["access_token"],
        refresh_token=result["refresh_token"],
        expires_at=result["access_token_expires_at"],
        refresh_expires_at=result["refresh_token_expires_at"],
        token_type=result["token_type"]
    )
