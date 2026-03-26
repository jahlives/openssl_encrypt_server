#!/usr/bin/env python3
"""
Async email service for sending confirmation and welcome emails.

Uses aiosmtplib for non-blocking SMTP communication.
"""

import logging
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

import aiosmtplib

logger = logging.getLogger(__name__)


class EmailService:
    """
    Async email service for keyserver registration flow.

    Sends confirmation emails with time-limited tokens and
    welcome emails containing the client_id after confirmation.
    """

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int = 587,
        smtp_username: Optional[str] = None,
        smtp_password: Optional[str] = None,
        smtp_use_tls: bool = True,
        smtp_verify_tls: bool = True,
        from_address: str = "noreply@example.com",
    ):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_username = smtp_username
        self.smtp_password = smtp_password
        self.smtp_use_tls = smtp_use_tls
        self.smtp_verify_tls = smtp_verify_tls
        self.from_address = from_address

    async def _send_email(self, to: str, subject: str, body_html: str) -> None:
        """
        Send an email via SMTP.

        Args:
            to: Recipient email address
            subject: Email subject line
            body_html: HTML email body
        """
        msg = MIMEMultipart("alternative")
        msg["From"] = self.from_address
        msg["To"] = to
        msg["Subject"] = subject
        msg.attach(MIMEText(body_html, "html"))

        kwargs = {
            "hostname": self.smtp_host,
            "port": self.smtp_port,
            "start_tls": self.smtp_use_tls,
        }
        if self.smtp_use_tls and not self.smtp_verify_tls:
            tls_context = ssl.create_default_context()
            tls_context.check_hostname = False
            tls_context.verify_mode = ssl.CERT_NONE
            kwargs["tls_context"] = tls_context
        if self.smtp_username and self.smtp_password:
            kwargs["username"] = self.smtp_username
            kwargs["password"] = self.smtp_password

        await aiosmtplib.send(msg, **kwargs)
        logger.info(f"Email sent to {to}: {subject}")

    async def send_confirmation_email(
        self, email: str, token: str, base_url: str
    ) -> None:
        """
        Send a registration confirmation email with a time-limited link.

        Args:
            email: Recipient email address
            token: Confirmation token
            base_url: Base URL for building the confirmation link
        """
        confirm_url = f"{base_url.rstrip('/')}/api/v1/keys/confirm/{token}"

        body = f"""\
<html>
<body>
<h2>Confirm your Keyserver Registration</h2>
<p>You have requested to register an account on the OpenSSL Encrypt Keyserver.</p>
<p>Click the link below to confirm your registration. This link expires in <strong>30 minutes</strong>.</p>
<p><a href="{confirm_url}">{confirm_url}</a></p>
<p>If you did not request this registration, you can safely ignore this email.</p>
</body>
</html>"""

        await self._send_email(email, "Confirm your Keyserver Registration", body)

    async def send_welcome_email(self, email: str, client_id: str) -> None:
        """
        Send a welcome email containing the client_id after successful confirmation.

        Args:
            email: Recipient email address
            client_id: The assigned client identifier for the keyserver plugin
        """
        body = f"""\
<html>
<body>
<h2>Keyserver Registration Complete</h2>
<p>Your account has been successfully activated.</p>
<p>Your client ID is:</p>
<pre style="background: #f4f4f4; padding: 12px; font-size: 16px;">{client_id}</pre>
<p>Add this client ID to your keyserver plugin configuration.</p>
<p><strong>Keep this ID safe.</strong> You will need it to authenticate with the keyserver.</p>
</body>
</html>"""

        await self._send_email(email, "Keyserver Registration Complete", body)
