#!/usr/bin/env python3
"""
Tests for security hardening fixes.

Covers:
- Fix 1: No hardcoded secrets in docker-compose.yml
- Fix 2: Refresh token in POST body (not query param)
- Fix 3: Constant-time hash comparison
- Fix 5: SQLAlchemy filter correctness
- Fix 7: Generic error messages (no internal detail leakage)
- Fix 8: Security validation independent of debug mode
- Fix 10: Migration script reads DB URL from env var
"""

import hmac
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class TestDockerComposeNoHardcodedSecrets(unittest.TestCase):
    """Fix 1: Verify docker-compose.yml has no hardcoded secrets."""

    def setUp(self):
        compose_path = Path(__file__).parent.parent / "docker-compose.yml"
        with open(compose_path) as f:
            self.compose_content = f.read()

    def test_no_default_postgres_password(self):
        """POSTGRES_PASSWORD must not have a default value."""
        self.assertNotIn("change_me_in_production", self.compose_content)
        self.assertIn("POSTGRES_PASSWORD:?", self.compose_content)

    def test_no_default_keyserver_secret(self):
        """KEYSERVER_TOKEN_SECRET must not have a default value."""
        self.assertNotIn("keyserver-secret-min-32-chars-CHANGE-ME", self.compose_content)
        self.assertIn("KEYSERVER_TOKEN_SECRET:?", self.compose_content)

    def test_no_default_telemetry_secret(self):
        """TELEMETRY_TOKEN_SECRET must not have a default value."""
        self.assertNotIn("telemetry-secret-min-32-chars-CHANGE-ME", self.compose_content)
        self.assertIn("TELEMETRY_TOKEN_SECRET:?", self.compose_content)

    def test_no_wildcard_cors_default(self):
        """CORS_ORIGINS must not default to wildcard '*'."""
        # Should have empty default, not wildcard
        self.assertNotIn("CORS_ORIGINS:-*}", self.compose_content)
        self.assertIn("CORS_ORIGINS:-}", self.compose_content)

    def test_env_example_no_hardcoded_password(self):
        """The .env.example must not contain default passwords."""
        env_path = Path(__file__).parent.parent / ".env.example"
        with open(env_path) as f:
            env_content = f.read()
        self.assertNotIn("change_me_in_production", env_content)

    def test_env_example_no_hardcoded_token_secrets(self):
        """The .env.example must not contain default token secrets."""
        env_path = Path(__file__).parent.parent / ".env.example"
        with open(env_path) as f:
            env_content = f.read()
        self.assertNotIn("CHANGE-ME", env_content)

    def test_env_example_no_wildcard_cors(self):
        """The .env.example must not default to wildcard CORS."""
        env_path = Path(__file__).parent.parent / ".env.example"
        with open(env_path) as f:
            env_content = f.read()
        # Check that CORS_ORIGINS is not set to just '*'
        for line in env_content.splitlines():
            if line.startswith("CORS_ORIGINS="):
                value = line.split("=", 1)[1].strip()
                self.assertNotEqual(value, "*",
                                    "CORS_ORIGINS must not default to wildcard")


class TestRefreshTokenInPostBody(unittest.TestCase):
    """Fix 2: Refresh token must be in POST body, not query parameter."""

    def test_keyserver_refresh_uses_post_body(self):
        """Keyserver refresh endpoint must accept token in POST body."""
        from openssl_encrypt_server.modules.keyserver.routes import refresh_token
        import inspect
        sig = inspect.signature(refresh_token)
        params = sig.parameters

        # Should have a body parameter, not a query parameter for refresh_token
        # The function should accept a Pydantic model body, not a Query param
        self.assertIn("body", params,
                       "Keyserver refresh endpoint must accept refresh_token via POST body")

    def test_telemetry_refresh_uses_post_body(self):
        """Telemetry refresh endpoint already uses POST body (regression test)."""
        from openssl_encrypt_server.modules.telemetry.routes import refresh_token
        import inspect
        sig = inspect.signature(refresh_token)
        params = sig.parameters
        self.assertIn("body", params,
                       "Telemetry refresh endpoint must accept refresh_token via POST body")


class TestConstantTimeHashComparison(unittest.TestCase):
    """Fix 3: Hash comparison must use constant-time comparison."""

    def test_hmac_compare_digest_used_in_verify(self):
        """IntegrityService.verify_hash must use hmac.compare_digest."""
        import inspect
        from openssl_encrypt_server.modules.integrity.service import IntegrityService
        source = inspect.getsource(IntegrityService.verify_hash)
        self.assertIn("hmac.compare_digest", source,
                       "verify_hash must use hmac.compare_digest for constant-time comparison")

    def test_hmac_compare_digest_correctness(self):
        """hmac.compare_digest returns correct results."""
        self.assertTrue(hmac.compare_digest("abc123", "abc123"))
        self.assertFalse(hmac.compare_digest("abc123", "abc124"))
        self.assertFalse(hmac.compare_digest("abc123", ""))


class TestSearchQueryFilter(unittest.TestCase):
    """Fix 5: SQLAlchemy filter must use .is_(False), not Python 'not'."""

    def test_search_uses_sqlalchemy_filter(self):
        """search_key must use SQLAlchemy .is_(False), not Python 'not'."""
        import inspect
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService
        source = inspect.getsource(KeyserverService.search_key)
        # Must NOT use Python's 'not' operator on a column
        self.assertNotIn("not KSKey.revoked", source,
                          "Must not use Python 'not' on SQLAlchemy column")
        # Must use SQLAlchemy's is_(False) or == False
        self.assertTrue(
            "is_(False)" in source or "== False" in source,
            "Must use SQLAlchemy .is_(False) or == False for column filter"
        )


class TestRegistrationGating(unittest.TestCase):
    """Fix 6: Registration must check REGISTRATION_SECRET when configured."""

    def test_keyserver_register_has_secret_header(self):
        """Keyserver register endpoint must accept X-Registration-Secret."""
        import inspect
        from openssl_encrypt_server.modules.keyserver.routes import register
        sig = inspect.signature(register)
        self.assertIn("x_registration_secret", sig.parameters,
                       "register must accept X-Registration-Secret header")

    def test_telemetry_register_has_secret_header(self):
        """Telemetry register endpoint must accept X-Registration-Secret."""
        import inspect
        from openssl_encrypt_server.modules.telemetry.routes import register
        sig = inspect.signature(register)
        self.assertIn("x_registration_secret", sig.parameters,
                       "register must accept X-Registration-Secret header")

    def test_keyserver_register_checks_secret(self):
        """Keyserver register must check registration_secret from config."""
        import inspect
        from openssl_encrypt_server.modules.keyserver.routes import register
        source = inspect.getsource(register)
        self.assertIn("registration_secret", source,
                       "register must check registration_secret")

    def test_telemetry_register_checks_secret(self):
        """Telemetry register must check registration_secret from config."""
        import inspect
        from openssl_encrypt_server.modules.telemetry.routes import register
        source = inspect.getsource(register)
        self.assertIn("registration_secret", source,
                       "register must check registration_secret")

    def test_settings_has_registration_secret_field(self):
        """Settings must include registration_secret field."""
        from openssl_encrypt_server.config import Settings
        fields = Settings.model_fields
        self.assertIn("registration_secret", fields,
                       "Settings must have registration_secret field")


class TestGenericErrorMessages(unittest.TestCase):
    """Fix 7: Error responses must not leak internal details."""

    def test_token_verify_no_internal_details(self):
        """Token verification errors must not include raw exception messages."""
        import inspect
        from openssl_encrypt_server.core.auth.token import TokenAuth
        source = inspect.getsource(TokenAuth.verify_token)
        # Should not pass str(e) to client
        self.assertNotIn('f"Invalid token: {str(e)}"', source,
                          "Must not expose raw exception in error response")
        self.assertNotIn("detail=f\"Invalid token:", source,
                          "Must not expose internal error details to client")

    def test_proxy_cert_error_no_internal_details(self):
        """Proxy cert errors must not include raw exception messages."""
        import inspect
        from openssl_encrypt_server.core.auth.proxy import ProxyAuth
        source = inspect.getsource(ProxyAuth.get_client_fingerprint)
        self.assertNotIn('f"Invalid client certificate: {e}"', source,
                          "Must not expose raw cert parsing error to client")

    def test_keyserver_verification_error_no_internal_details(self):
        """Keyserver verification errors must not include raw exception messages."""
        import inspect
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService
        source = inspect.getsource(KeyserverService.upload_key)
        self.assertNotIn('f"Verification failed: {e}"', source,
                          "Must not expose raw verification error to client")


class TestDebugModeSecurityValidation(unittest.TestCase):
    """Fix 8: Security validation must not be bypassed by debug mode."""

    def test_insecure_secret_rejected_in_debug_mode(self):
        """Insecure token secrets must be rejected even in debug mode."""
        from openssl_encrypt_server.config import Settings, validate_config

        with patch.dict(os.environ, {
            "DEBUG": "true",
            "KEYSERVER_TOKEN_SECRET": "keyserver-secret-min-32-chars-CHANGE-ME",
            "TELEMETRY_TOKEN_SECRET": "telemetry-secret-min-32-chars-change-me-too",
        }, clear=False):
            test_settings = Settings(
                debug=True,
                keyserver_token_secret="keyserver-secret-min-32-chars-CHANGE-ME",
                telemetry_token_secret="telemetry-secret-min-32-chars-change-me-too",
            )
            with self.assertRaises(ValueError):
                validate_config(test_settings)

    def test_empty_password_rejected_in_debug_mode(self):
        """Empty database password must be rejected even in debug mode."""
        from openssl_encrypt_server.config import Settings, validate_config

        test_settings = Settings(
            debug=True,
            postgres_password="",
            keyserver_enabled=False,
            telemetry_enabled=False,
        )
        with self.assertRaises(ValueError):
            validate_config(test_settings)

    def test_insecure_db_password_rejected_in_debug_mode(self):
        """Insecure database password must be rejected even in debug mode."""
        from openssl_encrypt_server.config import Settings, validate_config

        test_settings = Settings(
            debug=True,
            postgres_password="change_me_in_production",
            keyserver_enabled=False,
            telemetry_enabled=False,
        )
        with self.assertRaises(ValueError):
            validate_config(test_settings)

    def test_secure_config_passes_validation(self):
        """Properly configured settings must pass validation."""
        from openssl_encrypt_server.config import Settings, validate_config

        test_settings = Settings(
            debug=False,
            postgres_password="a-very-strong-and-secure-database-password-2024",
            keyserver_token_secret="ks-a8f3e2d1c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8",
            telemetry_token_secret="tm-z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4j3i2",
            keyserver_enabled=True,
            telemetry_enabled=True,
        )
        # Should not raise
        validate_config(test_settings)

    def test_allow_insecure_defaults_flag(self):
        """ALLOW_INSECURE_DEFAULTS=true permits insecure values for local dev."""
        from openssl_encrypt_server.config import Settings, validate_config

        test_settings = Settings(
            debug=True,
            allow_insecure_defaults=True,
            postgres_password="change_me_in_production",
            keyserver_token_secret="keyserver-secret-min-32-chars-CHANGE-ME",
            telemetry_token_secret="telemetry-secret-min-32-chars-change-me-too",
            keyserver_enabled=True,
            telemetry_enabled=True,
        )
        # Should not raise when allow_insecure_defaults is True
        validate_config(test_settings)


class TestPepperTOTPOnUpdateDelete(unittest.TestCase):
    """Fix 9: Pepper update/delete must require TOTP if enabled."""

    def test_update_pepper_has_totp_header(self):
        """update_pepper endpoint must accept X-TOTP-Code header."""
        import inspect
        from openssl_encrypt_server.modules.pepper.routes import update_pepper
        sig = inspect.signature(update_pepper)
        params = sig.parameters
        self.assertIn("x_totp_code", params,
                       "update_pepper must accept X-TOTP-Code header")

    def test_delete_pepper_has_totp_header(self):
        """delete_pepper endpoint must accept X-TOTP-Code header."""
        import inspect
        from openssl_encrypt_server.modules.pepper.routes import delete_pepper
        sig = inspect.signature(delete_pepper)
        params = sig.parameters
        self.assertIn("x_totp_code", params,
                       "delete_pepper must accept X-TOTP-Code header")

    def test_update_pepper_calls_verify_totp(self):
        """update_pepper must call verify_totp_if_enabled."""
        import inspect
        from openssl_encrypt_server.modules.pepper.routes import update_pepper
        source = inspect.getsource(update_pepper)
        self.assertIn("verify_totp_if_enabled", source,
                       "update_pepper must verify TOTP if enabled")

    def test_delete_pepper_calls_verify_totp(self):
        """delete_pepper must call verify_totp_if_enabled."""
        import inspect
        from openssl_encrypt_server.modules.pepper.routes import delete_pepper
        source = inspect.getsource(delete_pepper)
        self.assertIn("verify_totp_if_enabled", source,
                       "delete_pepper must verify TOTP if enabled")


class TestMigrationScriptNoCliCredentials(unittest.TestCase):
    """Fix 10: Migration script must read DB URL from env var, not CLI arg."""

    def test_migration_reads_from_env_var(self):
        """Migration script must support DATABASE_URL environment variable."""
        import inspect
        migration_path = Path(__file__).parent.parent / "migrations" / "001_increase_fingerprint_size.py"
        with open(migration_path) as f:
            source = f.read()
        self.assertIn("DATABASE_URL", source,
                       "Migration must read DATABASE_URL from environment")

    def test_migration_no_required_cli_url(self):
        """Migration script must not require --database-url as mandatory CLI arg."""
        migration_path = Path(__file__).parent.parent / "migrations" / "001_increase_fingerprint_size.py"
        with open(migration_path) as f:
            source = f.read()
        # --database-url should not be required=True
        self.assertNotIn('required=True', source,
                          "Migration must not require --database-url CLI argument")


class TestLoginEndpointSchema(unittest.TestCase):
    """Test that the login endpoint schema and route exist."""

    def test_login_schema_exists(self):
        """LoginRequest schema must exist in schemas module."""
        schemas_path = Path(__file__).parent.parent / "modules" / "keyserver" / "schemas.py"
        with open(schemas_path) as f:
            source = f.read()
        self.assertIn("class LoginRequest", source)
        self.assertIn("client_id", source)

    def test_login_route_exists(self):
        """Login route must be defined in keyserver routes."""
        routes_path = Path(__file__).parent.parent / "modules" / "keyserver" / "routes.py"
        with open(routes_path) as f:
            source = f.read()
        self.assertIn('"/login"', source)
        self.assertIn("async def login", source)

    def test_login_route_is_rate_limited(self):
        """Login route must have strict rate limiting."""
        routes_path = Path(__file__).parent.parent / "modules" / "keyserver" / "routes.py"
        with open(routes_path) as f:
            source = f.read()
        # Find the login function and check it has rate limiting before it
        login_idx = source.index("async def login")
        preceding = source[max(0, login_idx - 200):login_idx]
        self.assertIn("limiter.limit", preceding,
                       "Login endpoint must be rate-limited")

    def test_get_client_by_id_uses_constant_time(self):
        """get_client_by_id must use constant-time comparison."""
        service_path = Path(__file__).parent.parent / "modules" / "keyserver" / "service.py"
        with open(service_path) as f:
            source = f.read()
        self.assertIn("hmac.compare_digest", source,
                       "Client lookup must use constant-time comparison")


class TestRegistrationSecretConstantTime(unittest.TestCase):
    """Registration secret comparison must use constant-time comparison to prevent timing attacks."""

    def test_keyserver_register_uses_hmac_compare_digest(self):
        """Keyserver register must use hmac.compare_digest for secret comparison."""
        routes_path = Path(__file__).parent.parent / "modules" / "keyserver" / "routes.py"
        with open(routes_path) as f:
            source = f.read()
        # Find the register function body
        reg_idx = source.index("async def register(")
        # Find the next function definition to delimit the register function body
        next_func = source.index("\nasync def ", reg_idx + 1)
        register_source = source[reg_idx:next_func]
        self.assertIn("hmac.compare_digest", register_source,
                       "Registration secret comparison must use hmac.compare_digest, "
                       "not == operator, to prevent timing attacks")

    def test_keyserver_register_does_not_use_equality_for_secret(self):
        """Keyserver register must NOT use == to compare registration secret."""
        routes_path = Path(__file__).parent.parent / "modules" / "keyserver" / "routes.py"
        with open(routes_path) as f:
            source = f.read()
        reg_idx = source.index("async def register(")
        next_func = source.index("\nasync def ", reg_idx + 1)
        register_source = source[reg_idx:next_func]
        self.assertNotIn(
            "x_registration_secret != settings.registration_secret",
            register_source,
            "Must not use != operator for secret comparison (timing attack vulnerable)")

    def test_keyserver_routes_imports_hmac(self):
        """Keyserver routes must import hmac for constant-time comparison."""
        routes_path = Path(__file__).parent.parent / "modules" / "keyserver" / "routes.py"
        with open(routes_path) as f:
            source = f.read()
        self.assertIn("import hmac", source,
                       "routes.py must import hmac for constant-time secret comparison")

    def test_telemetry_register_uses_hmac_compare_digest(self):
        """Telemetry register must use hmac.compare_digest for secret comparison if it checks the secret."""
        routes_path = Path(__file__).parent.parent / "modules" / "telemetry" / "routes.py"
        with open(routes_path) as f:
            source = f.read()
        # If telemetry register checks registration_secret, it must use constant-time comparison
        if "registration_secret" in source:
            self.assertIn("hmac.compare_digest", source,
                           "Registration secret comparison must use hmac.compare_digest, "
                           "not == operator, to prevent timing attacks")


if __name__ == "__main__":
    unittest.main()
