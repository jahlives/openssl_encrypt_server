#!/usr/bin/env python3
"""
Unit tests for structured logging (Finding #12).

Verifies that logger calls in service.py use parameterized formatting
(%s) instead of f-string interpolation, preventing log injection via
user-controlled data like email addresses and key names.
"""

import re
from pathlib import Path

import pytest


class TestStructuredLogging:
    """Verify service.py uses parameterized logging, not f-strings (#12)."""

    @pytest.fixture
    def service_source(self):
        service_path = Path(__file__).parent.parent / "modules" / "keyserver" / "service.py"
        with open(service_path) as f:
            return f.read()

    def test_no_fstring_logger_calls(self, service_source):
        """Logger calls must not use f-string interpolation with user data."""
        # Match logger.(info|warning|error|debug)(f"...")
        fstring_pattern = re.compile(r'logger\.\w+\(f["\']')
        matches = fstring_pattern.findall(service_source)
        assert len(matches) == 0, (
            f"Found {len(matches)} f-string logger call(s) in service.py. "
            "Use parameterized logging (e.g. logger.info('msg %s', var)) instead."
        )

    def test_email_not_in_fstring_log(self, service_source):
        """Email addresses must not appear in f-string log calls."""
        # Look for f-string logs containing {email} or {pending.email}
        email_fstring = re.compile(r'logger\.\w+\(f["\'].*\{.*email.*\}')
        matches = email_fstring.findall(service_source)
        assert len(matches) == 0, (
            "Found f-string logger call(s) containing email in service.py. "
            "Email must use parameterized logging to prevent log injection."
        )

    def test_query_not_in_fstring_log(self, service_source):
        """Search queries must not appear in f-string log calls."""
        query_fstring = re.compile(r'logger\.\w+\(f["\'].*\{.*query.*\}')
        matches = query_fstring.findall(service_source)
        assert len(matches) == 0, (
            "Found f-string logger call(s) containing query in service.py. "
            "Search queries must use parameterized logging."
        )

    def test_key_name_not_in_fstring_log(self, service_source):
        """Key names must not appear in f-string log calls."""
        name_fstring = re.compile(r'logger\.\w+\(f["\'].*\{.*\.name.*\}')
        matches = name_fstring.findall(service_source)
        assert len(matches) == 0, (
            "Found f-string logger call(s) containing key name in service.py. "
            "Key names must use parameterized logging."
        )
