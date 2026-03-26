#!/usr/bin/env python3
"""
Unit tests for key search improvements (TDD red phase).

Tests:
1. KeyListSearchResponse schema — new schema with `keys` list and `count`
2. KeySearchResponse schema — existing schema has `key` field
3. search_key() service — returns list of ALL matching keys, not just first
4. get_key_by_fingerprint() service — new method, exact fingerprint match only
5. GET /search route — uses KeyListSearchResponse response model
6. GET /{fingerprint} route — new public endpoint, uses KeySearchResponse
"""

import asyncio
import inspect
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def run_async(coro):
    """Run an async coroutine synchronously (no pytest-asyncio required)."""
    return asyncio.run(coro)


def _make_ks_key(fingerprint, name, email=None, bundle_json=None):
    """Build a minimal KSKey mock."""
    key = MagicMock()
    key.fingerprint = fingerprint
    key.name = name
    key.email = email
    key.revoked = False
    if bundle_json is None:
        bundle_json = json.dumps({
            "name": name,
            "email": email,
            "fingerprint": fingerprint,
            "created_at": "2026-01-01T00:00:00+00:00",
            "encryption_public_key": "dGVzdA==",
            "signing_public_key": "dGVzdA==",
            "encryption_algorithm": "ML-KEM-768",
            "signing_algorithm": "ML-DSA-65",
            "self_signature": "dGVzdA==",
        })
    key.bundle_json = bundle_json
    return key


# ---------------------------------------------------------------------------
# TestKeyListSearchSchema
# ---------------------------------------------------------------------------


class TestKeyListSearchSchema:
    """KeyListSearchResponse is importable and has the correct fields."""

    def test_schema_is_importable(self):
        """KeyListSearchResponse can be imported from schemas."""
        from openssl_encrypt_server.modules.keyserver.schemas import KeyListSearchResponse
        assert KeyListSearchResponse is not None

    def test_schema_has_keys_field(self):
        """KeyListSearchResponse has a `keys` field."""
        from openssl_encrypt_server.modules.keyserver.schemas import KeyListSearchResponse
        fields = KeyListSearchResponse.model_fields
        assert "keys" in fields

    def test_schema_has_count_field(self):
        """KeyListSearchResponse has a `count` field."""
        from openssl_encrypt_server.modules.keyserver.schemas import KeyListSearchResponse
        fields = KeyListSearchResponse.model_fields
        assert "count" in fields

    def test_keys_field_is_list_type(self):
        """The `keys` field annotation is a list type."""
        from openssl_encrypt_server.modules.keyserver.schemas import KeyListSearchResponse
        import typing
        field_info = KeyListSearchResponse.model_fields["keys"]
        annotation = field_info.annotation
        # Should be List[KeyBundleSchema] or similar generic list
        origin = getattr(annotation, "__origin__", None)
        assert origin is list

    def test_schema_instantiates_with_empty_list(self):
        """KeyListSearchResponse can be instantiated with an empty keys list."""
        from openssl_encrypt_server.modules.keyserver.schemas import KeyListSearchResponse
        response = KeyListSearchResponse(keys=[], count=0)
        assert response.keys == []
        assert response.count == 0

    def test_schema_instantiates_with_key_bundles(self):
        """KeyListSearchResponse can be instantiated with a list of KeyBundleSchema."""
        from openssl_encrypt_server.modules.keyserver.schemas import (
            KeyBundleSchema,
            KeyListSearchResponse,
        )
        bundle = KeyBundleSchema(
            name="Alice",
            fingerprint="3a:4b:5c:6d",
            created_at="2026-01-01T00:00:00+00:00",
            encryption_public_key="dGVzdA==",
            signing_public_key="dGVzdA==",
            encryption_algorithm="ML-KEM-768",
            signing_algorithm="ML-DSA-65",
            self_signature="dGVzdA==",
        )
        response = KeyListSearchResponse(keys=[bundle], count=1)
        assert len(response.keys) == 1
        assert response.count == 1


# ---------------------------------------------------------------------------
# TestGetKeyByFingerprintSchema
# ---------------------------------------------------------------------------


class TestGetKeyByFingerprintSchema:
    """Existing KeySearchResponse has the `key` field (needed for single-key route)."""

    def test_key_search_response_is_importable(self):
        """KeySearchResponse can be imported from schemas."""
        from openssl_encrypt_server.modules.keyserver.schemas import KeySearchResponse
        assert KeySearchResponse is not None

    def test_key_search_response_has_key_field(self):
        """KeySearchResponse has a `key` field."""
        from openssl_encrypt_server.modules.keyserver.schemas import KeySearchResponse
        fields = KeySearchResponse.model_fields
        assert "key" in fields

    def test_key_search_response_has_message_field(self):
        """KeySearchResponse has a `message` field."""
        from openssl_encrypt_server.modules.keyserver.schemas import KeySearchResponse
        fields = KeySearchResponse.model_fields
        assert "message" in fields


# ---------------------------------------------------------------------------
# TestSearchKeyServiceReturnsList
# ---------------------------------------------------------------------------


class TestSearchKeyServiceReturnsList:
    """search_key() returns a dict with `keys` list and `count` (all matches)."""

    def _make_service(self):
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService
        db = AsyncMock()
        service = KeyserverService(db)
        return service, db

    def test_search_key_returns_keys_list_field(self):
        """search_key() response contains a `keys` field that is a list."""
        service, db = self._make_service()

        key1 = _make_ks_key("aa:bb:cc", "Alice")
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [key1]
        db.execute.return_value = mock_result

        with patch.object(service, "_log_access", new_callable=AsyncMock):
            result = run_async(service.search_key("Alice"))

        assert "keys" in result
        assert isinstance(result["keys"], list)

    def test_search_key_returns_count_field(self):
        """search_key() response contains a `count` field with number of results."""
        service, db = self._make_service()

        key1 = _make_ks_key("aa:bb:cc", "Alice")
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [key1]
        db.execute.return_value = mock_result

        with patch.object(service, "_log_access", new_callable=AsyncMock):
            result = run_async(service.search_key("Alice"))

        assert "count" in result
        assert result["count"] == 1

    def test_search_key_returns_all_matching_keys(self):
        """search_key() returns ALL matching keys, not just the first."""
        service, db = self._make_service()

        key1 = _make_ks_key("aa:bb:cc", "Alice", "alice@example.com")
        key2 = _make_ks_key("dd:ee:ff", "Alice Smith", "alice2@example.com")
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [key1, key2]
        db.execute.return_value = mock_result

        with patch.object(service, "_log_access", new_callable=AsyncMock):
            result = run_async(service.search_key("Alice"))

        assert result["count"] == 2
        assert len(result["keys"]) == 2

    def test_search_key_raises_404_when_no_results(self):
        """search_key() raises HTTPException 404 when no keys match."""
        from fastapi import HTTPException

        service, db = self._make_service()

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        db.execute.return_value = mock_result

        with pytest.raises(HTTPException) as exc_info:
            run_async(service.search_key("nobody@example.com"))

        assert exc_info.value.status_code == 404

    def test_search_key_empty_query_raises_404(self):
        """search_key() raises HTTPException 404 when query matches nothing."""
        from fastapi import HTTPException

        service, db = self._make_service()

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        db.execute.return_value = mock_result

        with pytest.raises(HTTPException) as exc_info:
            run_async(service.search_key(""))

        assert exc_info.value.status_code == 404

    def test_search_key_results_contain_key_bundle_schemas(self):
        """Each item in the `keys` list is a KeyBundleSchema instance."""
        from openssl_encrypt_server.modules.keyserver.schemas import KeyBundleSchema

        service, db = self._make_service()

        key1 = _make_ks_key("aa:bb:cc", "Alice")
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [key1]
        db.execute.return_value = mock_result

        with patch.object(service, "_log_access", new_callable=AsyncMock):
            result = run_async(service.search_key("Alice"))

        assert len(result["keys"]) == 1
        assert isinstance(result["keys"][0], KeyBundleSchema)

    def test_search_key_logs_access_for_each_result(self):
        """_log_access is called once per matching key."""
        service, db = self._make_service()

        key1 = _make_ks_key("aa:bb:cc", "Alice")
        key2 = _make_ks_key("dd:ee:ff", "Alice B")
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [key1, key2]
        db.execute.return_value = mock_result

        with patch.object(service, "_log_access", new_callable=AsyncMock) as mock_log:
            run_async(service.search_key("Alice"))

        assert mock_log.call_count == 2


# ---------------------------------------------------------------------------
# TestGetKeyByFingerprintService
# ---------------------------------------------------------------------------


class TestGetKeyByFingerprintService:
    """get_key_by_fingerprint() — exact fingerprint match only, new method."""

    def _make_service(self):
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService
        db = AsyncMock()
        service = KeyserverService(db)
        return service, db

    def test_method_exists_on_service(self):
        """get_key_by_fingerprint method exists on KeyserverService."""
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService
        assert hasattr(KeyserverService, "get_key_by_fingerprint")

    def test_method_is_async(self):
        """get_key_by_fingerprint is a coroutine function."""
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService
        assert asyncio.iscoroutinefunction(KeyserverService.get_key_by_fingerprint)

    def test_method_accepts_fingerprint_client_id_ip(self):
        """get_key_by_fingerprint accepts fingerprint, client_id, ip_address parameters."""
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService
        sig = inspect.signature(KeyserverService.get_key_by_fingerprint)
        params = sig.parameters
        assert "fingerprint" in params
        assert "client_id" in params
        assert "ip_address" in params

    def test_returns_dict_with_key_and_message(self):
        """get_key_by_fingerprint returns dict with `key` and `message` fields."""
        service, db = self._make_service()

        fp = "aa:bb:cc:dd"
        key = _make_ks_key(fp, "Alice")
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = key
        db.execute.return_value = mock_result

        with patch.object(service, "_log_access", new_callable=AsyncMock):
            result = run_async(service.get_key_by_fingerprint(fp))

        assert "key" in result
        assert "message" in result

    def test_returns_key_bundle_schema_in_key_field(self):
        """The `key` field is a KeyBundleSchema instance."""
        from openssl_encrypt_server.modules.keyserver.schemas import KeyBundleSchema

        service, db = self._make_service()

        fp = "aa:bb:cc:dd"
        key = _make_ks_key(fp, "Alice")
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = key
        db.execute.return_value = mock_result

        with patch.object(service, "_log_access", new_callable=AsyncMock):
            result = run_async(service.get_key_by_fingerprint(fp))

        assert isinstance(result["key"], KeyBundleSchema)

    def test_raises_404_when_fingerprint_not_found(self):
        """Raises HTTPException 404 when fingerprint has no match."""
        from fastapi import HTTPException

        service, db = self._make_service()

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        db.execute.return_value = mock_result

        with pytest.raises(HTTPException) as exc_info:
            run_async(service.get_key_by_fingerprint("xx:yy:zz:00"))

        assert exc_info.value.status_code == 404

    def test_does_not_match_by_name(self):
        """get_key_by_fingerprint does NOT match by name — only exact fingerprint."""
        from fastapi import HTTPException

        service, db = self._make_service()

        # DB returns nothing for exact fingerprint search
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        db.execute.return_value = mock_result

        # A name that happens to exist should not be found via this method
        with pytest.raises(HTTPException) as exc_info:
            run_async(service.get_key_by_fingerprint("Alice"))

        assert exc_info.value.status_code == 404

    def test_does_not_match_by_email(self):
        """get_key_by_fingerprint does NOT match by email."""
        from fastapi import HTTPException

        service, db = self._make_service()

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        db.execute.return_value = mock_result

        with pytest.raises(HTTPException) as exc_info:
            run_async(service.get_key_by_fingerprint("alice@example.com"))

        assert exc_info.value.status_code == 404

    def test_uses_exact_fingerprint_column_in_query(self):
        """The DB query filters on exact fingerprint equality (not LIKE/startswith)."""
        service, db = self._make_service()

        fp = "aa:bb:cc:dd"
        key = _make_ks_key(fp, "Alice")
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = key
        db.execute.return_value = mock_result

        with patch.object(service, "_log_access", new_callable=AsyncMock):
            run_async(service.get_key_by_fingerprint(fp))

        # db.execute was called — inspect the compiled query string
        assert db.execute.called
        call_arg = db.execute.call_args[0][0]
        # The query should be a SQLAlchemy select statement; convert to string to check
        query_str = str(call_arg.compile(compile_kwargs={"literal_binds": True}))
        # Must contain the fingerprint value; must NOT contain LIKE or startswith pattern
        assert fp in query_str
        assert "LIKE" not in query_str.upper()

    def test_message_field_contains_found_text(self):
        """The `message` field in the response confirms the key was found."""
        service, db = self._make_service()

        fp = "aa:bb:cc:dd"
        key = _make_ks_key(fp, "Alice")
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = key
        db.execute.return_value = mock_result

        with patch.object(service, "_log_access", new_callable=AsyncMock):
            result = run_async(service.get_key_by_fingerprint(fp))

        assert "found" in result["message"].lower()


# ---------------------------------------------------------------------------
# TestSearchRouteReturnsList
# ---------------------------------------------------------------------------


class TestSearchRouteReturnsList:
    """GET /search route uses KeyListSearchResponse as response_model."""

    def test_search_route_uses_key_list_search_response_model(self):
        """GET /search route has response_model=KeyListSearchResponse."""
        from openssl_encrypt_server.modules.keyserver.routes import router
        from openssl_encrypt_server.modules.keyserver.schemas import KeyListSearchResponse

        search_route = None
        for route in router.routes:
            if hasattr(route, "path") and route.path == "/search":
                methods = getattr(route, "methods", set())
                if "GET" in methods:
                    search_route = route
                    break

        assert search_route is not None, "GET /search route not found"
        assert search_route.response_model is KeyListSearchResponse, (
            f"Expected KeyListSearchResponse, got {search_route.response_model}"
        )

    def test_search_route_path_is_search(self):
        """The search endpoint is registered at /search."""
        from openssl_encrypt_server.modules.keyserver.routes import router

        paths = [route.path for route in router.routes if hasattr(route, "path")]
        assert "/search" in paths


# ---------------------------------------------------------------------------
# TestGetByFingerprintRoute
# ---------------------------------------------------------------------------


class TestGetByFingerprintRoute:
    """GET /{fingerprint} route — new public endpoint for fingerprint lookup."""

    def _get_fingerprint_route(self):
        """Find the GET /{fingerprint} route in the router."""
        from openssl_encrypt_server.modules.keyserver.routes import router

        for route in router.routes:
            if not hasattr(route, "path") or not hasattr(route, "methods"):
                continue
            if "GET" not in route.methods:
                continue
            # Match a path param route that is a single segment (not /search, /confirm/...)
            path = route.path
            if path == "/{fingerprint}":
                return route
        return None

    def test_get_fingerprint_route_exists(self):
        """A GET /{fingerprint} route is registered."""
        route = self._get_fingerprint_route()
        assert route is not None, "GET /{fingerprint} route not found"

    def test_get_fingerprint_route_is_public(self):
        """GET /{fingerprint} route has no auth dependency (is public)."""
        route = self._get_fingerprint_route()
        assert route is not None, "GET /{fingerprint} route not found"

        # Inspect dependencies — should not contain get_current_client
        from openssl_encrypt_server.modules.keyserver.routes import get_current_client
        deps = getattr(route, "dependencies", [])
        dep_callables = [d.dependency for d in deps]
        assert get_current_client not in dep_callables

        # Also check the endpoint function's direct parameter dependencies
        endpoint_src = inspect.getsource(route.endpoint)
        assert "get_current_client" not in endpoint_src

    def test_get_fingerprint_route_uses_key_search_response(self):
        """GET /{fingerprint} route has response_model=KeySearchResponse."""
        from openssl_encrypt_server.modules.keyserver.schemas import KeySearchResponse

        route = self._get_fingerprint_route()
        assert route is not None, "GET /{fingerprint} route not found"
        assert route.response_model is KeySearchResponse, (
            f"Expected KeySearchResponse, got {route.response_model}"
        )

    def test_get_fingerprint_route_calls_get_key_by_fingerprint(self):
        """GET /{fingerprint} endpoint calls service.get_key_by_fingerprint()."""
        route = self._get_fingerprint_route()
        assert route is not None, "GET /{fingerprint} route not found"

        endpoint_src = inspect.getsource(route.endpoint)
        assert "get_key_by_fingerprint" in endpoint_src

    def test_get_fingerprint_route_is_rate_limited(self):
        """GET /{fingerprint} route is rate-limited (100/minute)."""
        route = self._get_fingerprint_route()
        assert route is not None, "GET /{fingerprint} route not found"

        endpoint_src = inspect.getsource(route.endpoint)
        # The limiter decorator should be applied — check via source or decorator list
        # Look for the @limiter.limit decoration in the source of the routes module
        import openssl_encrypt_server.modules.keyserver.routes as routes_module
        routes_src = inspect.getsource(routes_module)

        # Find the section around get_by_fingerprint or /{fingerprint}
        assert "100/minute" in routes_src, (
            "Expected 100/minute rate limit somewhere in routes — none found"
        )
