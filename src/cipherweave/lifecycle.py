"""Module 4: Lifecycle management — MSK rotation, token validation, AuthMiddleware."""

from __future__ import annotations

import logging
import os
import time
from typing import Any

from cipherweave.exceptions import InvalidTokenError, UnauthorizedAgentError

logger = logging.getLogger(__name__)


class MSKManager:
    """Master Secret Key lifecycle — rotation schedule and KMS integration.

    In production: integrates with AWS KMS for envelope encryption.
    In local dev: uses os.urandom for the MSK.
    """

    _MSK_TTL_SECONDS = 3600  # rotate hourly

    def __init__(self, kms_client: Any, key_id: str, use_local: bool = True) -> None:
        self._kms_client = kms_client
        self._key_id = key_id
        self._use_local = use_local
        self._msk: bytes | None = None
        self._msk_expiry: float = 0.0

    async def get_msk(self) -> bytes:
        """Return current MSK, refreshing if expired."""
        now = time.monotonic()
        if self._msk is None or now >= self._msk_expiry:
            await self._rotate()
        assert self._msk is not None
        return self._msk

    async def _rotate(self) -> None:
        if self._use_local or self._kms_client is None:
            self._msk = os.urandom(32)
        else:
            try:
                resp = self._kms_client.generate_data_key(
                    KeyId=self._key_id, NumberOfBytes=32
                )
                self._msk = resp["Plaintext"]
            except Exception as exc:
                logger.error("KMS rotation failed: %s", exc)
                raise

        self._msk_expiry = time.monotonic() + self._MSK_TTL_SECONDS
        logger.info("MSK rotated; next rotation in %ds", self._MSK_TTL_SECONDS)

    def invalidate(self) -> None:
        """Force next get_msk() to rotate."""
        self._msk_expiry = 0.0


class TokenValidator:
    """Validate X-Agent-ID bearer tokens (HMAC-SHA256 in production)."""

    def __init__(self, secret: str) -> None:
        self._secret = secret.encode()

    def validate(self, token: str, agent_id: str) -> bool:
        """Return True if token is valid for this agent_id.

        Local dev: accept any non-empty token.
        Production: verify HMAC-SHA256(secret, agent_id).
        """
        if not token:
            raise InvalidTokenError("Token is empty")
        if not agent_id:
            raise InvalidTokenError("Agent ID is empty")

        import hashlib
        import hmac

        expected = hmac.new(
            self._secret,
            agent_id.encode(),
            hashlib.sha256,
        ).hexdigest()

        # Constant-time comparison
        if not hmac.compare_digest(token, expected):
            raise InvalidTokenError(f"Invalid token for agent '{agent_id}'")
        return True


class AuthMiddleware:
    """FastMCP middleware — validates X-Agent-ID header against Memgraph."""

    def __init__(self, risk_graph: Any, token_validator: TokenValidator) -> None:
        self._risk_graph = risk_graph
        self._token_validator = token_validator

    async def __call__(self, request: Any) -> Any | None:
        """Validate agent identity. Return None to continue; raise to reject."""
        agent_id: str = request.headers.get("X-Agent-ID", "")
        token: str = request.headers.get("Authorization", "").removeprefix("Bearer ")

        if not agent_id:
            raise InvalidTokenError("Missing X-Agent-ID header")

        # Check agent exists in graph
        if not await self._risk_graph.agent_exists(agent_id):
            raise UnauthorizedAgentError(agent_id)

        # Validate HMAC token (skip in local-dev mode where token_secret is default)
        try:
            self._token_validator.validate(token, agent_id)
        except InvalidTokenError:
            # In local dev mode, accept any token for known agents
            if os.environ.get("CIPHERWEAVE_USE_LOCAL_KMS", "true").lower() == "true":
                logger.debug("Local dev: skipping token HMAC validation for agent %s", agent_id)
            else:
                raise

        return None
