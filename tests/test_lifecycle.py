"""Unit tests for lifecycle.py — token validation, MSK manager, auth middleware."""

from __future__ import annotations

import hashlib
import hmac

import pytest

from cipherweave.exceptions import InvalidTokenError, UnauthorizedAgentError
from cipherweave.lifecycle import MSKManager, TokenValidator


def test_token_validator_valid_token() -> None:
    """Valid HMAC token accepted."""
    secret = "my-test-secret-32-characters-min"
    validator = TokenValidator(secret)
    agent_id = "agent-001"
    # Build correct HMAC
    token = hmac.new(secret.encode(), agent_id.encode(), hashlib.sha256).hexdigest()
    assert validator.validate(token, agent_id) is True


def test_token_validator_invalid_token() -> None:
    """Wrong token raises InvalidTokenError."""
    validator = TokenValidator("my-test-secret-32-characters-min")
    with pytest.raises(InvalidTokenError):
        validator.validate("totally-wrong-token", "agent-001")


def test_token_validator_empty_token() -> None:
    """Empty token raises InvalidTokenError."""
    validator = TokenValidator("my-test-secret-32-characters-min")
    with pytest.raises(InvalidTokenError):
        validator.validate("", "agent-001")


def test_token_validator_empty_agent() -> None:
    """Empty agent_id raises InvalidTokenError."""
    validator = TokenValidator("my-test-secret-32-characters-min")
    with pytest.raises(InvalidTokenError):
        validator.validate("some-token", "")


@pytest.mark.asyncio
async def test_msk_manager_local_mode() -> None:
    """MSKManager in local mode returns 32-byte secret."""
    mgr = MSKManager(kms_client=None, key_id="", use_local=True)
    msk = await mgr.get_msk()
    assert isinstance(msk, bytes)
    assert len(msk) == 32


@pytest.mark.asyncio
async def test_msk_manager_caches_until_expired() -> None:
    """MSKManager returns same secret within TTL."""
    mgr = MSKManager(kms_client=None, key_id="", use_local=True)
    msk1 = await mgr.get_msk()
    msk2 = await mgr.get_msk()
    assert msk1 == msk2


@pytest.mark.asyncio
async def test_msk_manager_invalidate_forces_rotation() -> None:
    """Calling invalidate() forces a new secret on next get_msk()."""
    mgr = MSKManager(kms_client=None, key_id="", use_local=True)
    msk1 = await mgr.get_msk()
    mgr.invalidate()
    msk2 = await mgr.get_msk()
    # With os.urandom, the chance of collision is astronomically low
    assert msk1 != msk2
