"""Custom exceptions for CipherWeave."""


class CipherWeaveError(Exception):
    """Base exception for all CipherWeave errors."""


class UnauthorizedAgentError(CipherWeaveError):
    """Agent lacks authorization for the requested endpoint or data asset."""

    def __init__(self, agent_id: str, endpoint_id: str | None = None) -> None:
        self.agent_id = agent_id
        self.endpoint_id = endpoint_id
        msg = f"Agent '{agent_id}' is not authorized"
        if endpoint_id:
            msg += f" for endpoint '{endpoint_id}'"
        super().__init__(msg)


class SaltReuseError(CipherWeaveError):
    """Identical (salt, info) pair detected on a second derivation — key reuse attack."""

    def __init__(self, info: str) -> None:
        self.info = info
        super().__init__(f"Salt reuse detected for context '{info}'. Derivation rejected.")


class GraphConnectionError(CipherWeaveError):
    """Failed to connect to or query Memgraph."""


class KMSError(CipherWeaveError):
    """Failed to retrieve master secret from KMS."""


class DriftOverrideError(CipherWeaveError):
    """Cipher drift detected; profile forcibly upgraded to QUANTUM_SAFE."""

    def __init__(self, agent_id: str, original_profile: str, reason: str) -> None:
        self.agent_id = agent_id
        self.original_profile = original_profile
        self.reason = reason
        super().__init__(
            f"Drift override for agent '{agent_id}': {original_profile} → QUANTUM_SAFE. {reason}"
        )


class InvalidTokenError(CipherWeaveError):
    """Authentication token is missing or invalid."""


class PathNotFoundError(CipherWeaveError):
    """No graph path found between agent and destination endpoint."""

    def __init__(self, agent_id: str, destination_url: str) -> None:
        super().__init__(
            f"No path from agent '{agent_id}' to destination '{destination_url}'"
        )


class MetadataInferenceError(CipherWeaveError):
    """Cannot infer encryption policy — metadata is missing, invalid, or unrecognized."""

    def __init__(self, field: str, reason: str) -> None:
        self.field = field
        self.reason = reason
        super().__init__(f"Cannot infer policy from metadata — {field}: {reason}")
