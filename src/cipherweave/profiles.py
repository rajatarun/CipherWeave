"""CipherProfile enum — maps security levels to cryptographic algorithm sets."""

from enum import Enum


class CipherProfile(str, Enum):
    """Ordered cipher profiles from weakest-allowed to strongest.

    Upgrade paths are one-way: CHEAP → BALANCED → HARDENED → QUANTUM_SAFE.
    Downgrade is never permitted by policy.
    """

    QUANTUM_SAFE = "QUANTUM_SAFE"  # ML-KEM-768 + AES-256-GCM + HKDF-SHA512
    HARDENED = "HARDENED"          # AES-256-GCM + HKDF-SHA384
    BALANCED = "BALANCED"          # AES-256-GCM + HKDF-SHA256
    CHEAP = "CHEAP"                # AES-128-GCM + HKDF-SHA256

    # Ordering for comparison (higher index = stronger)
    _ORDER = None  # populated below

    def strength(self) -> int:
        """Numeric strength: higher = stronger. Used for fail-secure upgrades."""
        return _STRENGTH[self]

    def key_length_bits(self) -> int:
        return 256 if self in (CipherProfile.QUANTUM_SAFE, CipherProfile.HARDENED, CipherProfile.BALANCED) else 128

    def hash_algorithm(self) -> str:
        return {
            CipherProfile.QUANTUM_SAFE: "sha512",
            CipherProfile.HARDENED: "sha384",
            CipherProfile.BALANCED: "sha256",
            CipherProfile.CHEAP: "sha256",
        }[self]

    def algorithm_label(self) -> str:
        return {
            CipherProfile.QUANTUM_SAFE: "ML-KEM-768+AES-256-GCM",
            CipherProfile.HARDENED: "AES-256-GCM",
            CipherProfile.BALANCED: "AES-256-GCM",
            CipherProfile.CHEAP: "AES-128-GCM",
        }[self]

    def kdf_label(self) -> str:
        return f"HKDF-SHA{self.hash_algorithm().upper().replace('SHA', '')}"

    def cost_per_operation_usd(self) -> float:
        """Approximate cost estimate per key derivation operation."""
        return {
            CipherProfile.QUANTUM_SAFE: 0.0000087,
            CipherProfile.HARDENED: 0.0000053,
            CipherProfile.BALANCED: 0.0000043,
            CipherProfile.CHEAP: 0.0000021,
        }[self]

    def ttl_seconds(self) -> int:
        """Recommended key lifetime in seconds."""
        return {
            CipherProfile.QUANTUM_SAFE: 1800,   # 30 min — highest sensitivity
            CipherProfile.HARDENED: 3600,        # 1 hour
            CipherProfile.BALANCED: 7200,        # 2 hours
            CipherProfile.CHEAP: 14400,          # 4 hours
        }[self]

    @classmethod
    def stronger(cls, a: "CipherProfile", b: "CipherProfile") -> "CipherProfile":
        """Return whichever profile is stronger (fail-secure: never downgrade)."""
        return a if _STRENGTH[a] >= _STRENGTH[b] else b


_STRENGTH: dict[CipherProfile, int] = {
    CipherProfile.CHEAP: 0,
    CipherProfile.BALANCED: 1,
    CipherProfile.HARDENED: 2,
    CipherProfile.QUANTUM_SAFE: 3,
}
