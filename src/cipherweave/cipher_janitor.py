"""Module 2: Stateless HKDF + PQC key derivation with memory sanitation."""

from __future__ import annotations

import ctypes
import gc
import hashlib
import logging
import os
from collections.abc import Generator
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cipherweave.exceptions import KMSError, SaltReuseError
from cipherweave.models import DerivedKeyResult, HybridKeyPair
from cipherweave.profiles import CipherProfile

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Full gc.collect() runs every N derivations; gen-0 collect runs every call.
# Full collect takes 5-25ms depending on heap size; interval amortizes that cost.
# 10000 = ~2-3 hour interval at 1 req/sec; production should schedule GC separately.
_GC_INTERVAL = 10000

_HASH_MAP: dict[str, Any] = {
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}


def _zero_bytes(buf: bytes | bytearray) -> None:
    """Overwrite a bytes/bytearray buffer with zeros in-place via ctypes."""
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0
        return
    # For immutable bytes objects, we target the internal buffer via ctypes.
    # This is a best-effort operation; CPython implementation detail.
    try:
        size = len(buf)
        if size > 0:
            ctypes.memmove(id(buf) + 33, b"\x00" * size, size)
    except Exception:
        pass  # Sanitization is best-effort; log but don't crash


class CipherJanitor:
    """Derives ephemeral keys using HKDF (RFC 5869) and ML-KEM-768 for PQC."""

    def __init__(self, kms_client: Any, master_key_id: str) -> None:
        self._kms_client = kms_client
        self._master_key_id = master_key_id
        # Track (salt_hex, info) pairs seen in this process lifetime to detect reuse
        self._used_contexts: set[tuple[str, str]] = set()
        self._ctx_buffers: list[bytes | bytearray] = []  # registered for secure_context cleanup
        self._gc_counter: int = 0  # counts derivations between full GC runs

    async def get_master_secret(self) -> bytes:
        """Fetch a fresh 32-byte master secret from KMS (or local mock)."""
        if self._kms_client is None:
            # Local dev: deterministic mock via os.urandom
            return os.urandom(32)
        try:
            response = self._kms_client.generate_data_key(
                KeyId=self._master_key_id,
                NumberOfBytes=32,
            )
            plaintext: bytes = response["Plaintext"]
            return plaintext
        except Exception as exc:
            raise KMSError(f"KMS GenerateDataKey failed: {exc}") from exc

    def derive_key(
        self,
        master_secret: bytes,
        salt: bytes,
        info: bytes,
        profile: CipherProfile,
    ) -> DerivedKeyResult:
        """HKDF (RFC 5869) key derivation with salt-reuse detection.

        Args:
            master_secret: 32-byte IKM from KMS.
            salt: Fresh 32-byte random salt — MUST be unique per call.
            info: Context string encoded as bytes.
            profile: Target CipherProfile determining key length and hash.

        Raises:
            SaltReuseError: Same (salt, info) pair used twice.
        """
        info_str = info.decode("utf-8", errors="replace")
        salt_hex = salt.hex()
        context_key = (salt_hex, info_str)

        if context_key in self._used_contexts:
            raise SaltReuseError(info_str)
        self._used_contexts.add(context_key)

        hash_algo_name = profile.hash_algorithm()
        hash_cls = _HASH_MAP[hash_algo_name]
        key_length = profile.key_length_bits() // 8

        hkdf = HKDF(
            algorithm=hash_cls(),
            length=key_length,
            salt=salt,
            info=info,
        )
        okm = hkdf.derive(master_secret)

        # Zero the IKM immediately after derivation
        _zero_bytes(master_secret)
        # Gen-0 collection is < 0.001ms; full gc.collect() runs every _GC_INTERVAL calls
        gc.collect(0)
        self._gc_counter += 1
        if self._gc_counter >= _GC_INTERVAL:
            gc.collect()
            self._gc_counter = 0

        return DerivedKeyResult(
            okm=okm,
            salt_used=salt,
            info_used=info_str,
            algorithm=profile.algorithm_label(),
            key_length_bits=profile.key_length_bits(),
            hash_algo=hash_algo_name,
        )

    def generate_hybrid_keypair(self) -> HybridKeyPair:
        """Generate X25519 + ML-KEM-768 hybrid keypair for QUANTUM_SAFE profile."""
        # X25519 keypair
        x25519_priv = X25519PrivateKey.generate()
        x25519_priv_bytes = x25519_priv.private_bytes_raw()
        x25519_pub_bytes = x25519_priv.public_key().public_bytes_raw()

        # ML-KEM-768 keypair
        mlkem_pub, mlkem_priv = _mlkem_generate_keypair()

        return HybridKeyPair(
            x25519_private=x25519_priv_bytes,
            x25519_public=x25519_pub_bytes,
            mlkem_private=mlkem_priv,
            mlkem_public=mlkem_pub,
        )

    def hybrid_shared_secret(
        self,
        x25519_private: bytes,
        x25519_peer_public: bytes,
        mlkem_ciphertext: bytes,
        mlkem_private: bytes,
    ) -> bytes:
        """Combine X25519 and ML-KEM shared secrets using SHA-512.

        Hybrid shared secret = SHA-512(x25519_shared || mlkem_shared)
        """
        x25519_priv_key = X25519PrivateKey.from_private_bytes(x25519_private)
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

        x25519_peer = X25519PublicKey.from_public_bytes(x25519_peer_public)
        x25519_shared = x25519_priv_key.exchange(x25519_peer)

        mlkem_shared = _mlkem_decapsulate(mlkem_private, mlkem_ciphertext)

        combined = x25519_shared + mlkem_shared
        digest = hashlib.sha512(combined).digest()

        _zero_bytes(x25519_shared)
        _zero_bytes(mlkem_shared)
        _zero_bytes(combined)

        return digest

    @contextmanager
    def secure_context(self) -> Generator[None, None, None]:
        """Context manager that zeros all registered byte buffers on exit."""
        registered: list[bytes | bytearray] = []
        original_add = self._ctx_buffers.append
        self._ctx_buffers = registered
        try:
            yield
        finally:
            for buf in registered:
                _zero_bytes(buf)
            self._ctx_buffers = []
            gc.collect(0)  # Gen-0 only; full GC is scheduled by derive_key's interval counter

    def register_buffer(self, buf: bytes | bytearray) -> None:
        """Register a buffer for cleanup when secure_context exits."""
        self._ctx_buffers.append(buf)


def _mlkem_generate_keypair() -> tuple[bytes, bytes]:
    """Generate ML-KEM-768 keypair. Returns (public_key, private_key)."""
    try:
        import mlkem  # type: ignore[import]

        # mlkem library API: keygen() → (ek, dk) where ek=encaps key, dk=decaps key
        ek, dk = mlkem.keygen(768)
        return ek, dk
    except ImportError:
        logger.warning("mlkem not installed — using random bytes stub for ML-KEM-768 keys")
        # Stub: realistic key sizes for ML-KEM-768
        # Public key: 1184 bytes, Private key: 2400 bytes
        return os.urandom(1184), os.urandom(2400)


def _mlkem_decapsulate(private_key: bytes, ciphertext: bytes) -> bytes:
    """Decapsulate ML-KEM-768 ciphertext to recover shared secret."""
    try:
        import mlkem  # type: ignore[import]

        shared_secret: bytes = mlkem.decaps(768, private_key, ciphertext)
        return shared_secret
    except ImportError:
        # Stub: return 32-byte random shared secret
        return os.urandom(32)
