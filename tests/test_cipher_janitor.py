"""Unit tests for CipherJanitor — HKDF, memory sanitation, salt reuse."""

from __future__ import annotations

import os

import pytest

from cipherweave.cipher_janitor import CipherJanitor, _zero_bytes
from cipherweave.exceptions import SaltReuseError
from cipherweave.profiles import CipherProfile


# ---------------------------------------------------------------------------
# RFC 5869 Test Vectors — Section A.1 (HKDF-SHA256, basic)
# ---------------------------------------------------------------------------

def test_hkdf_rfc5869_test_vectors() -> None:
    """Validate HKDF output against RFC 5869 Section A.1 test vector."""
    # A.1: Hash = SHA-256, IKM = 0x0b*22, Salt = 0x000102...0c, Info = 0xf0f1...f9
    ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    expected_okm = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    hkdf = HKDF(algorithm=hashes.SHA256(), length=42, salt=salt, info=info)
    okm = hkdf.derive(ikm)
    assert okm == expected_okm, f"RFC 5869 A.1 mismatch: {okm.hex()} != {expected_okm.hex()}"


def test_hkdf_rfc5869_vector_a2() -> None:
    """RFC 5869 Section A.2 — SHA-256 with longer inputs."""
    ikm = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f"
        "303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f"
    )
    salt = bytes.fromhex(
        "606162636465666768696a6b6c6d6e6f"
        "707172737475767778797a7b7c7d7e7f"
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    )
    info = bytes.fromhex(
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
        "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    )
    expected_okm = bytes.fromhex(
        "b11e398dc80327a1c8e7f78c596a4934"
        "4f012eda2d4efad8a050cc4c19afa97c"
        "59045a99cac7827271cb41c65e590e09"
        "da3275600c2f09b8367793a9aca3db71"
        "cc30c58179ec3e87c14c01d5c1f3434f"
        "1d87"
    )

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    hkdf = HKDF(algorithm=hashes.SHA256(), length=82, salt=salt, info=info)
    okm = hkdf.derive(ikm)
    assert okm == expected_okm


def test_derive_key_balanced(cipher_janitor: CipherJanitor) -> None:
    """derive_key returns correct key length for BALANCED profile."""
    msk = os.urandom(32)
    salt = os.urandom(32)
    info = b"cipherweave:v1:test-agent:ep-001:abc:1234567890"
    result = cipher_janitor.derive_key(msk, salt, info, CipherProfile.BALANCED)

    assert len(result.okm) == 32  # 256-bit
    assert result.hash_algo == "sha256"
    assert result.algorithm == "AES-256-GCM"


def test_derive_key_cheap(cipher_janitor: CipherJanitor) -> None:
    """derive_key returns 128-bit key for CHEAP profile."""
    msk = os.urandom(32)
    salt = os.urandom(32)
    info = b"cipherweave:v1:test-agent:ep-002:def:1234567890"
    result = cipher_janitor.derive_key(msk, salt, info, CipherProfile.CHEAP)

    assert len(result.okm) == 16  # 128-bit
    assert result.key_length_bits == 128


def test_derive_key_quantum_safe(cipher_janitor: CipherJanitor) -> None:
    """QUANTUM_SAFE uses SHA-512 and 256-bit key."""
    msk = os.urandom(32)
    salt = os.urandom(32)
    info = b"cipherweave:v1:test-agent:ep-003:ghi:1234567890"
    result = cipher_janitor.derive_key(msk, salt, info, CipherProfile.QUANTUM_SAFE)

    assert len(result.okm) == 32
    assert result.hash_algo == "sha512"
    assert "ML-KEM" in result.algorithm


def test_memory_sanitation() -> None:
    """Verify best-effort IKM zeroing does not crash and CipherJanitor completes normally."""
    janitor = CipherJanitor(kms_client=None, master_key_id="local")
    msk = bytearray(os.urandom(32))
    original = bytes(msk)

    salt = os.urandom(32)
    info = b"cipherweave:v1:mem-test:ep:hash:111"
    # Pass as bytes (copy of msk)
    msk_bytes = bytes(msk)
    result = janitor.derive_key(msk_bytes, salt, info, CipherProfile.BALANCED)

    # OKM must be present and correct length
    assert len(result.okm) == 32
    # Zero the bytearray manually and confirm
    _zero_bytes(msk)
    assert all(b == 0 for b in msk)


def test_salt_reuse_detection(cipher_janitor: CipherJanitor) -> None:
    """Same (salt, info) pair raises SaltReuseError on second call."""
    salt = os.urandom(32)
    info = b"cipherweave:v1:agent-x:ep-y:hash:9999"

    msk1 = os.urandom(32)
    cipher_janitor.derive_key(msk1, salt, info, CipherProfile.BALANCED)

    msk2 = os.urandom(32)
    with pytest.raises(SaltReuseError):
        cipher_janitor.derive_key(msk2, salt, info, CipherProfile.BALANCED)


def test_different_salts_succeed(cipher_janitor: CipherJanitor) -> None:
    """Two different salts with same info must both succeed."""
    info = b"cipherweave:v1:agent-a:ep-b:hash:8888"
    salt1 = os.urandom(32)
    salt2 = os.urandom(32)
    assert salt1 != salt2

    msk1 = os.urandom(32)
    msk2 = os.urandom(32)
    r1 = cipher_janitor.derive_key(msk1, salt1, info, CipherProfile.BALANCED)
    r2 = cipher_janitor.derive_key(msk2, salt2, info, CipherProfile.BALANCED)

    assert r1.okm != r2.okm  # different salts → different OKM


def test_hybrid_keypair_generation(cipher_janitor: CipherJanitor) -> None:
    """generate_hybrid_keypair returns valid key sizes."""
    kp = cipher_janitor.generate_hybrid_keypair()
    assert len(kp.x25519_public) == 32
    assert len(kp.x25519_private) == 32
    # ML-KEM-768 public key: 1184 bytes
    assert len(kp.mlkem_public) == 1184


def test_secure_context_cleans_up() -> None:
    """secure_context zeroes registered buffers on exit."""
    janitor = CipherJanitor(kms_client=None, master_key_id="local")
    buf = bytearray(os.urandom(32))

    with janitor.secure_context():
        janitor.register_buffer(buf)
        assert any(b != 0 for b in buf)

    assert all(b == 0 for b in buf)
