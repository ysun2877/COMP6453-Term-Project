# Translation of Rust `src/symmetric/prf/sha.rs` to Python.
from __future__ import annotations
import hashlib
import os
from dataclasses import dataclass
from typing import ClassVar

# Domain separator and key length constants
KEY_LENGTH: int = 32  # bytes
PRF_DOMAIN_SEP: bytes = bytes([
    0x00, 0x01, 0x12, 0xff, 0x00, 0x01, 0xfa, 0xff, 0x00, 0xaf, 0x12, 0xff, 0x01, 0xfa, 0xff, 0x00,
])

@dataclass(frozen=True)
class ShaPRF:
    """Python counterpart of `ShaPRF<const OUTPUT_LENGTH: usize>`.
    Set OUTPUT_LENGTH when constructing the instance, or via factory functions.
    """
    output_length: int  # OUTPUT_LENGTH in bytes

    @staticmethod
    def key_gen(rng) -> bytes:
        """Generate a random 32-byte key (matches Rust KEY_LENGTH)."""
        rb = getattr(rng, "randbytes", None)
        if rb is None:
            return os.urandom(KEY_LENGTH)
        return rb(KEY_LENGTH)

    @staticmethod
    def apply(key: bytes, epoch: int, index: int, *, output_length: int) -> bytes:
        """Apply the PRF to (key, epoch, index) and return `output_length` bytes (<= 32).
        The input order matches Rust: PRF_DOMAIN_SEP || key || epoch_be || index_be, hashed with SHA3-256.
        """
        assert isinstance(key, (bytes, bytearray)) and len(key) == KEY_LENGTH
        assert 0 <= epoch < (1 << 32)
        assert 0 <= index < (1 << 64)
        assert 0 <= output_length <= 32
        h = hashlib.sha3_256()
        h.update(PRF_DOMAIN_SEP)
        h.update(key)
        h.update(epoch.to_bytes(4, "big", signed=False))   # to_be_bytes in Rust
        h.update(index.to_bytes(8, "big", signed=False))   # to_be_bytes in Rust
        digest = h.digest()
        return digest[:output_length]

    @staticmethod
    def internal_consistency_check(output_length: int) -> None:
        assert output_length < 32, "SHA PRF: Output length must be less than 256 bit"

# Convenience factories to mirror Rust generics
def ShaPRF_16() -> ShaPRF:
    return ShaPRF(output_length=16)

def ShaPRF_32() -> ShaPRF:
    return ShaPRF(output_length=32)
