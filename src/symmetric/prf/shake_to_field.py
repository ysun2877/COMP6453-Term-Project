# Translation of Rust `src/symmetric/prf/shake_to_field.rs` to Python.

from __future__ import annotations
import hashlib
import os
from dataclasses import dataclass
from typing import List

# BabyBear modulus (2^31 - 2^27 + 1)
P_BABYBEAR = 2_013_265_921

# Constants
PRF_BYTES_PER_FE: int = 8  # number of PRF bytes per field element
KEY_LENGTH: int = 32
PRF_DOMAIN_SEP: bytes = bytes([
    0x00, 0x01, 0x12, 0xff, 0x00, 0x01, 0xfa, 0xff, 0x00, 0xaf, 0x12, 0xff, 0x01, 0xfa, 0xff, 0x00,
])

@dataclass(frozen=True)
class ShakePRFtoF:
    """Python counterpart of `ShakePRFtoF<const OUTPUT_LENGTH_FE: usize>`.
    Returns OUTPUT_LENGTH_FE BabyBear field elements per apply().
    """
    output_length_fe: int

    @staticmethod
    def key_gen(rng) -> bytes:
        """Generate a random 32-byte key."""
        rb = getattr(rng, "randbytes", None)
        if rb is None:
            return os.urandom(KEY_LENGTH)
        return rb(KEY_LENGTH)

    @staticmethod
    def _to_field_elements(raw: bytes, out_len_fe: int) -> List[int]:
        """Map raw bytes to field elements by grouping into PRF_BYTES_PER_FE chunks, big-endian, then mod p."""
        out = []
        for i in range(out_len_fe):
            start = i * PRF_BYTES_PER_FE
            end = start + PRF_BYTES_PER_FE
            chunk = raw[start:end]
            # Big-endian integer
            val = int.from_bytes(chunk, "big", signed=False) % P_BABYBEAR
            out.append(val)
        return out

    @staticmethod
    def apply(key: bytes, epoch: int, index: int, *, output_length_fe: int) -> List[int]:
        """Apply SHAKE128 keyed by domain-sep || key || epoch_be || index_be, return `output_length_fe` BabyBear FEs."""
        assert isinstance(key, (bytes, bytearray)) and len(key) == KEY_LENGTH
        assert 0 <= epoch < (1 << 32)
        assert 0 <= index < (1 << 64)
        # SHAKE128 XOF
        shake = hashlib.shake_128()
        shake.update(PRF_DOMAIN_SEP)
        shake.update(key)
        shake.update(epoch.to_bytes(4, "big", signed=False))
        shake.update(index.to_bytes(8, "big", signed=False))
        raw = shake.digest(PRF_BYTES_PER_FE * output_length_fe)
        return ShakePRFtoF._to_field_elements(raw, output_length_fe)

    @staticmethod
    def internal_consistency_check() -> None:
        # No additional param checks needed here (mirrors Rust comment)
        return None

# Convenience factories to mimic generic aliases
def ShakePRFtoF_4() -> ShakePRFtoF:
    return ShakePRFtoF(output_length_fe=4)

def ShakePRFtoF_8() -> ShakePRFtoF:
    return ShakePRFtoF(output_length_fe=8)
