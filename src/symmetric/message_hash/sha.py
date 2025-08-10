# Translation of Rust `symmetric/message_hash/sha.rs` to Python.
# Implements a SHA3-256-based message hash with chunking identical to the Rust logic.

from __future__ import annotations
from dataclasses import dataclass
from typing import List
import hashlib

from ...lib import MESSAGE_LENGTH  # your project-wide setting
from ..message_hash import bytes_to_chunks  # if you have a shared helper

def bytes_to_chunks(data: bytes, chunk_size: int) -> List[int]:
    """Split little-endian bitstream of `data` into chunks of `chunk_size` bits (1,2,4,8).
    Matches Rust's expected semantics (consuming bytes in order).
    """
    assert chunk_size in (1,2,4,8)
    out = []
    buf = 0
    buf_bits = 0
    for b in data:
        buf |= (b << buf_bits)
        buf_bits += 8
        while buf_bits >= chunk_size:
            out.append(buf & ((1 << chunk_size) - 1))
            buf >>= chunk_size
            buf_bits -= chunk_size
    return out

from ..tweak_hash.poseidon import TWEAK_SEPARATOR_FOR_MESSAGE_HASH

@dataclass(frozen=True)
class ShaMessageHash:
    """Python counterpart of const-generic `ShaMessageHash<PARAMETER_LEN, RAND_LEN, NUM_CHUNKS, CHUNK_SIZE>`."""
    parameter_len: int
    rand_len: int
    num_chunks: int
    chunk_size: int  # must be 1,2,4,8

    @property
    def DIMENSION(self) -> int:
        return self.num_chunks

    @property
    def BASE(self) -> int:
        return 1 << self.chunk_size

    def rand(self, rng) -> bytes:
        """Return RAND_LEN random bytes using rng.randbytes or os.urandom fallback."""
        rb = getattr(rng, "randbytes", None)
        if rb is None:
            import os
            return os.urandom(self.rand_len)
        return rb(self.rand_len)

    def apply(self, parameter: bytes, epoch: int, randomness: bytes, message: bytes) -> List[int]:
        assert isinstance(parameter, (bytes, bytearray)) and len(parameter) == self.parameter_len
        assert isinstance(randomness, (bytes, bytearray)) and len(randomness) == self.rand_len
        assert isinstance(message, (bytes, bytearray)) and len(message) == MESSAGE_LENGTH
        assert 0 <= epoch < (1 << 32)
        # Hash: randomness || parameter || [domain_sep] || u32_le(epoch) || message
        h = hashlib.sha3_256()
        h.update(randomness)
        h.update(parameter)
        h.update(bytes([TWEAK_SEPARATOR_FOR_MESSAGE_HASH & 0xFF]))
        h.update(epoch.to_bytes(4, "little", signed=False))
        h.update(message)
        digest = h.digest()
        # Take exactly NUM_CHUNKS * CHUNK_SIZE / 8 bytes before chunking
        nbytes = (self.num_chunks * self.chunk_size) // 8
        return bytes_to_chunks(digest[:nbytes], self.chunk_size)

    def internal_consistency_check(self):
        assert self.chunk_size in (1,2,4,8), "SHA Message Hash: Chunk Size must be 1, 2, 4, or 8"
        assert self.parameter_len < 32, "SHA Message Hash: Parameter Length must be less than 256 bit"
        assert self.rand_len < 32, "SHA Message Hash: Randomness Length must be less than 256 bit"
        assert self.rand_len > 0, "SHA Message Hash: Randomness Length must be non-zero"
        assert self.num_chunks * self.chunk_size % 8 == 0, "Output bit-length must be a whole number of bytes"

# Example aliases from the Rust file:
def ShaMessageHash128x3() -> ShaMessageHash:
    # PARAMETER_LEN=16, RAND_LEN=16, NUM_CHUNKS=16, CHUNK_SIZE=8
    return ShaMessageHash(16, 16, 16, 8)

def ShaMessageHash192x3() -> ShaMessageHash:
    # PARAMETER_LEN=24, RAND_LEN=24, NUM_CHUNKS=48, CHUNK_SIZE=4
    return ShaMessageHash(24, 24, 48, 4)
