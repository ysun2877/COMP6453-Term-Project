
# Message hash interface and exports (translation of the trait + helpers in message_hash.rs)

from __future__ import annotations
from typing import Protocol, runtime_checkable, Tuple, Iterable, Any, List
from dataclasses import dataclass
from ...lib import MESSAGE_LENGTH  


@runtime_checkable
class MessageHash(Protocol):
    """Python Protocol mirroring the Rust `MessageHash` trait.
    Implementations should provide:
      - Parameter: encoded as bytes or field elements (type-specific)
      - Randomness: bytes or field elements (type-specific)
      - DIMENSION: number of output chunks
      - BASE: radix of each chunk
    """
    # Suggested structural attributes
    DIMENSION: int
    BASE: int
    def rand(self, rng: Any) -> Any: ...
    def apply(self, parameter: Any, epoch: int, randomness: Any, message: bytes) -> List[int]: ...
    def internal_consistency_check(self) -> None: ...

def isolate_chunk_from_byte(byte: int, chunk_index: int, chunk_size: int) -> int:
    """Extract the `chunk_index`-th chunk (LSB-first) of width `chunk_size` bits from an 8-bit byte.
    Example: byte=0b11001010, chunk_size=2 produces chunks [2,2,0,3] for indices 0..3.
    """
    assert 0 <= byte <= 0xFF
    assert chunk_size in (1,2,4,8), "Chunk size must be 1,2,4, or 8"
    chunks_per_byte = 8 // chunk_size
    assert 0 <= chunk_index < chunks_per_byte, "chunk_index out of range for this chunk_size"
    # LSB-first selection
    shift = chunk_index * chunk_size
    mask = (1 << chunk_size) - 1
    return (byte >> shift) & mask

def bytes_to_chunks(data: bytes, chunk_size: int) -> List[int]:
    """Split a byte string into chunks of `chunk_size` bits (1,2,4,8), LSB-first within each byte.
    Matches the Rust helper used by SHA message hash.
    """
    assert chunk_size in (1,2,4,8), "Chunk size must be 1,2,4, or 8"
    if not data:
        return []
    out: List[int] = []
    chunks_per_byte = 8 // chunk_size
    for b in data:
        for i in range(chunks_per_byte):
            out.append(isolate_chunk_from_byte(b, i, chunk_size))
    return out
