# Translation of `src/inc_encoding/basic_winternitz.rs` to Python.
# Incomparable Encoding based on the basic Winternitz scheme.

from __future__ import annotations
from dataclasses import dataclass
from typing import List

from ..symmetric.message_hash import MessageHash 

@dataclass(frozen=True)
class WinternitzEncoding:
    """
    Python counterpart of the Rust const-generic
    `BasicWinternitz<MH, CHUNK_SIZE, NUM_CHUNKS_CHECKSUM>`.

    - `message_hash`: an instance implementing MessageHash; its outputs are the message chunks.
    - `chunk_size`: one of {1,2,4,8}. Base = 2**chunk_size.
    - `num_checksum_chains`: number of checksum chunks appended to the message chunks.
    """
    message_hash: MessageHash
    chunk_size: int
    num_checksum_chains: int

    @property
    def BASE(self) -> int:
        return 1 << self.chunk_size

    @property
    def NUM_CHAINS(self) -> int:
        # number of message chains equals MH.DIMENSION
        return int(getattr(self.message_hash, "DIMENSION"))

    @property
    def DIMENSION(self) -> int:
        return self.NUM_CHAINS + self.num_checksum_chains

    def _checksum_chunks(self, msg_chunks: List[int]) -> List[int]:
        """Compute the Winternitz checksum in base `BASE` with fixed length `num_checksum_chains` (LSB-first)."""
        base_minus_1 = self.BASE - 1
        s = sum(base_minus_1 - c for c in msg_chunks)
        cs: List[int] = []
        for _ in range(self.num_checksum_chains):
            cs.append(s % self.BASE)
            s //= self.BASE
        return cs

    def apply(self, parameter, epoch: int, randomness, message: bytes) -> List[int]:
        """
        Return `DIMENSION` base-`BASE` digits (the incomparable encoding):
          [message_chunks || checksum_chunks]
        """
        # Get message chunks from the message hash
        msg_chunks = self.message_hash.apply(parameter, epoch, randomness, message)
        # Sanity: ensure chunk counts/base match expectations
        assert len(msg_chunks) == self.NUM_CHAINS, "Winternitz Encoding: Unexpected message hash dimension"
        for c in msg_chunks:
            assert 0 <= c < self.BASE, "Winternitz Encoding: Message chunk out of range"

        checksum = self._checksum_chunks(msg_chunks)
        # If checksum didn't fully consume the sum (shouldn't happen if NUM_CHECKSUM is large enough),
        # remaining high digits are implicitly dropped (matching fixed-width representation).
        return list(msg_chunks) + checksum

    def internal_consistency_check(self):
        # dimension bound
        assert self.DIMENSION <= (1 << 8), "Winternitz Encoding: Dimension must be at most 2^8"

        # chunk size constraint
        assert self.chunk_size in (1, 2, 4, 8), "Winternitz Encoding: Chunk Size must be 1, 2, 4, or 8"

        # base consistency with message hash
        assert getattr(self.message_hash, "BASE") == self.BASE == (1 << self.chunk_size),             "Winternitz Encoding: Base and chunk size not consistent with message hash"

        # message hash should be self-consistent
        if hasattr(self.message_hash, "internal_consistency_check"):
            self.message_hash.internal_consistency_check()
