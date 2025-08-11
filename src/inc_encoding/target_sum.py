# Translation of `src/inc_encoding/target_sum.rs` to Python.
# Incomparable Encoding based on a target-sum constraint, parameterized by a MessageHash.
#
# Note: The target sum parameter affects the *signing/search procedure* (how preimages are found)
# rather than the deterministic encoding function. The encoding output here is exactly the
# chunk vector produced by the underlying message hash.

from __future__ import annotations
from dataclasses import dataclass
from typing import List, Any

from ..symmetric.message_hash import MessageHash

@dataclass(frozen=True)
class TargetSumEncoding:
    """
    Python counterpart of the Rust const-generic
    `TargetSum<MH, TARGET_SUM>`.

    - `message_hash`: an instance implementing MessageHash; its outputs are the message chunks.
    - `target_sum`: integer parameter used by the signer/prover algorithm (kept for parity).
    """
    message_hash: MessageHash
    target_sum: int

    @property
    def BASE(self) -> int:
        return int(getattr(self.message_hash, "BASE"))

    @property
    def DIMENSION(self) -> int:
        return int(getattr(self.message_hash, "DIMENSION"))

    def apply(self, parameter: Any, epoch: int, randomness: Any, message: bytes) -> List[int]:
        """
        Return the base-`BASE` digit vector produced by the underlying message hash.
        The target sum is *not* enforced here; it is used during signing to guide the search.
        """
        chunks = self.message_hash.apply(parameter, epoch, randomness, message)
        # Sanity: range check
        base = self.BASE
        assert len(chunks) == self.DIMENSION, "Target Sum Encoding: wrong number of chunks from message hash"
        for c in chunks:
            assert 0 <= c < base, "Target Sum Encoding: chunk out of range"
        return chunks

    def internal_consistency_check(self):
        # base and dimension must not be too large
        assert self.BASE <= (1 << 8), "Target Sum Encoding: Base must be at most 2^8"
        assert self.DIMENSION <= (1 << 8), "Target Sum Encoding: Dimension must be at most 2^8"
        # also check internal consistency of message hash
        if hasattr(self.message_hash, "internal_consistency_check"):
            self.message_hash.internal_consistency_check()
