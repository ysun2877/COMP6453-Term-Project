"""
inc_encoding package: Incomparable encoding framework and Winternitz encoding variants.

This package provides:
    - Common abstract base class `IncomparableEncoding`
    - A shared `EncodingError` exception type
    - Concrete implementations:
        * BasicWinternitzEncoding  (basic Winternitz message + checksum)
        * TargetSumWinternitzEncoding (target-sum variant)
"""
from __future__ import annotations
from typing import Protocol, runtime_checkable, Any, List, TypeVar

# Import crate-wide constant from lib
from ..lib import MESSAGE_LENGTH

# ─── Error Type ───
class EncodingError(Exception):
    """Raised when encoding fails (e.g., overflow, target-sum mismatch, max tries exceeded)."""
    pass

# Incomparable Encoding
ParameterT = TypeVar("ParameterT")
RandomnessT = TypeVar("RandomnessT")

@runtime_checkable
class IncomparableEncoding(Protocol[ParameterT, RandomnessT]):
    """Protocol mirroring the Rust `IncomparableEncoding` trait.

    Implementations should expose:
      - DIMENSION: int   (# of entries in the codeword)
      - MAX_TRIES: int   (# of times to resample randomness before giving up)
      - BASE: int        (each entry is in [0, BASE-1], with BASE <= 2^8)

    And provide:
      - rand(rng) -> RandomnessT
      - encode(parameter: ParameterT, message: bytes[MESSAGE_LENGTH],
               randomness: RandomnessT, epoch: int) -> List[int]
        (Raises EncodingError on failure.)

      - internal_consistency_check() -> None   (optional; for testing)
    """

    # Constants as attributes (implementations can define @property or class attrs)
    DIMENSION: int
    MAX_TRIES: int
    BASE: int

    @staticmethod
    def rand(rng: Any) -> RandomnessT: ...

    @staticmethod
    def encode(
        parameter: ParameterT,
        message: bytes,
        randomness: RandomnessT,
        epoch: int,
    ) -> List[int]: ...

    @staticmethod
    def internal_consistency_check() -> None: ...

# ─── Concrete Implementations ──────────────────────────────────────────────────
from .basic_winternitz import *
from .target_sum import *


