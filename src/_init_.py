"""
inc_encoding package: Incomparable encoding framework and Winternitz encoding variants.

This package provides:
    - Common abstract base class `IncomparableEncoding`
    - A shared `EncodingError` exception type
    - Concrete implementations:
        * BasicWinternitzEncoding  (basic Winternitz message + checksum)
        * TargetSumWinternitzEncoding (target-sum variant)
"""

from abc import ABC, abstractmethod
from random import Random
from typing import Protocol, Type, TypeVar, Generic, List, runtime_checkable

# Import crate-wide constant from lib
from ..lib import MESSAGE_LENGTH

# ─── Shared Error Type ─────────────────────────────────────────────────────────
class EncodingError(Exception):
    """Raised when encoding fails (e.g., overflow, target-sum mismatch, max tries exceeded)."""
    def __init__(self, message: str):
        super().__init__(message)

# ─── Serializable Protocol ─────────────────────────────────────────────────────
@runtime_checkable
class Serializable(Protocol):
    """Protocol for serializable objects used as Parameters and Randomness."""
    def to_bytes(self) -> bytes:
        """Serialize self to bytes."""
        ...
    @classmethod
    def from_bytes(cls: Type["Serializable"], data: bytes) -> "Serializable":
        """Deserialize from bytes."""
        ...

# ─── Type variables for generic Parameters & Randomness ────────────────────────
P = TypeVar("P", bound=Serializable)
R = TypeVar("R", bound=Serializable)

# ─── Abstract Base Class for Incomparable Encodings ─────────────────────────────
class IncomparableEncoding(ABC, Generic[P, R]):
    """
    Encode a fixed-length MESSAGE_LENGTH byte string into an integer vector of
    length DIMENSION with entries in [0, BASE-1], such that no two distinct
    codewords are pointwise comparable.

    This is a direct translation of the Rust trait:
        trait IncomparableEncoding {
            const DIMENSION: usize;
            const MAX_TRIES: usize;
            const BASE: usize;

            fn rand<R: Rng>(rng: &mut R) -> Self::Randomness;
            fn encode(...) -> Result<Vec<u8>, EncodingError>;
        }
    """

    # Constants (class attributes in Python)
    DIMENSION: int
    MAX_TRIES: int
    BASE: int

    @classmethod
    @abstractmethod
    def rand(cls, rng: Random) -> R:
        """
        Sample randomness for encode().
        Mirrors Rust's:
            fn rand<R: Rng>(rng: &mut R) -> Self::Randomness
        """
        ...

    @classmethod
    @abstractmethod
    def encode(
        cls,
        parameter: P,
        message: bytes,
        randomness: R,
        epoch: int
    ) -> List[int]:
        """
        Encode the given message and associated randomness into a vector of digits.
        Mirrors Rust's:
            fn encode(
                parameter: &Self::Parameter,
                message: &[u8; MESSAGE_LENGTH],
                randomness: &Self::Randomness,
                epoch: u32,
            ) -> Result<Vec<u8>, EncodingError>
        """
        ...

    @classmethod
    def internal_consistency_check(cls) -> None:
        """
        Optional: Run test-only consistency checks.
        In Rust, this would panic under #[cfg(test)] if any invariant is broken.
        In Python, raises AssertionError instead.
        """
        ...

# ─── Concrete Implementations ──────────────────────────────────────────────────
from .basic_winternitz import BasicWinternitzEncoding
from .target_sum import TargetSumWinternitzEncoding

# ─── Public API ────────────────────────────────────────────────────────────────
__all__ = [
    "EncodingError",
    "Serializable",
    "IncomparableEncoding",
    "BasicWinternitzEncoding",
    "TargetSumWinternitzEncoding",
]
