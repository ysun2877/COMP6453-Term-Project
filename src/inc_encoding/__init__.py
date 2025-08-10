# translated from src/inc_encoding.rs
from abc import ABC, abstractmethod
from random import Random
from typing import Protocol, Type, TypeVar, Generic, List, runtime_checkable

# Import crate-wide constant
from ..lib import MESSAGE_LENGTH

# ─── Error type ─────────────────────────────────────────────────────────────────

class EncodingError(Exception):
    """Encoding failed after MAX_TRIES."""
    def __init__(self, message):
        super().__init__(message)

# ─── Type variables for parameters & randomness ─────────────────────────────────
# 1) Define a simple Protocol for “serializable” objects.
@runtime_checkable
class Serializable(Protocol):
    def to_bytes(self) -> bytes:
        """Serialize self to bytes."""
        ...
    @classmethod
    def from_bytes(cls: Type["Serializable"], data: bytes) -> "Serializable":
        """Deserialize from bytes."""
        ...

# 2) Now bind our Parameter & Randomness type variables to that Protocol.
P = TypeVar("P", bound=Serializable)
R = TypeVar("R", bound=Serializable)


# ─── Base trait → abstract base class ──────────────────────────────────────────

class IncomparableEncoding(ABC, Generic[P, R]):
    """
    Encode a fixed-length MESSAGE_LENGTH byte string
    into an integer vector of length DIMENSION with entries in 0..BASE-1,
    such that no two distinct codewords are pointwise comparable.
    """

    # translate Rust’s `const DIMENSION: usize;`
    DIMENSION: int
    # `const MAX_TRIES: usize;`
    MAX_TRIES: int
    # `const BASE: usize;`
    BASE: int

    @classmethod
    @abstractmethod
    def rand(cls, rng: Random) -> R:
        """
        Sample randomness for encode().
        Mirrors Rust’s `fn rand<R: Rng>(rng: &mut R) -> Self::Randomness`.
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
        Mirrors Rust’s:
          fn encode(
            parameter: &Self::Parameter,
            message: &[u8; MESSAGE_LENGTH],
            randomness: &Self::Randomness,
            epoch: u32,
          ) -> Result<Vec<u8>, EncodingError>;
        """
        ...

    @classmethod
    def internal_consistency_check(cls) -> None:
        """
        Test-only consistency checks (panics in Rust under `#[cfg(test)]`).
        Python version can raise AssertionError if something’s wrong.
        """
from .basic_winternitz import BasicWinternitzEncoding, EncodingError
from .target_sum      import TargetSumWinternitzEncoding