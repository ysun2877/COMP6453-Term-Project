from abc import ABC, abstractmethod
from random import Random
from typing import Generic, TypeVar, Tuple

# pull in the shared MESSAGE_LENGTH constant
from ..lib import MESSAGE_LENGTH

# import our Serializable protocol (defined in inc_encoding/__init__.py)
from ..inc_encoding import Serializable

# ─── Associated‐type placeholders ───────────────────────────────────────────────
# In Rust: type PublicKey: Serialize + DeserializeOwned; etc.
PK = TypeVar("PK", bound=Serializable)
SK = TypeVar("SK", bound=Serializable)
SG = TypeVar("SG", bound=Serializable)


# ─── Error enum → Python exceptions ──────────────────────────────────────────────

class SigningError(Exception):
    """Base class for all signature‐scheme errors."""
    pass

class InvalidMessageLength(SigningError):
    """Raised if `message` is not exactly MESSAGE_LENGTH bytes."""
    pass

class UnluckyFailure(SigningError):
    """Raised if signing fails after all random retries."""
    pass


# ─── SignatureScheme trait → Python ABC ──────────────────────────────────────────

class SignatureScheme(ABC, Generic[PK, SK, SG]):
    """
    Synchronized signature scheme over discrete epochs.
    One signature per (secret key, epoch) pair.
    """

    #: total number of epochs supported by one key (must be a power of two)
    LIFETIME: int

    @classmethod
    @abstractmethod
    def key_gen(
        cls,
        rng: Random,
        activation_epoch: int,
        num_active_epochs: int,
    ) -> Tuple[PK, SK]:
        """
        Generate a fresh (public, secret) key pair.
        Valid for epochs
          activation_epoch .. activation_epoch + num_active_epochs - 1.
        """

    @classmethod
    @abstractmethod
    def sign(
        cls,
        rng: Random,
        sk: SK,
        epoch: int,
        message: bytes,
    ) -> SG:
        """
        Sign a fixed-length message for `epoch`.
        Raises:
          - InvalidMessageLength
          - UnluckyFailure
        """

    @classmethod
    @abstractmethod
    def verify(
        cls,
        pk: PK,
        epoch: int,
        message: bytes,
        signature: SG,
    ) -> bool:
        """
        Check that `signature` is valid for `pk`, `epoch`, and `message`.
        """

    @classmethod
    def internal_consistency_check(cls) -> None:
        """
        (Optional; test-only)
        Raise AssertionError if any invariants break.
        """
        pass


# ─── Submodule declaration ──────────────────────────────────────────────────────
# mirrors: `pub mod generalized_xmss;`
from .generalized_xmss import *