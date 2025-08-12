from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Protocol, Tuple, TypeVar, ClassVar, runtime_checkable
import os
import pickle

from ..lib import MESSAGE_LENGTH  

# -----------------------------
# Errors (Rust: enum SigningError)
# -----------------------------

class SigningError(Exception):
    """Base class for signature-scheme errors."""
    INVALID_MESSAGE_LENGTH = "Invalid message length"
    UNLUCKY_FAILURE = "Unlucky failure"

class InvalidMessageLength(SigningError):
    """Raised if `message` is not exactly MESSAGE_LENGTH bytes."""
    pass

class UnluckyFailure(SigningError):
    """Raised if signing fails after all random retries."""
    pass


# -----------------------------
# SignatureScheme protocol (Rust: trait SignatureScheme)
# -----------------------------

PK = TypeVar("PK")
SK = TypeVar("SK")
SIG = TypeVar("SIG")

@runtime_checkable
class SignatureScheme(Protocol[PK, SK, SIG]):
    """
    Models a synchronized signature scheme that signs with respect to discrete epochs.
    Each epoch can be used at most once for signing with a given key.

    Implementations are defined as concrete classes (not instances) with fixed
    class-level parameters and all primary operations exposed as classmethods.

    Class attributes:
    - LIFETIME: int        # total number of supported epochs (must be a power of two)
    - LOG_LIFETIME: int    # log2(LIFETIME)
    - PRF: Pseudorandom    # instance of the PRF implementation
    - IE: IncomparableEncoding
    - TH: TweakableHash

    Methods (all @classmethod):
    - key_gen(cls, rng, activation_epoch: int, num_active_epochs: int) -> (PK, SK)
        Generate a fresh (public, secret) key pair valid for epochs
        activation_epoch .. activation_epoch + num_active_epochs - 1.

    - sign(cls, rng, sk: SK, epoch: int, message: bytes) -> SIG
        Sign a fixed-length message for the given epoch.
        Should raise SigningError on failure (InvalidMessageLength, UnluckyFailure).

    - verify(cls, pk: PK, epoch: int, message: bytes, sig: SIG) -> bool
        Verify that the signature is valid for the given public key, epoch, and message.

    - internal_consistency_check(cls) -> None
        (Optional) Raise AssertionError if any scheme-specific invariants are violated.
    """
    LIFETIME: ClassVar[int]
    LOG_LIFETIME: ClassVar[int]

    @classmethod
    def key_gen(cls, activation_epoch: int, num_active_epochs: int, rng: Any) -> Tuple[PK, SK]: ...
    @classmethod
    def sign(cls, sk: SK, epoch: int, message: bytes, rng: Any) -> SIG: ...
    @classmethod
    def verify(cls, pk: PK, epoch: int, message: bytes, sig: SIG) -> bool: ...
    @classmethod
    def internal_consistency_check(cls) -> None: ...

# -----------------------------
# Test template (mirror of Rust test_templates)
# -----------------------------

def test_signature_scheme_correctness(
    scheme_factory,
    epoch: int,
    activation_epoch: int,
    num_active_epochs: int,
):
    """
    Generic test for any implementation of SignatureScheme.
    - Generates a key pair
    - Signs a random message
    - Verifies the signature
    - Checks pickle round-trip consistency for pk/sk/sig (serde/bincode analog)
    """
    # Rust used rand::rng(); here we provide an OS-backed RNG adapter
    class ThreadRng:
        def randbytes(self, n: int) -> bytes:
            return os.urandom(n)

    rng = ThreadRng()

    # Build scheme and run keygen
    scheme: SignatureScheme = scheme_factory()
    pk, sk = scheme.key_gen(activation_epoch, num_active_epochs, rng)

    # Random message of fixed length
    message = os.urandom(MESSAGE_LENGTH)
    if len(message) != MESSAGE_LENGTH:
        raise InvalidMessageLength(SigningError.INVALID_MESSAGE_LENGTH)

    # Sign (raise on failure) and verify
    sig = scheme.sign(sk, epoch, message,rng)
    assert scheme.verify(pk, epoch, message, sig), f"Signature verification failed. Epoch was {epoch}"

    # Pickle round-trip (bincode serde analog)
    def round_trip_ok(x: Any) -> bool:
        blob = pickle.dumps(x, protocol=pickle.HIGHEST_PROTOCOL)
        y = pickle.loads(blob)
        return pickle.dumps(y, protocol=pickle.HIGHEST_PROTOCOL) == blob

    assert round_trip_ok(pk), "Serde consistency check failed for PK"
    assert round_trip_ok(sk), "Serde consistency check failed for SK"
    assert round_trip_ok(sig), "Serde consistency check failed for SIG"


# -----------------------------
# Module exports (Rust: pub mod generalized_xmss)
# -----------------------------

from .generalized_xmss import *
