# Translation of Rust `symmetric/prf/prf.rs` (helper & init) to Python.

from __future__ import annotations
from typing import Protocol, runtime_checkable, Any

@runtime_checkable
class Pseudorandom(Protocol):
    """Protocol mirroring the Rust `Pseudorandom` trait.
    Implementations should provide:
      - key_gen(rng) -> Key
      - apply(key, epoch: int, index: int) -> Output
      - internal_consistency_check() -> None  (optional, for tests)
    """
    # The concrete types for Key/Output are implementation-specific.

    @staticmethod
    def key_gen(rng: Any): ...

    @staticmethod
    def apply(key: Any, epoch: int, index: int): ...

    # Optional in Python; present to mirror Rust test hook.
    @staticmethod
    def internal_consistency_check() -> None: ...
    
from .sha import *
from .shake_to_field import *