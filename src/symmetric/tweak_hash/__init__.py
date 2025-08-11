# Tweak hash interface and exports (translation of the trait + helpers in tweak_hash.rs)

from __future__ import annotations
from typing import Protocol, runtime_checkable, Tuple, Iterable, Any, List, TypeVar, Generic
from dataclasses import dataclass
from abc import ABC, abstractmethod

from .sha import *
from .poseidon import *

@runtime_checkable
class TweakableHash(Protocol):
    """Python Protocol mirroring the Rust `TweakableHash` trait.
    
    A tweakable hash function takes a public parameter, a tweak, and a
    message to be hashed. The tweak should be understood as an
    address for domain separation.
    
    In our setting, we require the support of hashing lists of
    hashes. Therefore, we just define a type `Domain` and the
    hash function maps from [Domain] to Domain.
    
    We also require that the tweak hash already specifies how
    to obtain distinct tweaks for applications in chains and
    applications in Merkle trees.
    """
    def rand_parameter(self, rng: Any) -> Any: ...
    def rand_domain(self, rng: Any) -> Any: ...
    def tree_tweak(self, level: int, pos_in_level: int) -> Any: ...
    def chain_tweak(self, epoch: int, chain_index: int, pos_in_chain: int) -> Any: ...
    def apply(self, parameter: Any, tweak: Any, message: List[Any]) -> Any: ...
    def hash(self, public_param: bytes, tweak: bytes, data: bytes) -> bytes: ...
    def internal_consistency_check(self) -> None: ...

def chain(parameter: Any, epoch: int, chain_index: int, start_pos_in_chain: int, 
          steps: int, start: Any, th_class: type) -> Any:
    """Function implementing hash chains, implemented over a tweakable hash function.
    
    The chain is specific to an epoch `epoch`, and an index `chain_index`. All
    evaluations of the tweakable hash function use the given parameter `parameter`
    and tweaks determined by `epoch`, `chain_index`, and their position in the chain.
    We start walking the chain at position `start_pos_in_chain` with `start`,
    and then walk the chain for `steps` many steps. For example, walking two steps
    with `start = A` would mean we walk A -> B -> C, and then return C.
    
    Args:
        parameter: The public parameter for the tweakable hash function
        epoch: The epoch for domain separation
        chain_index: The index of the chain
        start_pos_in_chain: The starting position in the chain
        steps: The number of steps to walk
        start: The starting domain element
        th_class: The class implementing TweakableHash
    
    Returns:
        The final domain element after walking the chain
    """
    # keep track of what we have
    current = start

    # otherwise, walk the right amount of steps
    for j in range(steps):
        tweak = th_class.chain_tweak(epoch, chain_index, start_pos_in_chain + j + 1)
        current = th_class.apply(parameter, tweak, [current])

    # return where we are now
    return current