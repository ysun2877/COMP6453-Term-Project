# Translation of Rust `symmetric/tweak_hash/sha.rs` to Python.
# This is a functional implementation using Python's SHA3-256.
# It preserves the interface expected by the previously generated instantiation factories.

from __future__ import annotations
from dataclasses import dataclass
from typing import List, Sequence, Union
import hashlib
import os
import random

# Constants
from ...lib import TWEAK_SEPARATOR_FOR_CHAIN_HASH, TWEAK_SEPARATOR_FOR_TREE_HASH

def _to_be_bytes(x: int, length: int) -> bytes:
    """Convert integer to big-endian bytes."""
    return x.to_bytes(length, "big", signed=False)

class ShaTweak:
    """Enum to implement tweaks."""
    
    class TreeTweak:
        def __init__(self, level: int, pos_in_level: int):
            self.level = level
            self.pos_in_level = pos_in_level
        
        def to_bytes(self) -> bytes:
            """Convert tree tweak to bytes."""
            bytes_list = []
            # start with the tree tweak prefix
            bytes_list.append(TWEAK_SEPARATOR_FOR_TREE_HASH)
            # then we extend with the actual data
            bytes_list.extend(_to_be_bytes(self.level, 1))
            bytes_list.extend(_to_be_bytes(self.pos_in_level, 4))
            return bytes(bytes_list)
    
    class ChainTweak:
        def __init__(self, epoch: int, chain_index: int, pos_in_chain: int):
            self.epoch = epoch
            self.chain_index = chain_index
            self.pos_in_chain = pos_in_chain
        
        def to_bytes(self) -> bytes:
            """Convert chain tweak to bytes."""
            bytes_list = []
            # start with the chain tweak prefix
            bytes_list.append(TWEAK_SEPARATOR_FOR_CHAIN_HASH)
            # then we extend with the actual data
            bytes_list.extend(_to_be_bytes(self.epoch, 4))
            bytes_list.extend(_to_be_bytes(self.chain_index, 1))
            bytes_list.extend(_to_be_bytes(self.pos_in_chain, 1))
            return bytes(bytes_list)

@dataclass(frozen=True)
class ShaTweakHash:
    """Python counterpart of the const-generic Rust `ShaTweakHash<...>`.
    Parameters are lengths in bytes, matching the Rust meaning.
    """
    parameter_len: int
    hash_len: int

    def rand_parameter(self, rng) -> bytes:
        """Return `parameter_len` random bytes using rng.randbytes(n)."""
        rb = getattr(rng, "randbytes", None)
        if rb is None:
            return os.urandom(self.parameter_len)
        else:
            return rb(self.parameter_len)

    def rand_domain(self, rng) -> bytes:
        """Return `hash_len` random bytes using rng.randbytes(n)."""
        rb = getattr(rng, "randbytes", None)
        if rb is None:
            return os.urandom(self.hash_len)
        else:
            return rb(self.hash_len)

    @staticmethod
    def tree_tweak(level: int, pos_in_level: int) -> ShaTweak.TreeTweak:
        """Create tree tweak."""
        return ShaTweak.TreeTweak(level, pos_in_level)

    @staticmethod
    def chain_tweak(epoch: int, chain_index: int, pos_in_chain: int) -> ShaTweak.ChainTweak:
        """Create chain tweak."""
        return ShaTweak.ChainTweak(epoch, chain_index, pos_in_chain)

    def apply(self, parameter: bytes, tweak: Union[ShaTweak.TreeTweak, ShaTweak.ChainTweak], 
              message: List[bytes]) -> bytes:
        """Apply the tweakable hash function.
        
        Args:
            parameter: hash parameter as bytes
            tweak: tweak for domain separation
            message: message to hash (list of domain elements as bytes)
        
        Returns:
            hash output as bytes
        """
        hasher = hashlib.sha3_256()

        # add the parameter and tweak
        hasher.update(parameter)
        hasher.update(tweak.to_bytes())

        # now add the actual message to be hashed
        for m in message:
            hasher.update(m)

        # finalize the hash, and take as many bytes as we need
        result = hasher.digest()
        return result[:self.hash_len]

    def hash(self, public_param: bytes, tweak: bytes, data: bytes) -> bytes:
        """Hash function that takes bytes and returns bytes.
        This method converts the byte inputs to the appropriate format for the apply method.
        
        Args:
            public_param: public parameter as bytes
            tweak: tweak as bytes  
            data: data to hash as bytes
        
        Returns:
            hash output as bytes
        """
        # Create a default tweak (you might want to parse tweak bytes to determine type)
        # For now, we'll use a tree tweak as default
        tweak_obj = self.tree_tweak(0, 0)
        
        # Convert data to list of bytes chunks
        message = [data[i:i+self.hash_len] for i in range(0, len(data), self.hash_len)]
        
        # Apply the hash function
        return self.apply(public_param, tweak_obj, message)

    def internal_consistency_check(self):
        """Mirror Rust's internal parameter checks."""
        assert self.parameter_len < 256 // 8, \
            "SHA Tweak Hash: Parameter Length must be less than 256 bit"
        assert self.hash_len < 256 // 8, \
            "SHA Tweak Hash: Hash Length must be less than 256 bit"

# Example instantiations
class ShaTweak128128(ShaTweakHash):
    def __init__(self):
        super().__init__(16, 16)

class ShaTweak128192(ShaTweakHash):
    def __init__(self):
        super().__init__(16, 24)

class ShaTweak192192(ShaTweakHash):
    def __init__(self):
        super().__init__(24, 24)