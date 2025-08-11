# Translation of Rust `symmetric/tweak_hash/poseidon.rs` to Python.
# This is a functional stand-in using Python big-ints and SHAKE128 to emulate Poseidon2 compression.
# It preserves the interface expected by the previously generated instantiation factories.

from __future__ import annotations
from dataclasses import dataclass
from typing import List, Sequence, Union
import hashlib
import os
import math

# Constants
from ...lib import TWEAK_SEPARATOR_FOR_CHAIN_HASH, TWEAK_SEPARATOR_FOR_TREE_HASH


# BabyBear prime modulus (Plonky3 BabyBear): 2^31 - 2^27 + 1
P_BABYBEAR = 2_013_265_921

def _to_le_bytes(x: int, length: int) -> bytes:
    return x.to_bytes(length, "little", signed=False)

def _from_le_bytes(b: bytes) -> int:
    return int.from_bytes(b, "little", signed=False)

def encode_tree_tweak(level: int, pos_in_level: int, tweak_len_fe: int) -> List[int]:
    """Combine tree tweak parameters with domain separator, then decompose in base p."""
    assert 0 <= level < (1 << 8)
    assert 0 <= pos_in_level < (1 << 32)
    acc = ((level & 0xFF) << 40) | ((pos_in_level & 0xFFFFFFFF) << 8) | (TWEAK_SEPARATOR_FOR_TREE_HASH & 0xFF)
    limbs = []
    for _ in range(tweak_len_fe):
        digit = acc % P_BABYBEAR
        acc //= P_BABYBEAR
        limbs.append(digit)
    return limbs

def encode_chain_tweak(epoch: int, chain_index: int, pos_in_chain: int, tweak_len_fe: int) -> List[int]:
    """Combine chain tweak parameters with domain separator, then decompose in base p."""
    assert 0 <= epoch < (1 << 32)
    assert 0 <= chain_index < (1 << 8)
    assert 0 <= pos_in_chain < (1 << 8)
    acc = ((epoch & 0xFFFFFFFF) << 24) | ((chain_index & 0xFF) << 16) | ((pos_in_chain & 0xFF) << 8) | (TWEAK_SEPARATOR_FOR_CHAIN_HASH & 0xFF)
    limbs = []
    for _ in range(tweak_len_fe):
        digit = acc % P_BABYBEAR
        acc //= P_BABYBEAR
        limbs.append(digit)
    return limbs

def _poseidon2_compress_emulated(fe_list: Sequence[int], width: int, out_len: int) -> List[int]:
    """Emulate Poseidon2 compression using SHAKE128 as a KDF over canonical field bytes, then map to field elements.
    NOTE: This is NOT cryptographically equivalent to Poseidon2. Replace with a real Poseidon2 over BabyBear if available.
    """
    shake = hashlib.shake_128()
    for fe in fe_list:
        # 8-byte little-endian is enough to encode BabyBear elements (< 2^31)
        shake.update(_to_le_bytes(fe % P_BABYBEAR, 8))
    
    # Pad to width if needed
    while len(fe_list) < width:
        shake.update(b"\x00")
    
    out = []
    for _ in range(out_len):
        limb = _from_le_bytes(shake.digest(8)) % P_BABYBEAR
        # Differentiate subsequent limbs
        shake.update(b"\x00")
        out.append(limb)
    return out

def _poseidon2_sponge_emulated(fe_list: Sequence[int], capacity_value: List[int], width: int, out_len: int) -> List[int]:
    """Emulate Poseidon2 sponge construction using SHAKE128.
    NOTE: This is NOT cryptographically equivalent to Poseidon2. Replace with a real Poseidon2 over BabyBear if available.
    """
    shake = hashlib.shake_128()
    
    # Initialize with capacity value
    for fe in capacity_value:
        shake.update(_to_le_bytes(fe % P_BABYBEAR, 8))
    
    # Absorb input
    for fe in fe_list:
        shake.update(_to_le_bytes(fe % P_BABYBEAR, 8))
    
    # Squeeze output
    out = []
    for _ in range(out_len):
        limb = _from_le_bytes(shake.digest(8)) % P_BABYBEAR
        shake.update(b"\x00")
        out.append(limb)
    
    return out

@dataclass(frozen=True)
class PoseidonTweakHash:
    """Python counterpart of the const-generic Rust `PoseidonTweakHash<...>`.
    Parameters marked *_fe are counts of field elements, matching the Rust meaning.
    """
    parameter_len: int
    hash_len: int
    tweak_len: int
    capacity: int
    num_chunks: int

    def rand_parameter(self, rng) -> List[int]:
        """Return `parameter_len` random field elements using rng.randbytes(n)."""
        out = []
        for _ in range(self.parameter_len):
            rb = getattr(rng, "randbytes", None)
            if rb is None:
                val = _from_le_bytes(os.urandom(8)) % P_BABYBEAR
            else:
                val = _from_le_bytes(rb(8)) % P_BABYBEAR
            out.append(val)
        return out

    def rand_domain(self, rng) -> List[int]:
        """Return `hash_len` random field elements using rng.randbytes(n)."""
        out = []
        for _ in range(self.hash_len):
            rb = getattr(rng, "randbytes", None)
            if rb is None:
                val = _from_le_bytes(os.urandom(8)) % P_BABYBEAR
            else:
                val = _from_le_bytes(rb(8)) % P_BABYBEAR
            out.append(val)
        return out

    @staticmethod
    def tree_tweak(level: int, pos_in_level: int) -> tuple[int, int]:
        """Create tree tweak parameters."""
        return level, pos_in_level

    @staticmethod
    def chain_tweak(epoch: int, chain_index: int, pos_in_chain: int) -> tuple[int, int, int]:
        """Create chain tweak parameters."""
        return epoch, chain_index, pos_in_chain

    def apply(self, parameter: List[int], tweak: Union[tuple[int, int], tuple[int, int, int]], 
              message: List[List[int]]) -> List[int]:
        """Apply the tweakable hash function.
        
        Args:
            parameter: hash parameter as field elements
            tweak: tweak for domain separation (tree or chain parameters)
            message: message to hash (list of domain elements)
        
        Returns:
            hash output as field elements
        """
        # Determine tweak type and encode
        if len(tweak) == 2:
            # Tree tweak
            level, pos_in_level = tweak
            tweak_fe = encode_tree_tweak(level, pos_in_level, self.tweak_len)
        else:
            # Chain tweak
            epoch, chain_index, pos_in_chain = tweak
            tweak_fe = encode_chain_tweak(epoch, chain_index, pos_in_chain, self.tweak_len)

        if len(message) == 1:
            # Compress parameter, tweak, message
            combined_input = parameter + tweak_fe + message[0]
            return _poseidon2_compress_emulated(combined_input, 16, self.hash_len)
        
        elif len(message) == 2:
            # Compress parameter, tweak, message (now containing two parts)
            combined_input = parameter + tweak_fe + message[0] + message[1]
            return _poseidon2_compress_emulated(combined_input, 24, self.hash_len)
        
        elif len(message) > 2:
            # Hashing many blocks using sponge mode
            combined_input = parameter + tweak_fe + [item for sublist in message for item in sublist]
            
            # Create capacity value from domain parameters
            lengths = [
                self.parameter_len,
                self.tweak_len,
                self.num_chunks,
                self.hash_len,
            ]
            
            # Encode lengths as field elements
            capacity_value = []
            for length in lengths:
                capacity_value.extend(_to_le_bytes(length, 4))
                capacity_value = [x % P_BABYBEAR for x in capacity_value]
            
            return _poseidon2_sponge_emulated(combined_input, capacity_value, 24, self.hash_len)
        else:
            # Unreachable case, added for safety
            return [1] * self.hash_len

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
        # Convert bytes to field elements (simplified conversion)
        parameter = [_from_le_bytes(public_param[i:i+4]) % P_BABYBEAR 
                    for i in range(0, len(public_param), 4)]
        parameter = parameter[:self.parameter_len]  # Truncate to parameter_len
        
        # Create a default tweak (you might want to parse tweak bytes to determine type)
        # For now, we'll use a tree tweak as default
        tweak_obj = self.tree_tweak(0, 0)
        
        # Convert data to field elements
        message = [_from_le_bytes(data[i:i+4]) % P_BABYBEAR 
                  for i in range(0, len(data), 4)]
        message = [message[i:i+self.hash_len] for i in range(0, len(message), self.hash_len)]
        
        # Apply the hash function
        result = self.apply(parameter, tweak_obj, message)
        
        # Convert result back to bytes
        output_bytes = b''
        for field_elem in result:
            output_bytes += _to_le_bytes(field_elem, 4)
        
        return output_bytes

    def internal_consistency_check(self):
        """Mirror Rust's internal parameter checks."""
        assert self.capacity < 24, "Poseidon Tweak Chain Hash: Capacity must be less than 24"
        assert (self.parameter_len + self.tweak_len + self.hash_len <= 16), \
            "Poseidon Tweak Chain Hash: Input lengths too large for Poseidon instance"
        assert (self.parameter_len + self.tweak_len + 2 * self.hash_len <= 24), \
            "Poseidon Tweak Tree Hash: Input lengths too large for Poseidon instance"
        
        bits_per_fe = math.floor(math.log2(P_BABYBEAR))
        state_bits = bits_per_fe * 24
        assert state_bits >= (4 * 32), \
            "Poseidon Tweak Leaf Hash: not enough field elements to hash the domain separator"
        
        bits_for_tree_tweak = 32 + 8
        bits_for_chain_tweak = 32 + 8 + 8 + 8
        tweak_fe_bits = bits_per_fe * self.tweak_len
        assert tweak_fe_bits >= bits_for_tree_tweak, \
            "Poseidon Tweak Hash: not enough field elements to encode the tree tweak"
        assert tweak_fe_bits >= bits_for_chain_tweak, \
            "Poseidon Tweak Hash: not enough field elements to encode the chain tweak"

# Example instantiations
class PoseidonTweak44(PoseidonTweakHash):
    def __init__(self):
        super().__init__(4, 4, 3, 9, 128)

class PoseidonTweak37(PoseidonTweakHash):
    def __init__(self):
        super().__init__(3, 7, 3, 9, 128)

class PoseidonTweakW1L18(PoseidonTweakHash):
    def __init__(self):
        super().__init__(5, 7, 2, 9, 163)

class PoseidonTweakW1L5(PoseidonTweakHash):
    def __init__(self):
        super().__init__(5, 7, 2, 9, 163)
