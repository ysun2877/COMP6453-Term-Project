# Translation of Rust `symmetric/message_hash/poseidon.rs` to Python.
# This is a functional stand-in using Python big-ints and SHAKE128 to emulate Poseidon2 compression.
# It preserves the interface expected by the previously generated instantiation factories.

from __future__ import annotations
from dataclasses import dataclass
from typing import List, Sequence
import hashlib
import os
import math

from ...lib import MESSAGE_LENGTH, TWEAK_SEPARATOR_FOR_MESSAGE_HASH

# BabyBear prime modulus (Plonky3 BabyBear): 2^31 - 2^27 + 1
P_BABYBEAR = 2_013_265_921

def _to_le_bytes(x: int, length: int) -> bytes:
    return x.to_bytes(length, "little", signed=False)

def _from_le_bytes(b: bytes) -> int:
    return int.from_bytes(b, "little", signed=False)

def encode_message(message: bytes, msg_len_fe: int) -> List[int]:
    """Interpret message (fixed MESSAGE_LENGTH bytes) as little-endian integer and decompose in base p."""
    assert isinstance(message, (bytes, bytearray)) and len(message) == MESSAGE_LENGTH
    acc = _from_le_bytes(message)
    limbs = []
    for _ in range(msg_len_fe):
        digit = acc % P_BABYBEAR
        acc //= P_BABYBEAR
        limbs.append(digit)
    return limbs

def encode_epoch(epoch: int, tweak_len_fe: int) -> List[int]:
    """Combine epoch (u32) with a 1-byte domain separator, then decompose in base p."""
    assert 0 <= epoch < (1 << 32)
    acc = ((epoch & 0xFFFFFFFF) << 8) | (TWEAK_SEPARATOR_FOR_MESSAGE_HASH & 0xFF)
    limbs = []
    for _ in range(tweak_len_fe):
        digit = acc % P_BABYBEAR
        acc //= P_BABYBEAR
        limbs.append(digit)
    return limbs

def decode_to_chunks(field_elements: Sequence[int], dimension: int, base: int) -> List[int]:
    """Collapse HASH_LEN_FE field elements (base-p) to an integer, then convert to base-`base` digits of length `dimension`."""
    acc = 0
    for fe in field_elements:
        acc = (acc * P_BABYBEAR + (fe % P_BABYBEAR))  # base-p expansion
    chunks = []
    for _ in range(dimension):
        chunks.append(int(acc % base))
        acc //= base
    return chunks

def _poseidon2_compress_emulated(fe_list: Sequence[int], hash_len_fe: int) -> List[int]:
    """Emulate Poseidon2 compression using SHAKE128 as a KDF over canonical field bytes, then map to field elements.
    NOTE: This is NOT cryptographically equivalent to Poseidon2. Replace with a real Poseidon2 over BabyBear if available.
    """
    shake = hashlib.shake_128()
    for fe in fe_list:
        # 8-byte little-endian is enough to encode BabyBear elements (< 2^31)
        shake.update(_to_le_bytes(fe % P_BABYBEAR, 8))
    out = []
    for _ in range(hash_len_fe):
        limb = _from_le_bytes(shake.digest(8)) % P_BABYBEAR
        # Differentiate subsequent limbs
        shake.update(b"\x00")
        out.append(limb)
    return out

@dataclass(frozen=True)
class PoseidonMessageHash:
    """Python counterpart of the const-generic Rust `PoseidonMessageHash<...>`.
    Parameters marked *_fe are counts of field elements, matching the Rust meaning.
    """
    parameter_len: int
    rand_len_fe: int
    hash_len_fe: int
    dimension: int
    base: int
    tweak_len_fe: int
    msg_len_fe: int

    def rand(self, rng) -> List[int]:
        """Return `rand_len_fe` random field elements using rng.randbytes(n)."""
        out = []
        for _ in range(self.rand_len_fe):
            rb = getattr(rng, "randbytes", None)
            if rb is None:
                val = _from_le_bytes(os.urandom(8)) % P_BABYBEAR
            else:
                val = _from_le_bytes(rb(8)) % P_BABYBEAR
            out.append(val)
        return out

    def apply(self, parameter: List[int], epoch: int, randomness: List[int], message: bytes) -> List[int]:
        """Compute the message hash output as DIMENSION base-base chunks in [0, base)."""
        # Encode inputs
        msg_fe = encode_message(message, self.msg_len_fe)
        epoch_fe = encode_epoch(epoch, self.tweak_len_fe)

        # Combine inputs: randomness || parameter || epoch || message
        combined = [x % P_BABYBEAR for x in randomness]
        combined += [int(x) % P_BABYBEAR for x in parameter]
        combined += epoch_fe
        combined += msg_fe

        # Emulated Poseidon2 compression → HASH_LEN_FE field elements
        hash_fe = _poseidon2_compress_emulated(combined, self.hash_len_fe)

        # Decode to DIMENSION chunks base `base`
        return decode_to_chunks(hash_fe, self.dimension, self.base)

    def internal_consistency_check(self):
        """Mirror Rust's internal parameter checks."""
        assert self.hash_len_fe <= 24, "Poseidon width 24 bound exceeded"
        assert self.base <= (1 << 8), "Base must be at most 2^8"
        assert self.dimension <= (1 << 8), "Dimension must be at most 2^8"

        bits_per_fe = math.floor(math.log2(P_BABYBEAR))
        # enough bits to encode message
        message_fe_bits = bits_per_fe * self.msg_len_fe
        assert message_fe_bits >= 8 * MESSAGE_LENGTH, "Not enough field elements to encode the message"
        # enough bits to encode tweak (epoch + 1 byte)
        tweak_fe_bits = bits_per_fe * self.tweak_len_fe
        assert tweak_fe_bits >= (32 + 8), "Not enough field elements to encode the epoch tweak"
        # enough bits to decode hash into chunks
        needed_bits = math.log(self.base, 2) * self.dimension
        provided_bits = bits_per_fe * self.hash_len_fe
        assert provided_bits >= needed_bits, "Not enough bits to decode the hash into chunks"
