# Translation of `symmetric/message_hash/top_level_poseidon.rs` to Python.
# Uses the previously provided BabyBear field emulation and hypercube helpers.
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Sequence
import hashlib
import math
import os

from ...lib import MESSAGE_LENGTH
from .poseidon import encode_message, encode_epoch, P_BABYBEAR, _to_le_bytes, _from_le_bytes
from ...hypercube import hypercube_find_layer, hypercube_part_size, map_to_vertex

def _poseidon2_compress_emulated(fe_list: Sequence[int], out_len_fe: int) -> List[int]:
    """Emulate Poseidon2 compression using SHAKE128 over canonical field bytes; NOT crypto-equivalent."""
    shake = hashlib.shake_128()
    for fe in fe_list:
        shake.update(_to_le_bytes(fe % P_BABYBEAR, 8))
    out = []
    for _ in range(out_len_fe):
        limb = _from_le_bytes(shake.digest(8)) % P_BABYBEAR
        shake.update(b"\x00")
        out.append(limb)
    return out

def _map_into_hypercube_part(fe: Sequence[int], dimension: int, base: int, final_layer: int) -> List[int]:
    """Combine field elements to big integer (base p), then map into layers [0..final_layer] of {0..base-1}^dimension."""
    # Combine to big int in base-p
    acc = 0
    for x in fe:
        acc = acc * P_BABYBEAR + (int(x) % P_BABYBEAR)
    # How many elements live in layers 0..final_layer?
    part_size = 0
    for d in range(final_layer+1):
        part_size += hypercube_part_size(base, dimension, d)
    # Reduce into the part and find layer+offset
    acc_mod = acc % part_size
    d, offset = hypercube_find_layer(base, dimension, acc_mod)
    # Map offset to vertex on layer d
    vertex = map_to_vertex(base, dimension, d, offset)
    return vertex  # list of digits length=dimension in [0..base-1]

@dataclass(frozen=True)
class TopLevelPoseidonMessageHash:
    """Python counterpart of const-generic `TopLevelPoseidonMessageHash<...>`"""
    pos_output_len_per_inv_fe: int
    pos_invocations: int
    pos_output_len_fe: int
    dimension: int
    base: int
    final_layer: int
    tweak_len_fe: int
    msg_len_fe: int
    parameter_len: int
    rand_len: int

    @property
    def DIMENSION(self): return self.dimension
    @property
    def BASE(self): return self.base

    def rand(self, rng) -> List[int]:
        """Return `rand_len` random field elements in BabyBear."""
        out = []
        rb = getattr(rng, "randbytes", None)
        for _ in range(self.rand_len):
            b = (rb(8) if rb else os.urandom(8))
            out.append(_from_le_bytes(b) % P_BABYBEAR)
        return out

    def apply(self, parameter: List[int], epoch: int, randomness: List[int], message: bytes) -> List[int]:
        # Encode message and tweak
        msg_fe = encode_message(message, self.msg_len_fe)
        epoch_fe = encode_epoch(epoch, self.tweak_len_fe)

        # Collect Poseidon outputs across invocations with iteration index domain-sep
        total = self.pos_output_len_fe
        outputs = [0]*total
        for i in range(self.pos_invocations):
            iter_idx = [i & 0xFF]  # one-byte index as field element surrogate
            combined = [x % P_BABYBEAR for x in randomness]
            combined += [int(x) % P_BABYBEAR for x in parameter]
            combined += [int(x) % P_BABYBEAR for x in epoch_fe]
            combined += [int(x) % P_BABYBEAR for x in msg_fe]
            combined += iter_idx
            limbs = _poseidon2_compress_emulated(combined, self.pos_output_len_per_inv_fe)
            s = i*self.pos_output_len_per_inv_fe
            outputs[s:s+self.pos_output_len_per_inv_fe] = limbs

        # Map to the upper layers of the hypercube (0..final_layer)
        return _map_into_hypercube_part(outputs, self.dimension, self.base, self.final_layer)

    def internal_consistency_check(self):
        POSEIDON_WIDTH = 24
        assert self.pos_output_len_per_inv_fe <= 15, "POS_OUTPUT_LEN_PER_INV_FE must be at most 15"
        assert self.pos_invocations <= (1<<8), "POS_INVOCATIONS must be at most 2^8"
        assert self.pos_output_len_fe == self.pos_invocations * self.pos_output_len_per_inv_fe, \
            "POS_OUTPUT_LEN_FE must equal POS_INVOCATIONS * POS_OUTPUT_LEN_PER_INV_FE"
        assert self.final_layer <= (self.base - 1) * self.dimension, "FINAL_LAYER must be a valid layer"
        assert self.base <= (1<<8), "Base must be at most 2^8"
        assert self.dimension <= (1<<8), "Dimension must be at most 2^8"
        bits_per_fe = math.floor(math.log2(P_BABYBEAR))
        msg_bits = bits_per_fe * self.msg_len_fe
        assert msg_bits >= 8 * MESSAGE_LENGTH, "Not enough field elements to encode the message"
        tweak_bits = bits_per_fe * self.tweak_len_fe
        assert tweak_bits >= 40, "Not enough field elements to encode the epoch tweak"
