# translation of Rust module `instantiations_poseidon.rs`
# Functional translation: defines factory functions to instantiate Poseidon-based XMSS schemes
# using Winternitz and Target-Sum encodings for lifetimes 2^18 and 2^20.
#
# Changes vs Rust:
# - Rust uses const generics and type aliases. Here we provide Python factory functions returning
#   configured instances of `GeneralizedXMSSSignatureScheme`.
# - Rust splits variants by modules; here we keep a flat module with clear function names.
# - Tests in Rust are omitted; you can validate via your existing test harness.
#
# Dependencies expected (Python counterparts):
#   - inc_encoding.basic_winternitz.WinternitzEncoding
#   - inc_encoding.target_sum.TargetSumEncoding
#   - symmetric.message_hash.poseidon.PoseidonMessageHash
#   - symmetric.prf.shake_to_field.ShakePRFtoF
#   - symmetric.tweak_hash.poseidon.PoseidonTweakHash
#   - signature.generalized_xmss.GeneralizedXMSSSignatureScheme
#
from dataclasses import dataclass
from typing import Literal

from inc_encoding.basic_winternitz import WinternitzEncoding
from inc_encoding.target_sum import TargetSumEncoding
from symmetric.message_hash.poseidon import PoseidonMessageHash
from symmetric.prf.shake_to_field import ShakePRFtoF
from symmetric.tweak_hash.poseidon import PoseidonTweakHash
from signature.generalized_xmss import GeneralizedXMSSSignatureScheme

# Shared Poseidon/XMSS constants (mirroring Rust)
PARAMETER_LEN = 5
CAPACITY = 9
RAND_LEN = 6
MSG_HASH_LEN_FE = 5
MSG_LEN_FE = 9
TWEAK_LEN_FE = 2

BASE = {1: 2, 2: 4, 4: 16, 8: 256}
CHUNK_SIZE = {1: 1, 2: 2, 4: 4, 8: 8}
NUM_CHAINS = {1: 155, 2: 78, 4: 39, 8: 20}
NUM_CHECKSUM_CHAINS = {1: 8, 2: 4, 4: 3, 8: 2}
HASH_LEN_FE = {1: 7, 2: 7, 4: 7, 8: 8}

TARGET_SUM_NO_OFF = {1: 78, 2: 117, 4: 293, 8: 2550}
TARGET_SUM_OFF10 = {1: 86, 2: 129, 4: 322, 8: 2805}

@dataclass(frozen=True)
class XMSSVariant:
    lifetime_log2: Literal[18, 20]
    w: Literal[1,2,4,8]
    encoding: Literal['winternitz','target_sum']
    offset10: bool = False

def _build_shared(w: int):
    # Components parameterized by w
    mh = PoseidonMessageHash(
        parameter_len=PARAMETER_LEN,
        rand_len=RAND_LEN,
        msg_hash_len_fe=MSG_HASH_LEN_FE,
        num_chains=NUM_CHAINS[w],
        base=BASE[w],
        tweak_len_fe=TWEAK_LEN_FE,
    )
    th = PoseidonTweakHash(
        parameter_len=PARAMETER_LEN,
        hash_len_fe=HASH_LEN_FE[w],
        tweak_len_fe=TWEAK_LEN_FE,
        capacity=CAPACITY,
        num_chains=NUM_CHAINS[w],
    )
    prf = ShakePRFtoF(output_len_fe=HASH_LEN_FE[w])
    return mh, th, prf

def make_winternitz(lifetime_log2: int, w: int) -> GeneralizedXMSSSignatureScheme:
    """Factory for Winternitz-encoded Poseidon-based XMSS (lifetime 2^lifetime_log2, w in {1,2,4,8})."""
    mh, th, prf = _build_shared(w)
    ie = WinternitzEncoding(
        message_hash=mh,
        chunk_size=CHUNK_SIZE[w],
        num_checksum_chains=NUM_CHECKSUM_CHAINS[w],
    )
    return GeneralizedXMSSSignatureScheme(
        prf=prf,
        encoding=ie,
        tweak_hash=th,
        log_lifetime=lifetime_log2,
    )

def make_target_sum(lifetime_log2: int, w: int, offset10: bool=False) -> GeneralizedXMSSSignatureScheme:
    """Factory for Target-Sum-encoded Poseidon-based XMSS (lifetime 2^lifetime_log2, w in {1,2,4,8}).
    If offset10=True, uses 'Off10' target-sum parameter set from Rust; otherwise uses 'NoOff'.
    """
    mh, th, prf = _build_shared(w)
    target = TARGET_SUM_OFF10[w] if offset10 else TARGET_SUM_NO_OFF[w]
    ie = TargetSumEncoding(
        message_hash=mh,
        target_sum=target,
    )
    return GeneralizedXMSSSignatureScheme(
        prf=prf,
        encoding=ie,
        tweak_hash=th,
        log_lifetime=lifetime_log2,
    )

# Convenient pre-bound constructors mirroring Rust type aliases
def SIGWinternitzLifetime18W1(): return make_winternitz(18, 1)
def SIGWinternitzLifetime18W2(): return make_winternitz(18, 2)
def SIGWinternitzLifetime18W4(): return make_winternitz(18, 4)
def SIGWinternitzLifetime18W8(): return make_winternitz(18, 8)

def SIGTargetSumLifetime18W1NoOff(): return make_target_sum(18, 1, False)
def SIGTargetSumLifetime18W1Off10(): return make_target_sum(18, 1, True)
def SIGTargetSumLifetime18W2NoOff(): return make_target_sum(18, 2, False)
def SIGTargetSumLifetime18W2Off10(): return make_target_sum(18, 2, True)
def SIGTargetSumLifetime18W4NoOff(): return make_target_sum(18, 4, False)
def SIGTargetSumLifetime18W4Off10(): return make_target_sum(18, 4, True)
def SIGTargetSumLifetime18W8NoOff(): return make_target_sum(18, 8, False)
def SIGTargetSumLifetime18W8Off10(): return make_target_sum(18, 8, True)

def SIGWinternitzLifetime20W1(): return make_winternitz(20, 1)
def SIGWinternitzLifetime20W2(): return make_winternitz(20, 2)
def SIGWinternitzLifetime20W4(): return make_winternitz(20, 4)
def SIGWinternitzLifetime20W8(): return make_winternitz(20, 8)

def SIGTargetSumLifetime20W1NoOff(): return make_target_sum(20, 1, False)
def SIGTargetSumLifetime20W1Off10(): return make_target_sum(20, 1, True)
def SIGTargetSumLifetime20W2NoOff(): return make_target_sum(20, 2, False)
def SIGTargetSumLifetime20W2Off10(): return make_target_sum(20, 2, True)
def SIGTargetSumLifetime20W4NoOff(): return make_target_sum(20, 4, False)
def SIGTargetSumLifetime20W4Off10(): return make_target_sum(20, 4, True)
def SIGTargetSumLifetime20W8NoOff(): return make_target_sum(20, 8, False)
def SIGTargetSumLifetime20W8Off10(): return make_target_sum(20, 8, True)
