# translation of Rust module `instantiations_sha.rs`
# Functional translation for SHA-based XMSS instantiations (Winternitz & Target-Sum).
#
# Changes vs Rust:
# - Replace const generics/type aliases with Python factory functions returning
#   configured GeneralizedXMSSSignatureScheme instances.
# - Keep names for convenience constructors to mirror Rust aliases.
#
from dataclasses import dataclass
from typing import Literal

from inc_encoding.basic_winternitz import WinternitzEncoding
from inc_encoding.target_sum import TargetSumEncoding
from symmetric.message_hash.sha import ShaMessageHash
from symmetric.prf.sha import ShaPRF
from symmetric.tweak_hash.sha import ShaTweakHash
from signature.generalized_xmss import GeneralizedXMSSSignatureScheme

PARAMETER_LEN = 18
MESSAGE_HASH_LEN = 18
RAND_LEN = 23

CHUNK_SIZE = {1: 1, 2: 2, 4: 4, 8: 8}
NUM_CHAINS = {1: 144, 2: 72, 4: 36, 8: 18}
HASH_LEN_W = {1: 25, 2: 26, 4: 26, 8: 28}

# Winternitz checksum chains are fixed to 8 in the Rust file
WINTERNITZ_NUM_CHECKSUM_CHAINS = 8

# Target-sum parameters (from Rust type aliases)
TARGET_SUM_NO_OFF = {1: 72, 2: 108, 4: 270, 8: 2295}
TARGET_SUM_OFF10 = {1: 80, 2: 119, 4: 297, 8: 2525}

@dataclass(frozen=True)
class XMSSVariant:
    lifetime_log2: Literal[18,20]
    w: Literal[1,2,4,8]
    encoding: Literal['winternitz','target_sum']
    offset10: bool = False

def _build_shared(w: int):
    mh = ShaMessageHash(
        parameter_len=PARAMETER_LEN,
        rand_len=RAND_LEN,
        num_chains=NUM_CHAINS[w],
        chunk_size=CHUNK_SIZE[w],
    )
    th = ShaTweakHash(
        parameter_len=PARAMETER_LEN,
        hash_len=HASH_LEN_W[w],
    )
    prf = ShaPRF(output_len=HASH_LEN_W[w])
    return mh, th, prf

def make_winternitz(lifetime_log2: int, w: int) -> GeneralizedXMSSSignatureScheme:
    mh, th, prf = _build_shared(w)
    ie = WinternitzEncoding(
        message_hash=mh,
        chunk_size=CHUNK_SIZE[w],
        num_checksum_chains=WINTERNITZ_NUM_CHECKSUM_CHAINS,
    )
    return GeneralizedXMSSSignatureScheme(
        prf=prf,
        encoding=ie,
        tweak_hash=th,
        log_lifetime=lifetime_log2,
    )

def make_target_sum(lifetime_log2: int, w: int, offset10: bool=False) -> GeneralizedXMSSSignatureScheme:
    mh, th, prf = _build_shared(w)
    target = TARGET_SUM_OFF10[w] if offset10 else TARGET_SUM_NO_OFF[w]
    ie = TargetSumEncoding(message_hash=mh, target_sum=target)
    return GeneralizedXMSSSignatureScheme(
        prf=prf,
        encoding=ie,
        tweak_hash=th,
        log_lifetime=lifetime_log2,
    )

# Convenience functions mirroring Rust type aliases
def SIGWinternitzLifetime18W1(): return make_winternitz(18,1)
def SIGWinternitzLifetime18W2(): return make_winternitz(18,2)
def SIGWinternitzLifetime18W4(): return make_winternitz(18,4)
def SIGWinternitzLifetime18W8(): return make_winternitz(18,8)

def SIGTargetSumLifetime18W1NoOff(): return make_target_sum(18,1,False)
def SIGTargetSumLifetime18W1Off10(): return make_target_sum(18,1,True)
def SIGTargetSumLifetime18W2NoOff(): return make_target_sum(18,2,False)
def SIGTargetSumLifetime18W2Off10(): return make_target_sum(18,2,True)
def SIGTargetSumLifetime18W4NoOff(): return make_target_sum(18,4,False)
def SIGTargetSumLifetime18W4Off10(): return make_target_sum(18,4,True)
def SIGTargetSumLifetime18W8NoOff(): return make_target_sum(18,8,False)
def SIGTargetSumLifetime18W8Off10(): return make_target_sum(18,8,True)

def SIGWinternitzLifetime20W1(): return make_winternitz(20,1)
def SIGWinternitzLifetime20W2(): return make_winternitz(20,2)
def SIGWinternitzLifetime20W4(): return make_winternitz(20,4)
def SIGWinternitzLifetime20W8(): return make_winternitz(20,8)

def SIGTargetSumLifetime20W1NoOff(): return make_target_sum(20,1,False)
def SIGTargetSumLifetime20W1Off10(): return make_target_sum(20,1,True)
def SIGTargetSumLifetime20W2NoOff(): return make_target_sum(20,2,False)
def SIGTargetSumLifetime20W2Off10(): return make_target_sum(20,2,True)
def SIGTargetSumLifetime20W4NoOff(): return make_target_sum(20,4,False)
def SIGTargetSumLifetime20W4Off10(): return make_target_sum(20,4,True)
def SIGTargetSumLifetime20W8NoOff(): return make_target_sum(20,8,False)
def SIGTargetSumLifetime20W8Off10(): return make_target_sum(20,8,True)
