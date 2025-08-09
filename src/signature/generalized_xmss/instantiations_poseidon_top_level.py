# Python translation of `instantiations_poseidon_top_level.rs`
# Functional factories for Top-Level Poseidon + Target-Sum XMSS instantiations.

from inc_encoding.target_sum import TargetSumEncoding
from symmetric.message_hash.top_level_poseidon import TopLevelPoseidonMessageHash
from symmetric.prf.shake_to_field import ShakePRFtoF
from symmetric.tweak_hash.poseidon import PoseidonTweakHash
from signature.generalized_xmss import GeneralizedXMSSSignatureScheme

def _build_components(*, DIMENSION, BASE, FINAL_LAYER, PARAMETER_LEN, TWEAK_LEN_FE, MSG_LEN_FE,
                      RAND_LEN_FE, HASH_LEN_FE, CAPACITY, POS_OUTPUT_LEN_PER_INV_FE, POS_INVOCATIONS):
    # Top-level Poseidon message hash
    mh = TopLevelPoseidonMessageHash(
        dimension=DIMENSION,
        base=BASE,
        final_layer=FINAL_LAYER,
        tweak_len_fe=TWEAK_LEN_FE,
        msg_len_fe=MSG_LEN_FE,
        parameter_len=PARAMETER_LEN,
        rand_len_fe=RAND_LEN_FE,
        pos_output_len_per_inv_fe=POS_OUTPUT_LEN_PER_INV_FE,
        pos_invocations=POS_INVOCATIONS,
    )
    th = PoseidonTweakHash(
        parameter_len=PARAMETER_LEN,
        hash_len_fe=HASH_LEN_FE,
        tweak_len_fe=TWEAK_LEN_FE,
        capacity=CAPACITY,
        num_chains=DIMENSION,  # matches 'DIMENSION' used as chain count in Rust for top-level
    )
    prf = ShakePRFtoF(output_len_fe=HASH_LEN_FE)
    return mh, th, prf

def _make_sig(*, log_lifetime, target_sum, **params):
    mh, th, prf = _build_components(**params)
    ie = TargetSumEncoding(message_hash=mh, target_sum=target_sum)
    return GeneralizedXMSSSignatureScheme(
        prf=prf, encoding=ie, tweak_hash=th, log_lifetime=log_lifetime
    )

# ---- 2^18 variant (Dim64, Base8) ----
def SIGTopLevelTargetSumLifetime18Dim64Base8():
    return _make_sig(
        log_lifetime=18,
        target_sum=375,
        DIMENSION=64,
        BASE=8,
        FINAL_LAYER=77,
        PARAMETER_LEN=5,
        TWEAK_LEN_FE=2,
        MSG_LEN_FE=9,
        RAND_LEN_FE=6,
        HASH_LEN_FE=7,
        CAPACITY=9,
        POS_OUTPUT_LEN_PER_INV_FE=15,
        POS_INVOCATIONS=1,
    )

# ---- 2^32 variants ----
def SIGTopLevelTargetSumLifetime32Dim64Base8():
    return _make_sig(
        log_lifetime=32,
        target_sum=375,
        DIMENSION=64,
        BASE=8,
        FINAL_LAYER=77,
        PARAMETER_LEN=5,
        TWEAK_LEN_FE=2,
        MSG_LEN_FE=9,
        RAND_LEN_FE=7,
        HASH_LEN_FE=8,
        CAPACITY=9,
        POS_OUTPUT_LEN_PER_INV_FE=15,
        POS_INVOCATIONS=1,
    )

def SIGTopLevelTargetSumLifetime32Dim48Base10():
    return _make_sig(
        log_lifetime=32,
        target_sum=326,
        DIMENSION=48,
        BASE=10,
        FINAL_LAYER=112,
        PARAMETER_LEN=5,
        TWEAK_LEN_FE=2,
        MSG_LEN_FE=9,
        RAND_LEN_FE=7,
        HASH_LEN_FE=8,
        CAPACITY=9,
        POS_OUTPUT_LEN_PER_INV_FE=15,
        POS_INVOCATIONS=1,
    )

def SIGTopLevelTargetSumLifetime32Dim32Base26():
    return _make_sig(
        log_lifetime=32,
        target_sum=579,
        DIMENSION=32,
        BASE=26,
        FINAL_LAYER=231,
        PARAMETER_LEN=5,
        TWEAK_LEN_FE=2,
        MSG_LEN_FE=9,
        RAND_LEN_FE=7,
        HASH_LEN_FE=8,
        CAPACITY=9,
        POS_OUTPUT_LEN_PER_INV_FE=15,
        POS_INVOCATIONS=1,
    )
