# Translation of Rust main.rs to Python
# Notes:
# - Rust uses generic functions and associated functions `T::key_gen`. Here we instantiate
#   the scheme via factory helpers and call `scheme.key_gen(...)`.
# - Rust uses `rand::rng()`/`ThreadRng`; here we use `os.urandom` via a small RNG adapter.
# - The descriptions and ordering mirror the Rust code.
#
import time
import os
from typing import Callable, Tuple

# Import the Poseidon instantiations (factories) previously translated
# Adjust the import path to your package layout as needed.
from ..signature.generalized_xmss.instantiations_poseidon import (
    SIGWinternitzLifetime18W1, SIGWinternitzLifetime18W2, SIGWinternitzLifetime18W4, SIGWinternitzLifetime18W8,
    SIGTargetSumLifetime18W1NoOff, SIGTargetSumLifetime18W2NoOff, SIGTargetSumLifetime18W4NoOff, SIGTargetSumLifetime18W8NoOff,
    SIGWinternitzLifetime20W1, SIGWinternitzLifetime20W2, SIGWinternitzLifetime20W4, SIGWinternitzLifetime20W8,
    SIGTargetSumLifetime20W1NoOff, SIGTargetSumLifetime20W2NoOff, SIGTargetSumLifetime20W4NoOff, SIGTargetSumLifetime20W8NoOff,
)

class OsRng:
    """Minimal RNG adapter providing os.urandom(bytes) via .randbytes(n)."""
    def randbytes(self, n: int) -> bytes:
        return os.urandom(n)

def measure_time(description: str, scheme_factory: Callable[[], object], rng: OsRng) -> None:
    """Mimics the Rust measure_time::<T, R>: generate keys and report elapsed time."""
    scheme = scheme_factory()  # Instance of GeneralizedXMSSSignatureScheme
    # The Rust code calls: T::key_gen(rng, 0, T::LIFETIME as usize)
    # In Python we expect: scheme.key_gen(rng, start_epoch=0, lifetime=scheme.lifetime or scheme.log_lifetime)
    # We'll try to read the exposed lifetime; else, fall back to 1 << scheme.log_lifetime.
    lifetime = getattr(scheme, "LIFETIME", None)
    if lifetime is None:
        log_L = getattr(scheme, "LOG_LIFETIME", None)
        lifetime = (1 << log_L) if isinstance(log_L, int) else None
    if lifetime is None:
        raise ValueError("lifetime is not defined")

    t0 = time.perf_counter()
    # Key generation should return (pk, sk); if the interface differs, adapt here.
    #_pk_sk = scheme.key_gen(rng, 0, lifetime) if lifetime is not None else scheme.key_gen(rng, 0)
    pk, sk = scheme.key_gen(0, lifetime, rng=rng)
    dt = time.perf_counter() - t0
    print(f"{description} - Gen: {dt:.6f}s")

    return pk, sk

def main():
    rng = OsRng()

    benches = [
        # Lifetime 2^18 - Winternitz
        ("Poseidon - L 18 - Winternitz - w 1", SIGWinternitzLifetime18W1),
        ("Poseidon - L 18 - Winternitz - w 2", SIGWinternitzLifetime18W2),
        ("Poseidon - L 18 - Winternitz - w 4", SIGWinternitzLifetime18W4),
        ("Poseidon - L 18 - Winternitz - w 8", SIGWinternitzLifetime18W8),

        # Lifetime 2^18 - Target Sum (NoOff)
        ("Poseidon - L 18 - Target Sum - w 1", SIGTargetSumLifetime18W1NoOff),
        ("Poseidon - L 18 - Target Sum - w 2", SIGTargetSumLifetime18W2NoOff),
        ("Poseidon - L 18 - Target Sum - w 4", SIGTargetSumLifetime18W4NoOff),
        ("Poseidon - L 18 - Target Sum - w 8", SIGTargetSumLifetime18W8NoOff),

        # Lifetime 2^20 - Winternitz
        ("Poseidon - L 20 - Winternitz - w 1", SIGWinternitzLifetime20W1),
        ("Poseidon - L 20 - Winternitz - w 2", SIGWinternitzLifetime20W2),
        ("Poseidon - L 20 - Winternitz - w 4", SIGWinternitzLifetime20W4),
        ("Poseidon - L 20 - Winternitz - w 8", SIGWinternitzLifetime20W8),

        # Lifetime 2^20 - Target Sum (NoOff)
        ("Poseidon - L 20 - Target Sum - w 1", SIGTargetSumLifetime20W1NoOff),
        ("Poseidon - L 20 - Target Sum - w 2", SIGTargetSumLifetime20W2NoOff),
        ("Poseidon - L 20 - Target Sum - w 4", SIGTargetSumLifetime20W4NoOff),
        ("Poseidon - L 20 - Target Sum - w 8", SIGTargetSumLifetime20W8NoOff),
    ]

    for desc, factory in benches:
        measure_time(desc, factory, rng)


if __name__ == "__main__":
    main()