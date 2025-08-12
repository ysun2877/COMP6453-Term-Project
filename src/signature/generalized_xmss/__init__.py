import random
from dataclasses import dataclass
from typing import Type, List, Tuple

from ...signature import SignatureScheme, SigningError
from ...inc_encoding import IncomparableEncoding
from ...symmetric.prf import Pseudorandom
from ...symmetric.tweak_hash import TweakableHash, chain
from ...symmetric.tweak_hash_tree import HashTree, HashTreeOpening, hash_tree_verify

@dataclass
class GeneralizedXMSSSignature:
    path: HashTreeOpening
    rho: bytes  # IE.Randomness
    hashes: List[bytes]  # List[TH.Domain]


@dataclass
class GeneralizedXMSSPublicKey:
    root: bytes  # TH.Domain
    parameter: object  # TH.Parameter


@dataclass
class GeneralizedXMSSSecretKey:
    prf_key: object  # PRF.Key
    tree: HashTree
    parameter: object  # TH.Parameter
    activation_epoch: int
    num_active_epochs: int


class GeneralizedXMSSSignatureScheme(SignatureScheme):
    # To instantiate, subclass and set these class attributes:
    PRF: Type[Pseudorandom]
    IE: Type[IncomparableEncoding]
    TH: Type[TweakableHash]
    LOG_LIFETIME: int

    @classmethod
    def key_gen(cls,
                activation_epoch: int,
                num_active_epochs: int
                ) -> Tuple[GeneralizedXMSSPublicKey, GeneralizedXMSSSecretKey]:
        lifetime = 1 << cls.LOG_LIFETIME
        assert activation_epoch + num_active_epochs <= lifetime, (
            "Key gen: activation_epoch + num_active_epochs exceed lifetime"
        )

        rng = random.SystemRandom()
        # Parameter for tweakable hash
        parameter = cls.TH.rand_parameter(rng)
        # PRF key
        prf_key = cls.PRF.key_gen(rng)

        num_chains = cls.IE.DIMENSION
        chain_length = cls.IE.BASE

        chain_ends_hashes = []
        for epoch in range(activation_epoch, activation_epoch + num_active_epochs):
            ends = []
            for idx in range(num_chains):
                start = cls.PRF.apply(prf_key, epoch, idx).into()
                end = chain(
                    parameter,
                    epoch,
                    idx,
                    0,
                    chain_length - 1,
                    start
                )
                ends.append(end)
            leaf = cls.TH.apply(parameter, cls.TH.tree_tweak(0, epoch), ends)
            chain_ends_hashes.append(leaf)

        tree = HashTree.new(
            rng,
            cls.LOG_LIFETIME,
            activation_epoch,
            parameter,
            chain_ends_hashes
        )
        root = tree.root()

        pk = GeneralizedXMSSPublicKey(root=root, parameter=parameter)
        sk = GeneralizedXMSSSecretKey(
            prf_key=prf_key,
            tree=tree,
            parameter=parameter,
            activation_epoch=activation_epoch,
            num_active_epochs=num_active_epochs
        )
        return pk, sk

    @classmethod
    def sign(cls,
             sk: GeneralizedXMSSSecretKey,
             epoch: int,
             message: bytes
             ) -> GeneralizedXMSSSignature:
        # Validate epoch
        start = sk.activation_epoch
        end = start + sk.num_active_epochs
        if not (start <= epoch < end):
            raise AssertionError("Signing: key not active for this epoch")

        path = sk.tree.path(epoch)

        # Incomparable encoding
        max_tries = cls.IE.MAX_TRIES
        rho = None
        x = None
        for _ in range(max_tries):
            curr_rho = cls.IE.rand(random.SystemRandom())
            try:
                curr_x = cls.IE.encode(sk.parameter, message, curr_rho, epoch)
                rho = curr_rho
                x = curr_x
                break
            except Exception:
                continue
        if x is None:
            raise SigningError(SigningError.UNLUCKY_FAILURE)

        # Compute chain hashes
        num_chains = cls.IE.DIMENSION
        hashes = []
        for idx in range(num_chains):
            start_val = cls.PRF.apply(sk.prf_key, epoch, idx).into()
            steps = x[idx]
            h = chain(
                sk.parameter,
                epoch,
                idx,
                0,
                steps,
                start_val
            )
            hashes.append(h)

        return GeneralizedXMSSSignature(path=path, rho=rho, hashes=hashes)

    @classmethod
    def verify(cls,
               pk: GeneralizedXMSSPublicKey,
               epoch: int,
               message: bytes,
               sig: GeneralizedXMSSSignature
               ) -> bool:
        lifetime = 1 << cls.LOG_LIFETIME
        if not (0 <= epoch < lifetime):
            return False

        try:
            x = cls.IE.encode(pk.parameter, message, sig.rho, epoch)
        except Exception:
            return False
        if len(x) != cls.IE.DIMENSION:
            return False

        chain_length = cls.IE.BASE
        ends = []
        for idx, xi in enumerate(x):
            steps = (chain_length - 1) - xi
            start_val = sig.hashes[idx]
            end = chain(
                pk.parameter,
                epoch,
                idx,
                xi,
                steps,
                start_val
            )
            ends.append(end)

        return hash_tree_verify(
            pk.parameter,
            pk.root,
            epoch,
            ends,
            sig.path
        )

    @classmethod
    def internal_consistency_check(cls) -> None:
        cls.PRF.internal_consistency_check()
        cls.IE.internal_consistency_check()
        cls.TH.internal_consistency_check()
        assert cls.IE.BASE <= 256, "BASE must fit in u8"
        assert cls.IE.DIMENSION <= 256, "DIMENSION must fit in u8"