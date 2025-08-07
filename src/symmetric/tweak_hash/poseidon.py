# translated from src/symmetric/tweak_hash/poseidon.rs
# TODO: Poseidon2-based tweakable hash
class PoseidonTweakableHash:
    def __init__(self, params):
        self.params = params
    def hash(self, public_param: bytes, tweak: bytes, data: bytes) -> bytes:
        raise NotImplementedError("Poseidon tweakable hash not implemented")