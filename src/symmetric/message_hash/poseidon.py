# translated from src/symmetric/message_hash/poseidon.rs
# TODO: full Poseidon2-based message hash implementation
class PoseidonMessageHash(): #MessageHash
    def __init__(self, params):
        # placeholder for Poseidon parameters
        self.params = params

    def encode(self, message: bytes, randomness: bytes, epoch: int):
        raise NotImplementedError("Poseidon message hash not yet implemented")