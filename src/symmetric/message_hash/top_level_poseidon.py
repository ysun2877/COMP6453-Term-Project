# translated from src/symmetric/message_hash/top_level_poseidon.rs
# TODO: top-level Poseidon message hash glue
class TopLevelPoseidonMessageHash(MessageHash):
    def __init__(self, params):
        self.params = params
    def encode(self, message: bytes, randomness: bytes, epoch: int):
        raise NotImplementedError("Top-level Poseidon message hash not yet implemented")