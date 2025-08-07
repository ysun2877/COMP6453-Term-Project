import hashlib

class SHA3TweakableHash:
    def __init__(self, output_size: int = 32):
        self.output_size = output_size

    def hash(self, public_param: bytes, tweak: bytes, data: bytes) -> bytes:
        h = hashlib.sha3_256()
        h.update(public_param)
        h.update(tweak)
        h.update(data)
        return h.digest()[: self.output_size]