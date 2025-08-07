import hashlib
from typing import List

class EncodingError(Exception):
    pass

class TargetSumWinternitzEncoding:
    def __init__(self, v: int, w_exp: int, target: int):
        self.v = v
        self.base = 1 << w_exp
        self.target = target

    def encode(self, message: bytes) -> List[int]:
        digest = hashlib.shake_128(message).digest(self.v)
        x = [b % self.base for b in digest]
        if sum(x) != self.target:
            raise EncodingError("Sum mismatch")
        return x
