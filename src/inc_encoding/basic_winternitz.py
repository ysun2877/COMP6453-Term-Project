import hashlib
import math
from typing import List

class EncodingError(Exception):
    pass

class BasicWinternitzEncoding:
    """
    Winternitz encoding:
      - chunk size = CHUNK_SIZE = w_exp
      - BASE = 1 << CHUNK_SIZE
      - DIMENSION = n0 + n1, where n1 covers the checksum bits
    """

    VALID_CHUNK_SIZES = {1, 2, 4, 8}
    MH_BASE = 256  # SHAKE-128 outputs bytes ∈ [0,255]

    @staticmethod
    def internal_consistency_check(n0: int, w_exp: int):
        # chunk size must be 1, 2, 4, or 8
        if w_exp not in BasicWinternitzEncoding.VALID_CHUNK_SIZES:
            raise ValueError("Winternitz Encoding: Chunk Size must be 1, 2, 4, or 8")

        base = 1 << w_exp
        # base must be at most 2^8
        if w_exp > 8 or base > BasicWinternitzEncoding.MH_BASE:
            raise ValueError("Winternitz Encoding: Base must be at most 2^8")

        # compute DIMENSION = n0 + n1
        checksum_bits = (n0 * (base - 1)).bit_length()
        n1 = math.ceil(checksum_bits / w_exp)
        dimension = n0 + n1

        # dimension must be at most 2^8
        if dimension > (1 << 8):
            raise ValueError("Winternitz Encoding: Dimension must be at most 2^8")

    def __init__(self, n0: int, w_exp: int):
        # mirror Rust's compile-time sanity checks at runtime
        BasicWinternitzEncoding.internal_consistency_check(n0, w_exp)

        self.n0 = n0
        self.w = 1 << w_exp
        self.base = self.w

        # compute checksum length n1 and total dimension v
        checksum_bits = (n0 * (self.base - 1)).bit_length()
        self.n1 = math.ceil(checksum_bits / w_exp)
        self.v = n0 + self.n1

    def encode(self, message: bytes) -> List[int]:
        # Hash the message to n0 bytes
        digest = hashlib.shake_128(message).digest(self.n0)
        x = list(digest)
        # ensure each chunk < BASE
        if any(xi >= self.base for xi in x):
            raise EncodingError("Encoded chunk too large")

        # compute checksum
        checksum = self.n0 * (self.base - 1) - sum(x)
        c = []
        for _ in range(self.n1):
            c.append(checksum % self.base)
            checksum //= self.base
        if checksum != 0:
            raise EncodingError("Checksum overflow")

        # return message-chunks || checksum-chunks (reversed)
        return x + c[::-1]