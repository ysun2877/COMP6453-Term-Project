import hashlib
import math
from typing import List

# Use the unified error type defined in inc_encoding/__init__.py
from . import EncodingError


class BasicWinternitzEncoding:
    """
    Basic Winternitz encoding (used in WOTS/W-OTS schemes).

    Parameters
    ----------
    n0 : int
        Number of message digits (before checksum digits).
    w_exp : int
        log2(base). Must be 1, 2, 4, or 8.

    Attributes
    ----------
    base : int
        The base = 2**w_exp.
    n1 : int
        Number of checksum digits.
    v : int
        Total number of digits = n0 + n1.

    Notes
    -----
    This implementation bit-slices the SHAKE-128 output to support w_exp in {1,2,4,8}.
    It matches the typical W-OTS encoding: message digits + checksum digits (MSB first).
    """

    VALID_CHUNK_SIZES = {1, 2, 4, 8}
    MH_BASE = 256  # SHAKE-128 outputs bytes in [0,255]

    @staticmethod
    def internal_consistency_check(n0: int, w_exp: int):
        """
        Perform consistency checks:
          - w_exp must be in {1,2,4,8}
          - base <= 256
          - total dimension <= 256
        """
        if w_exp not in BasicWinternitzEncoding.VALID_CHUNK_SIZES:
            raise ValueError("Winternitz Encoding: chunk size must be 1, 2, 4, or 8")

        base = 1 << w_exp
        if w_exp > 8 or base > BasicWinternitzEncoding.MH_BASE:
            raise ValueError("Winternitz Encoding: base must be at most 2^8")

        checksum_bits = (n0 * (base - 1)).bit_length()
        n1 = math.ceil(checksum_bits / w_exp)
        dimension = n0 + n1
        if dimension > (1 << 8):
            raise ValueError("Winternitz Encoding: dimension must be at most 2^8")

    def __init__(self, n0: int, w_exp: int):
        BasicWinternitzEncoding.internal_consistency_check(n0, w_exp)
        self.n0 = n0
        self.w_exp = w_exp
        self.base = 1 << w_exp

        checksum_bits = (n0 * (self.base - 1)).bit_length()
        self.n1 = math.ceil(checksum_bits / w_exp)
        self.v = n0 + self.n1

    def encode(self, message: bytes) -> List[int]:
        """
        Encode a message into a list of v base-w digits.

        Args
        ----
        message : bytes
            Input message.

        Returns
        -------
        List[int]
            Digits in [0, base-1], length = v.

        Raises
        ------
        EncodingError
            If checksum overflow occurs (should not happen with correct sizing).
        """
        base = self.base
        w = self.w_exp

        # Number of bits needed for message digits
        total_bits = self.n0 * w
        need_bytes = (total_bits + 7) // 8

        # Generate enough bytes from SHAKE-128(message)
        stream = hashlib.shake_128(message).digest(need_bytes)

        # Bit-slice into n0 base-w digits
        digits = []
        bitbuf = 0
        bitcnt = 0
        i = 0
        while len(digits) < self.n0:
            if bitcnt < w:
                if i >= len(stream):
                    # Safety: should not happen since we requested enough bytes
                    stream += hashlib.shake_128(stream).digest(1)
                bitbuf |= stream[i] << bitcnt
                bitcnt += 8
                i += 1
                continue
            digits.append(bitbuf & (base - 1))
            bitbuf >>= w
            bitcnt -= w

        # Compute checksum = n0*(base-1) - sum(digits)
        checksum = self.n0 * (base - 1) - sum(digits)

        # Split checksum into n1 digits (MSB first)
        cs = []
        for _ in range(self.n1):
            cs.append(checksum % base)
            checksum //= base
        if checksum != 0:
            raise EncodingError("Checksum overflow")

        return digits + cs[::-1]
