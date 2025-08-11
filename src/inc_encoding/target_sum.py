import hashlib
from typing import List

# Use the unified error type defined in inc_encoding/__init__.py
from . import EncodingError


class TargetSumWinternitzEncoding:
    """
    Target-sum variant of Winternitz-style digit encoding.

    Parameters
    ----------
    v : int
        Number of digits to output.
    w_exp : int
        log2(base). The digit base is base = 2**w_exp.
    target : int
        The exact sum all digits must add up to.

    Notes
    -----
    `encode()` is the strict version: it maps v bytes to digits and requires the
    exact sum to match `target`, otherwise raises EncodingError.

    `encode_with_last_digit_adjustment()` is a pragmatic helper that fixes only
    the last digit if possible so the sum equals `target`.
    """

    def __init__(self, v: int, w_exp: int, target: int):
        self.v = v
        self.base = 1 << w_exp
        self.target = target

    def encode(self, message: bytes) -> List[int]:
        """
        Strict target-sum encoding.

        Steps
        -----
        1) Compute digest = SHAKE128(message).digest(v)
        2) Map each byte to a digit via x_i = byte % base
        3) Require sum(x) == target

        Returns
        -------
        List[int]
            A list of length v with digits in [0, base-1].

        Raises
        ------
        EncodingError
            If sum(x) != target.
        """
        digest = hashlib.shake_128(message).digest(self.v)
        x = [b % self.base for b in digest]
        if sum(x) != self.target:
            raise EncodingError("Sum mismatch")
        return x

    def encode_with_last_digit_adjustment(self, message: bytes) -> List[int]:
        """
        Adjust the last digit only if it keeps the digit in range and achieves the target sum.

        Logic
        -----
        - Compute the first v-1 digits as x_i = byte % base.
        - Let s = sum(x_0, ..., x_{v-2}). Set x_{v-1} = target - s.
        - If 0 <= x_{v-1} < base, return the vector; otherwise raise.

        Returns
        -------
        List[int]
            A list of length v with digits in [0, base-1].

        Raises
        ------
        EncodingError
            If v <= 0, or the required last digit is out of range.
        """
        if self.v <= 0:
            raise EncodingError("v must be positive")

        if self.v == 1:
            last = self.target
            if 0 <= last < self.base:
                return [last]
            raise EncodingError("Target is out of range for a single digit")

        digest = hashlib.shake_128(message).digest(self.v - 1)
        x = [b % self.base for b in digest]
        s = sum(x)
        last = self.target - s
        if 0 <= last < self.base:
            x.append(last)
            return x
        raise EncodingError("Cannot satisfy target with single-digit adjustment")
