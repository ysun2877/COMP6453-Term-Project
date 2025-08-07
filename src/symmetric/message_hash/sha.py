import hashlib
import math
from typing import List
from abc import ABC, abstractmethod

class MessageHash(ABC):
    @abstractmethod
    def encode(self, message: bytes, randomness: bytes, epoch: int) -> List[int]:
        pass

class SHAMessageHash(MessageHash):
    VALID_CHUNK_SIZES = {1,2,4,8}

    def __init__(self, n0: int, chunk_size: int):
        if chunk_size not in self.VALID_CHUNK_SIZES:
            raise ValueError("Chunk size must be 1,2,4,8")
        self.n0 = n0
        self.chunk_size = chunk_size

    def encode(self, message: bytes, randomness: bytes, epoch: int) -> List[int]:
        data = randomness + message + epoch.to_bytes(4, 'big')
        digest = hashlib.shake_128(data).digest(self.n0)
        return bytes_to_chunks(digest, self.chunk_size)

def bytes_to_chunks(data: bytes, chunk_size: int) -> List[int]:
    # translate bytes_to_chunks from Rust
    assert chunk_size in {1,2,4,8}, "invalid chunk size"
    mask = (1 << chunk_size) - 1
    out = []
    for byte in data:
        for _ in range(8 // chunk_size):
            out.append(byte & mask)
            byte >>= chunk_size
    return out