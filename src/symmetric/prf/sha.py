import hashlib
from abc import ABC, abstractmethod

class PRF(ABC):
    @abstractmethod
    def eval(self, key: bytes, data: bytes) -> bytes:
        pass

class ShaPRF(PRF):
    def __init__(self, output_len: int):
        self.output_len = output_len

    def eval(self, key: bytes, data: bytes) -> bytes:
        h = hashlib.sha3_256()
        h.update(key)
        h.update(data)
        return h.digest()[:self.output_len]
