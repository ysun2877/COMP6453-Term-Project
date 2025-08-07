from typing import List
from .tweak_hash.sha import SHA3TweakableHash
class MerkleTree:
    def __init__(self, leaves: List[bytes], hash_fn: SHA3TweakableHash, pub_seed: bytes):
        self.hash_fn = hash_fn
        self.pub_seed = pub_seed
        self.levels: List[List[bytes]] = []
        self._build(leaves)

    def _build(self, leaves: List[bytes]):
        self.levels = [leaves]
        level = leaves
        height = 0
        while len(level) > 1:
            nxt = []
            for i in range(0, len(level), 2):
                left, right = level[i], level[i+1]
                tweak = height.to_bytes(4,'big') + (i//2).to_bytes(4,'big')
                nxt.append(self.hash_fn.hash(self.pub_seed, tweak, left+right))
            self.levels.append(nxt)
            level = nxt
            height += 1

    def root(self) -> bytes:
        return self.levels[-1][0]

    def path(self, idx: int) -> List[bytes]:
        path = []
        for h, lvl in enumerate(self.levels[:-1]):
            sibling = idx ^ 1
            path.append(lvl[sibling])
            idx >>= 1
        return path

    @staticmethod
    def compute_root_from_path(leaf: bytes, idx: int, path: List[bytes], hash_fn: SHA3TweakableHash, pub_seed: bytes) -> bytes:
        node = leaf
        for height, sibling in enumerate(path):
            if (idx & 1) == 0:
                data = node + sibling
            else:
                data = sibling + node
            tweak = height.to_bytes(4,'big') + ((idx>>1).to_bytes(4,'big'))
            node = hash_fn.hash(pub_seed, tweak, data)
            idx >>= 1
        return node