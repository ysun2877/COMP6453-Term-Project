# Translation of Rust `hypercube.rs` to Python
# Functional equivalence with Python's big integers.
from dataclasses import dataclass
from itertools import accumulate
from functools import lru_cache
from typing import List, Tuple

MAX_DIMENSION = 100  # matches Rust

@dataclass
class LayerInfo:
    sizes: List[int]        # size of each layer d (0..=v*(w-1))
    prefix_sums: List[int]  # inclusive prefix sums over sizes

    def sizes_sum_in_range(self, start: int, end: int) -> int:
        """Sum sizes[start..=end], handling empty/invalid ranges."""
        if start > end:
            return 0
        # inclusive prefix sums: S[k] = sum_{i=0..k} sizes[i]
        total = self.prefix_sums[end]
        before = self.prefix_sums[start-1] if start > 0 else 0
        return total - before

# Cache: per base w we keep an array of LayerInfo for v=0..MAX_DIMENSION
_all_layer_info_cache = {}

def _prepare_layer_info(w: int):
    """Compute LayerInfo for v=0..MAX_DIMENSION for base w."""
    all_info: List[LayerInfo] = []

    # v = 0
    sizes0 = [1]  # only layer d=0
    pref0 = [1]
    all_info.append(LayerInfo(sizes0, pref0))

    # v = 1
    sizes1 = [1] * w  # layers 0..(w-1), each of size 1
    pref1 = list(accumulate(sizes1))
    all_info.append(LayerInfo(sizes1, pref1))

    # v >= 2
    for v in range(2, MAX_DIMENSION+1):
        prev = all_info[v-1]
        max_d = v*(w-1)
        sizes_v = []
        for d in range(0, max_d+1):
            # For this layer d, sum over a_i in [max(1, w-d), min(w, w - max(0, w-1 - d))]
            a_i_start = max(1, w - d)
            a_i_end = min(w, w - max(0, (w-1) - d))
            if a_i_start > a_i_end:
                sizes_v.append(0)
                continue
            d_prime_start = d - (w - a_i_start)
            d_prime_end = d - (w - a_i_end)
            sizes_v.append(prev.sizes_sum_in_range(d_prime_start, d_prime_end))
        pref_v = list(accumulate(sizes_v))
        all_info.append(LayerInfo(sizes_v, pref_v))

    return all_info

def _get_layer_data(w: int) -> List[LayerInfo]:
    if w not in _all_layer_info_cache:
        _all_layer_info_cache[w] = _prepare_layer_info(w)
    return _all_layer_info_cache[w]

def hypercube_part_size(w: int, v: int, d: int) -> int:
    """Size of layer d for v-dimensional w-ary hypercube."""
    return _get_layer_data(w)[v].sizes[d]

def hypercube_find_layer(w: int, v: int, x: int) -> Tuple[int, int]:
    """Given x in [0, w^v), find layer index d and offset within that layer."""
    info = _get_layer_data(w)[v]
    # binary search in prefix_sums to find smallest d with prefix_sums[d] > x
    lo, hi = 0, len(info.prefix_sums)-1
    while lo < hi:
        mid = (lo + hi)//2
        if info.prefix_sums[mid] > x:
            hi = mid
        else:
            lo = mid + 1
    d = lo
    if d == 0:
        return 0, x
    remainder = x - info.prefix_sums[d-1]
    return d, remainder

def map_to_vertex(w: int, v: int, d: int, x: int) -> List[int]:
    """Map index x inside layer d to the vertex a (length v, digits in [0,w-1]) lying on that layer.
    Preconditions mirror Rust asserts: 0 <= d <= v*(w-1), and x < size(layer v,d).
    """
    info = _get_layer_data(w)[v]
    assert 0 <= d <= v*(w-1)
    assert 0 <= x < info.sizes[d]

    out: List[int] = []
    x_curr = x
    d_curr = d
    # dimension v contributes last; work backwards building digits a_{v-1}..a_0
    for i in range(v, 0, -1):
        if i == 1:
            # last coordinate is determined
            a_i = d_curr
            out.append(a_i)
            break
        # find a_i in [max(1, w-d_curr), min(w, w - max(0, (w-1) - d_curr))] (1..w inclusive, represent a_i-1 as digit 0..w-1)
        a_start = max(1, w - d_curr)
        a_end = min(w, w - max(0, (w-1) - d_curr))
        # iterate possible a_i in increasing order and find the bucket for x_curr
        found = None
        for a_i in range(a_start, a_end+1):
            d_prime = d_curr - (w - a_i)
            prev = _get_layer_data(w)[i-1]
            sz = prev.sizes[d_prime]
            if x_curr < sz:
                found = a_i
                break
            x_curr -= sz
        assert found is not None
        a_digit = found - 1  # store as 0..w-1
        out.append(a_digit)
        d_curr -= (w - found)
    # out currently has length v but in reverse (from a_{v-1} down to a_0)
    out.reverse()
    return out

def map_to_integer(w: int, v: int, d: int, a: List[int]) -> int:
    """Inverse of map_to_vertex: map vertex a (digits 0..w-1 summing to d) to index x within layer d."""
    assert len(a) == v
    # verify sum of digits equals d
    assert sum(a) == d
    x_curr = 0
    d_curr = 0
    for i in range(v-1, -1, -1):
        ji = (w - 1) - a[i]
        d_curr += ji
        # j_start is max(0, d_curr - (w-1)*(remaining dims))
        j_start = max(0, d_curr - (w - 1) * (v - i - 1))
        info = _get_layer_data(w)[v - i - 1]
        x_curr += info.sizes_sum_in_range(d_curr - ji + 1, d_curr - j_start)
    assert d_curr == d
    return x_curr
