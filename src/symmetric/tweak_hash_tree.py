# Translation of Rust `src/symmetric/tweak_hash_tree.rs` to Python.
# Uses the project-provided `symmetric.tweak_hash.TweakableHash` interface.
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, List, Sequence

from .tweak_hash import TweakableHash 


@dataclass
class HashTreeLayer:
    start_index: int
    nodes: List[Any]  # TH::Domain

@dataclass
class HashTreeOpening:
    start_index: int
    co_path: List[Any]  # siblings (TH::Domain), one per level

@dataclass
class HashTree:
    depth: int
    layers: List[HashTreeLayer]

def _get_padded_layer(th_impl: TweakableHash, rng: Any, nodes: List[Any], start_index: int) -> HashTreeLayer:
    end_index = start_index + len(nodes) - 1
    nodes_with_padding: List[Any] = []

    # front padding if start_index is odd
    if start_index % 2 == 1:
        nodes_with_padding.append(th_impl.rand_domain(rng))

    actual_start_index = start_index - (start_index % 2)

    # actual content
    nodes_with_padding.extend(nodes)

    # back padding if end_index is even
    if end_index % 2 == 0:
        nodes_with_padding.append(th_impl.rand_domain(rng))

    return HashTreeLayer(start_index=actual_start_index, nodes=nodes_with_padding)


class HashTreeBuilder:
    """Functional builder providing methods equivalent to Rust `impl<HashTree<TH>>`."""

    def __init__(self, th_impl: TweakableHash):
        self.TH = th_impl

    def new(self, rng: Any, depth: int, start_index: int, parameter: Any, leaf_hashes: List[Any]) -> HashTree:
        # Validate capacity
        assert start_index + len(leaf_hashes) <= (1 << depth), (
            "Hash-Tree new: Not enough space for leafs. "
            "Consider changing start_index or number of leaf hashes"
        )

        th = self.TH
        layers: List[HashTreeLayer] = []

        # Leaf layer: leaves are already TH::Domain values
        leaf_nodes: List[Any] = list(leaf_hashes)

        # Add padding and store layer 0
        layers.append(_get_padded_layer(th, rng, leaf_nodes, start_index))

        # Build parents up to root
        for level in range(depth):
            current_layer = layers[level]
            parents: List[Any] = []
            # number of parent nodes equals len(current_layer.nodes)/2
            for j in range(0, len(current_layer.nodes), 2):
                left = current_layer.nodes[j]
                right = current_layer.nodes[j + 1]
                parent_index = j // 2 + current_layer.start_index // 2
                tweak = th.tree_tweak(level + 1, parent_index)
                parent = th.apply(parameter, tweak, [left, right])
                parents.append(parent)

            start_idx = current_layer.start_index // 2
            layers.append(_get_padded_layer(th, rng, parents, start_idx))

        return HashTree(depth=depth, layers=layers)

    @staticmethod
    def root(tree: HashTree) -> Any:
        assert tree.layers, "Hash-Tree must have at least one layer"
        return tree.layers[-1].nodes[0]

    @staticmethod
    def path(tree: HashTree, position: int) -> HashTreeOpening:
        assert tree.layers, "Hash-Tree path: Need at least one layer"
        assert position >= tree.layers[0].start_index, (
            "Hash-Tree path: Invalid position, position before start index"
        )
        assert position < tree.layers[0].start_index + len(tree.layers[0].nodes), (
            "Hash-Tree path: Invalid position, position too large"
        )

        co_path: List[Any] = []
        current_position = position
        for l in range(tree.depth):
            sibling_position = current_position ^ 0x01
            sibling_pos_in_vec = sibling_position - tree.layers[l].start_index
            co_path.append(tree.layers[l].nodes[sibling_pos_in_vec])
            current_position >>= 1

        return HashTreeOpening(start_index=tree.layers[0].start_index, co_path=co_path)


def hash_tree_verify(
    th_impl: TweakableHash,
    parameter: Any,
    root: Any,
    position: int,
    leaf: Any,
    opening: HashTreeOpening,
) -> bool:
    """Verify a Merkle authentication path for a sparse tweakable-hash tree."""
    depth = len(opening.co_path)
    num_leafs = 1 << depth

    assert position >= opening.start_index, (
        "Hash-Tree verify: Invalid position, position before start index"
    )
    assert position < opening.start_index + num_leafs, (
        "Hash-Tree verify: Invalid position, position too large"
    )

    current_node = leaf
    current_position = position

    # climb up
    for l in range(depth):
        # determine child order: if current_position is even -> left child, else right child
        if current_position % 2 == 0:
            children = [current_node, opening.co_path[l]]
        else:
            children = [opening.co_path[l], current_node]

        # determine new position (parent index)
        current_position >>= 1

        # hash to get parent
        tweak = th_impl.tree_tweak(l + 1, current_position)
        current_node = th_impl.apply(parameter, tweak, children)

    # Finally, root check
    return current_node == root
