"""RFC 9162 tree hashing and proof checks, against reference roots and exhaustive sizes."""

from __future__ import annotations

import hashlib

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from probity_observer.witness import proofs
from probity_observer.witness.proofs import ProofError

# The eight reference leaves and roots of the Certificate Transparency Merkle
# tree tests (certificate-transparency-go merkletree and trillian testonly).
CT_LEAVES = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"]
CT_ROOTS = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]


def leaves(count: int) -> list[bytes]:
    return [proofs.leaf_hash(n.to_bytes(4, "big")) for n in range(count)]


def test_empty_tree_root_is_the_hash_of_nothing():
    assert proofs.root([]) == hashlib.sha256(b"").digest()


@pytest.mark.parametrize("size", range(1, 9))
def test_roots_match_the_certificate_transparency_reference(size):
    hashed = [proofs.leaf_hash(bytes.fromhex(leaf)) for leaf in CT_LEAVES[:size]]
    assert proofs.root(hashed).hex() == CT_ROOTS[size - 1]


def test_leaf_and_node_prefixes_differ():
    left, right = proofs.leaf_hash(b"a"), proofs.leaf_hash(b"b")
    assert proofs.leaf_hash(left + right) != proofs.node_hash(left, right)


@pytest.mark.parametrize("size", range(1, 34))
def test_every_inclusion_path_verifies(size):
    tree = leaves(size)
    top = proofs.root(tree)
    for index in range(size):
        proofs.verify_inclusion(tree[index], index, size, proofs.inclusion_path(index, tree), top)


@pytest.mark.parametrize("size", range(1, 34))
def test_every_consistency_path_verifies(size):
    tree = leaves(size)
    for first in range(0, size + 1):
        path = proofs.consistency_path(first, tree)
        proofs.verify_consistency(first, size, proofs.root(tree[:first]), proofs.root(tree), path)


# A path does not bind the tree size by itself: for some sizes the same path and
# root also verify at size + 1. The checkpoint signature binds size and root
# together, which is why every check below takes both from one checkpoint.
@pytest.mark.parametrize("size", [2, 3, 5, 8, 13])
def test_inclusion_refuses_any_altered_input(size):
    tree = leaves(size)
    top = proofs.root(tree)
    for index in range(size):
        path = proofs.inclusion_path(index, tree)
        other = proofs.leaf_hash(b"tampered")
        with pytest.raises(ProofError):
            proofs.verify_inclusion(other, index, size, path, top)
        with pytest.raises(ProofError):
            proofs.verify_inclusion(tree[index], (index + 1) % size, size, path, top)
        with pytest.raises(ProofError):
            proofs.verify_inclusion(tree[index], index, size, [*path, top], top)
        if path:
            with pytest.raises(ProofError):
                proofs.verify_inclusion(tree[index], index, size, path[:-1], top)
            for position in range(len(path)):
                bent = list(path)
                bent[position] = other
                with pytest.raises(ProofError):
                    proofs.verify_inclusion(tree[index], index, size, bent, top)


def test_inclusion_refuses_an_index_outside_the_tree():
    tree = leaves(4)
    with pytest.raises(ProofError):
        proofs.verify_inclusion(tree[0], 4, 4, [], proofs.root(tree))
    with pytest.raises(ProofError):
        proofs.inclusion_path(4, tree)


@pytest.mark.parametrize("size", [2, 3, 5, 8, 13, 17])
def test_consistency_refuses_a_different_history(size):
    tree = leaves(size)
    forked = list(tree)
    forked[0] = proofs.leaf_hash(b"forked")
    for first in range(1, size):
        path = proofs.consistency_path(first, tree)
        first_root, second_root = proofs.root(tree[:first]), proofs.root(tree)
        with pytest.raises(ProofError):
            proofs.verify_consistency(first, size, proofs.root(forked[:first]), second_root, path)
        with pytest.raises(ProofError):
            proofs.verify_consistency(first, size, first_root, proofs.root(forked), path)
        with pytest.raises(ProofError):
            proofs.verify_consistency(first, size, first_root, second_root, [*path, second_root])
        if len(path) > 1:
            with pytest.raises(ProofError):
                proofs.verify_consistency(first, size, first_root, second_root, path[:-1])
        for position in range(len(path)):
            bent = list(path)
            bent[position] = proofs.leaf_hash(b"bent")
            with pytest.raises(ProofError):
                proofs.verify_consistency(first, size, first_root, second_root, bent)


def test_consistency_edge_cases():
    tree = leaves(4)
    top = proofs.root(tree)
    proofs.verify_consistency(4, 4, top, top, [])
    with pytest.raises(ProofError):
        proofs.verify_consistency(4, 4, top, proofs.root(tree[:3]), [])
    with pytest.raises(ProofError):
        proofs.verify_consistency(4, 4, top, top, [top])
    with pytest.raises(ProofError):
        proofs.verify_consistency(3, 2, top, top, [top])
    with pytest.raises(ProofError):
        proofs.verify_consistency(2, 4, proofs.root(tree[:2]), top, [])
    with pytest.raises(ProofError):
        proofs.verify_consistency(0, 4, top, top, [])
    with pytest.raises(ProofError):
        proofs.verify_consistency(0, 4, proofs.EMPTY_ROOT, top, [top])
    proofs.verify_consistency(0, 4, proofs.EMPTY_ROOT, top, [])


@settings(max_examples=200, deadline=None)
@given(st.integers(1, 300).flatmap(lambda size: st.tuples(st.just(size), st.integers(0, size - 1), st.integers(1, size))))
def test_random_sizes_verify_and_reject_a_moved_leaf(case):
    size, index, first = case
    tree = leaves(size)
    top = proofs.root(tree)
    proofs.verify_inclusion(tree[index], index, size, proofs.inclusion_path(index, tree), top)
    proofs.verify_consistency(first, size, proofs.root(tree[:first]), top, proofs.consistency_path(first, tree))
    if size > 1:
        other = (index + 1) % size
        with pytest.raises(ProofError):
            proofs.verify_inclusion(tree[other], index, size, proofs.inclusion_path(index, tree), top)


def test_records_round_trip_and_refuse_malformed_fields():
    tree = leaves(5)
    record = proofs.inclusion_record("log", 2, 5, tree[2], proofs.inclusion_path(2, tree))
    assert proofs.parse_inclusion(record)[1:4] == (2, 5, tree[2])
    for change in ({"index": -1}, {"index": True}, {"size": 2**53}, {"leafHash": "AB" * 32},
                   {"path": ["00"]}, {"format": "other"}, {"extra": 1}, {"path": [tree[0].hex()] * 65}):
        with pytest.raises(ProofError):
            proofs.parse_inclusion({**record, **change})
    consistency = proofs.consistency_record("log", 2, 5, proofs.consistency_path(2, tree))
    assert proofs.parse_consistency(consistency)[1:3] == (2, 5)
    for change in ({"first": "2"}, {"format": "other"}, {"path": "x"}):
        with pytest.raises(ProofError):
            proofs.parse_consistency({**consistency, **change})


def test_each_bound_is_checked_even_when_the_hashes_would_agree():
    a, b = proofs.leaf_hash(b"a"), proofs.leaf_hash(b"b")
    # Index one past a one-leaf tree, with the leaf itself as the root.
    with pytest.raises(ProofError, match="outside the tree"):
        proofs.verify_inclusion(a, 1, 1, [], a)
    # A two-leaf tree claimed with no path, and a root equal to the leaf.
    with pytest.raises(ProofError, match="shorter than the tree"):
        proofs.verify_inclusion(a, 0, 2, [], a)
    # A three-leaf tree claimed with a one-node path whose fold is the claimed root.
    with pytest.raises(ProofError, match="shorter than the tree"):
        proofs.verify_consistency(1, 3, a, proofs.node_hash(a, b), [b])
    with pytest.raises(ProofError, match="out of order"):
        proofs.verify_consistency(3, 2, a, a, [a])
