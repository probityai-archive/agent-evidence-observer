"""Merkle tree hashing, inclusion proofs and consistency proofs (RFC 9162 section 2.1).

The witness log is a Merkle tree over leaf hashes. A leaf hash is
``SHA-256(0x00 || leaf bytes)`` and an interior node is
``SHA-256(0x01 || left || right)``, so a leaf can never be presented as a node.
The empty tree's root is ``SHA-256("")``.

Generation (``root``, ``inclusion_path``, ``consistency_path``) is used by the
server. Verification (``verify_inclusion``, ``verify_consistency``) is all a
reader needs: it takes a checkpoint's size and root, never the log itself.

The proof records that travel on the wire are plain JSON objects:

``probity-witness-inclusion/v1``
    ``{"format", "origin", "index", "size", "leafHash", "path"}``
``probity-witness-consistency/v1``
    ``{"format", "origin", "first", "second", "path"}``

Hashes are lowercase hexadecimal.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from typing import Any

INCLUSION_FORMAT = "probity-witness-inclusion/v1"
CONSISTENCY_FORMAT = "probity-witness-consistency/v1"
EMPTY_ROOT = hashlib.sha256(b"").digest()
MAX_PATH = 64
HEX_HASH = re.compile(r"[0-9a-f]{64}\Z")


class ProofError(ValueError):
    """A proof does not verify, or its record is malformed."""


def leaf_hash(data: bytes) -> bytes:
    """Hash leaf bytes with the RFC 9162 leaf prefix."""
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """Hash two child hashes with the RFC 9162 interior-node prefix."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(size: int) -> int:
    """Return the largest power of two strictly below ``size`` (``size`` >= 2)."""
    return 1 << ((size - 1).bit_length() - 1)


def root(leaves: Sequence[bytes]) -> bytes:
    """Return the Merkle tree hash of a sequence of leaf hashes."""
    if not leaves:
        return EMPTY_ROOT
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return node_hash(root(leaves[:k]), root(leaves[k:]))


def inclusion_path(index: int, leaves: Sequence[bytes]) -> list[bytes]:
    """Return the audit path for ``leaves[index]`` in the tree of ``leaves``."""
    if not 0 <= index < len(leaves):
        raise ProofError("leaf index is outside the tree")
    if len(leaves) == 1:
        return []
    k = _split(len(leaves))
    if index < k:
        return inclusion_path(index, leaves[:k]) + [root(leaves[k:])]
    return inclusion_path(index - k, leaves[k:]) + [root(leaves[:k])]


def _subproof(first: int, leaves: Sequence[bytes], complete: bool) -> list[bytes]:
    if first == len(leaves):
        return [] if complete else [root(leaves)]
    k = _split(len(leaves))
    if first <= k:
        return _subproof(first, leaves[:k], complete) + [root(leaves[k:])]
    return _subproof(first - k, leaves[k:], False) + [root(leaves[:k])]


def consistency_path(first: int, leaves: Sequence[bytes]) -> list[bytes]:
    """Return the proof that the first ``first`` leaves are a prefix of ``leaves``."""
    if not 0 <= first <= len(leaves):
        raise ProofError("consistency sizes are outside the tree")
    if first in (0, len(leaves)):
        return []
    return _subproof(first, leaves, True)


def verify_inclusion(leaf: bytes, index: int, size: int, path: Sequence[bytes], expected_root: bytes) -> None:
    """Check that ``leaf`` is entry ``index`` of the tree of ``size`` with ``expected_root``.

    Raises
    ------
    ProofError
        If the index is outside the tree, the path is the wrong length, or the
        recomputed root differs.
    """
    if not 0 <= index < size:
        raise ProofError("leaf index is outside the tree")
    fn, sn, result = index, size - 1, leaf
    for sibling in path:
        if sn == 0:
            raise ProofError("inclusion path is longer than the tree")
        if fn & 1 or fn == sn:
            result = node_hash(sibling, result)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            result = node_hash(result, sibling)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ProofError("inclusion path is shorter than the tree")
    if result != expected_root:
        raise ProofError("inclusion path does not reach the checkpoint root")


def verify_consistency(
    first: int, second: int, first_root: bytes, second_root: bytes, path: Sequence[bytes]
) -> None:
    """Check that the tree of ``first`` leaves is a prefix of the tree of ``second``.

    Raises
    ------
    ProofError
        If the sizes are out of order, the path is malformed, or either
        recomputed root differs. Two signed checkpoints that fail this check
        are evidence that their signer equivocated.
    """
    if not 0 <= first <= second:
        raise ProofError("consistency sizes are out of order")
    if first == second:
        if path:
            raise ProofError("consistency path for equal sizes must be empty")
        if first_root != second_root:
            raise ProofError("two roots for one tree size")
        return
    if first == 0:
        if path:
            raise ProofError("consistency path from the empty tree must be empty")
        if first_root != EMPTY_ROOT:
            raise ProofError("the empty tree has a different root")
        return
    if not path:
        raise ProofError("consistency path is empty")
    nodes = list(path)
    if first & (first - 1) == 0:
        nodes.insert(0, first_root)
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = nodes[0]
    for node in nodes[1:]:
        if sn == 0:
            raise ProofError("consistency path is longer than the tree")
        if fn & 1 or fn == sn:
            fr = node_hash(node, fr)
            sr = node_hash(node, sr)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, node)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ProofError("consistency path is shorter than the tree")
    if fr != first_root:
        raise ProofError("consistency path does not reach the first root")
    if sr != second_root:
        raise ProofError("consistency path does not reach the second root")


def decode_hash(value: Any, label: str) -> bytes:
    """Decode one lowercase-hex SHA-256 value from a proof or checkpoint record."""
    if not isinstance(value, str) or HEX_HASH.fullmatch(value) is None:
        raise ProofError(f"{label} is not a lowercase hex SHA-256 value")
    return bytes.fromhex(value)


def _count(value: Any, label: str) -> int:
    if type(value) is not int or value < 0 or value >= 2**53:
        raise ProofError(f"{label} is not a safe non-negative integer")
    return value


def _path(value: Any) -> list[bytes]:
    if not isinstance(value, list) or len(value) > MAX_PATH:
        raise ProofError("proof path is not a bounded list")
    return [decode_hash(item, "proof path entry") for item in value]


def inclusion_record(origin: str, index: int, size: int, leaf: bytes, path: Sequence[bytes]) -> dict[str, Any]:
    """Build the wire record of an inclusion proof."""
    return {
        "format": INCLUSION_FORMAT,
        "origin": origin,
        "index": index,
        "size": size,
        "leafHash": leaf.hex(),
        "path": [node.hex() for node in path],
    }


def consistency_record(origin: str, first: int, second: int, path: Sequence[bytes]) -> dict[str, Any]:
    """Build the wire record of a consistency proof."""
    return {
        "format": CONSISTENCY_FORMAT,
        "origin": origin,
        "first": first,
        "second": second,
        "path": [node.hex() for node in path],
    }


def parse_inclusion(record: Any) -> tuple[str, int, int, bytes, list[bytes]]:
    """Validate an inclusion record and return ``(origin, index, size, leaf, path)``."""
    if not isinstance(record, dict) or set(record) != {"format", "origin", "index", "size", "leafHash", "path"}:
        raise ProofError("inclusion proof has invalid fields")
    if record["format"] != INCLUSION_FORMAT or not isinstance(record["origin"], str):
        raise ProofError("inclusion proof has an unsupported format")
    return (
        record["origin"],
        _count(record["index"], "inclusion index"),
        _count(record["size"], "inclusion size"),
        decode_hash(record["leafHash"], "inclusion leaf hash"),
        _path(record["path"]),
    )


def parse_consistency(record: Any) -> tuple[str, int, int, list[bytes]]:
    """Validate a consistency record and return ``(origin, first, second, path)``."""
    if not isinstance(record, dict) or set(record) != {"format", "origin", "first", "second", "path"}:
        raise ProofError("consistency proof has invalid fields")
    if record["format"] != CONSISTENCY_FORMAT or not isinstance(record["origin"], str):
        raise ProofError("consistency proof has an unsupported format")
    return (
        record["origin"],
        _count(record["first"], "consistency first size"),
        _count(record["second"], "consistency second size"),
        _path(record["path"]),
    )
