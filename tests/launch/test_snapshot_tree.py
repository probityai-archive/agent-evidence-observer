"""S3 tree digest and the sealed start tarball."""

import hashlib
import os
import subprocess

import pytest

from probity_observer.launch import snapshot
from probity_observer.sensors import treedigest


def make(root):
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text("def app():\n    return 1\n")
    (root / "tests").mkdir()
    (root / "tests" / "test_app.py").write_text("x\n")


def test_tree_digest_is_what_sha256sum_prints(tmp_path):
    make(tmp_path)
    tree = treedigest.scan(tmp_path)
    listing = subprocess.run(["sh", "-c", "find . -type f | sed 's|^\\./||' | LC_ALL=C sort "
                              "| xargs sha256sum"], cwd=tmp_path, capture_output=True,
                             text=True, check=True).stdout
    assert tree.sha256 == hashlib.sha256(listing.encode()).hexdigest()
    assert set(tree.files) == {"src/app.py", "tests/test_app.py"}


def test_symlinks_are_listed_not_followed(tmp_path):
    make(tmp_path)
    os.symlink("/etc/passwd", tmp_path / "escape")
    tree = treedigest.scan(tmp_path)
    assert "escape" not in tree.files
    assert tree.symlinks == {"escape": "/etc/passwd"}


def test_seal_is_deterministic_and_reset_restores(tmp_path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    make(workspace)
    first = snapshot.seal(workspace, tmp_path / "a.tar")
    os.utime(workspace / "src" / "app.py", (1, 1))
    assert snapshot.seal(workspace, tmp_path / "b.tar") == first
    before = treedigest.scan(workspace).sha256
    (workspace / "tests" / "test_app.py").write_text("tampered\n")
    (workspace / "extra.txt").write_text("new\n")
    snapshot.reset(workspace, tmp_path / "a.tar", first)
    assert treedigest.scan(workspace).sha256 == before


def test_reset_refuses_a_changed_tarball(tmp_path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    make(workspace)
    digest = snapshot.seal(workspace, tmp_path / "a.tar")
    with open(tmp_path / "a.tar", "ab") as handle:
        handle.write(b"\0")
    with pytest.raises(snapshot.SnapshotError):
        snapshot.reset(workspace, tmp_path / "a.tar", digest)
    assert (workspace / "src" / "app.py").exists()
