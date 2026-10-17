"""Fetch a pinned OpenShell release executable into a cache, verifying both digests.

The tarball must match :data:`.pins.RELEASE_ASSETS` and the extracted executable
:data:`.pins.BINARY_SHA256`; anything else is refused and nothing is left behind as usable.
"""

from __future__ import annotations

import hashlib
import io
import os
import tarfile
import urllib.request
from pathlib import Path

from . import pins

ASSET_OF = {"openshell": "openshell-x86_64-unknown-linux-musl.tar.gz",
            "openshell-gateway": "openshell-gateway-x86_64-unknown-linux-gnu.tar.gz",
            "openshell-prover": "openshell-prover-x86_64-unknown-linux-musl.tar.gz"}


class ReleaseError(RuntimeError):
    """A release download or its contents differ from the pins."""


def default_cache() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "probity-openshell" / pins.OPENSHELL_VERSION


def _download(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=120) as response:  # noqa: S310 (pinned https URL)
        return response.read()


def executable(name: str, cache: Path | None = None, fetch=_download) -> Path:
    """The verified executable ``name``, downloading and extracting it on first use."""
    if name not in ASSET_OF:
        raise ReleaseError(f"no pinned release asset for {name}")
    cache = cache or default_cache()
    target = cache / name
    want = pins.BINARY_SHA256[name]
    if target.is_file() and hashlib.sha256(target.read_bytes()).hexdigest() == want:
        return target
    asset = ASSET_OF[name]
    data = fetch(f"{pins.OPENSHELL_RELEASE}/{asset}")
    if hashlib.sha256(data).hexdigest() != pins.RELEASE_ASSETS[asset]:
        raise ReleaseError(f"{asset} differs from its pinned digest")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        member = archive.getmember(name)
        if not member.isfile():
            raise ReleaseError(f"{asset} holds no regular file {name}")
        body = archive.extractfile(member).read()  # type: ignore[union-attr]
    if hashlib.sha256(body).hexdigest() != want:
        raise ReleaseError(f"{name} in {asset} differs from its pinned digest")
    cache.mkdir(parents=True, exist_ok=True)
    partial = target.with_suffix(".partial")
    partial.write_bytes(body)
    partial.chmod(0o755)
    partial.replace(target)
    return target
