"""OpenShell's policy prover gates the launch policy: within_boundary passes, nothing else."""

from __future__ import annotations

import hashlib
import io
import json
import sys
import tarfile
from pathlib import Path

import pytest

from probity_observer.openshell import pins, prover, release
from probity_observer.openshell.prover import ContainmentRefused, Prover

FIXTURES = Path(__file__).with_name("fixtures")
NARROW = b"""version: 1
network_policies:
  pypi:
    name: pypi
    endpoints:
      - host: pypi.org
        port: 443
    binaries:
      - path: /usr/local/bin/python3.12
"""
WIDE = NARROW + b"""      - path: /usr/bin/curl
"""


@pytest.fixture(scope="module")
def binary() -> Prover:
    return Prover(release.executable("openshell-prover"))


@pytest.fixture
def files(tmp_path):
    (tmp_path / "narrow.yaml").write_bytes(NARROW)
    (tmp_path / "wide.yaml").write_bytes(WIDE)
    return tmp_path


def test_a_policy_within_the_boundary_is_accepted(files, binary) -> None:
    record = prover.check(files / "narrow.yaml", files / "wide.yaml", binary)
    assert record["accepted"] is True and record["result"] == "within_boundary"
    assert record["prover"] == {"path": str(binary.path), "version": "0.1.4",
                                "sha256": pins.BINARY_SHA256["openshell-prover"]}
    assert record["candidate_sha256"] == hashlib.sha256(NARROW).hexdigest()
    assert "network_l4" in record["coverage"]["domains"]


def test_a_policy_that_widens_the_boundary_is_refused_with_its_counterexample(files, binary):
    with pytest.raises(ContainmentRefused, match="exceeds_boundary") as caught:
        prover.check(files / "wide.yaml", files / "narrow.yaml", binary)
    assert caught.value.record["accepted"] is False
    assert caught.value.record["counterexample"]["port"] == 443


def test_a_policy_outside_the_model_is_refused_not_admitted(files, binary) -> None:
    nemoclaw = FIXTURES / "openclaw-sandbox.yaml"
    with pytest.raises(ContainmentRefused, match="unsupported") as caught:
        prover.check(nemoclaw, nemoclaw, binary)
    assert caught.value.record["reason_code"] == "unsupported_policy_shape"


def fake(tmp_path: Path, body: str) -> Prover:
    path = tmp_path / "fake-prover"
    path.write_text(f"#!{sys.executable}\n{body}\n")
    path.chmod(0o755)
    return Prover(path)


@pytest.mark.parametrize("body,needle", [
    ("print('not json')", "printed no JSON"),
    ("import json; print(json.dumps({'schema_version': 2, 'result': 'within_boundary'}))",
     "contract is not the pinned"),
    ("import json; print(json.dumps({'schema_version': 1, 'prover_version': '9.9',"
     " 'result': 'within_boundary'}))", "version other than"),
    ("import json, sys; print(json.dumps({'schema_version': 1, 'prover_version': '0.1.4',"
     " 'result': 'within_boundary'})); sys.exit(3)", "not within the boundary"),
    ("import json; print(json.dumps({'schema_version': 1, 'prover_version': '0.1.4',"
     " 'result': 'inconclusive', 'reason_code': 'timeout'}))", "inconclusive (timeout)"),
])
def test_anything_but_a_pinned_within_is_refused(files, body, needle) -> None:
    with pytest.raises(ContainmentRefused, match=needle.replace("(", r"\(").replace(")", r"\)")):
        prover.check(files / "narrow.yaml", files / "wide.yaml", fake(files, body),
                     expected_sha256=None)


def test_an_unpinned_or_missing_prover_is_refused(files) -> None:
    with pytest.raises(ContainmentRefused, match="not the pinned build"):
        prover.check(files / "narrow.yaml", files / "wide.yaml", fake(files, "pass"))
    with pytest.raises(ContainmentRefused, match="not found"):
        prover.check(files / "narrow.yaml", files / "wide.yaml", Prover(files / "absent"))
    stuck = fake(files, "import time; time.sleep(60)")
    with pytest.raises(ContainmentRefused, match="did not run"):
        prover.check(files / "narrow.yaml", files / "wide.yaml", stuck, timeout_seconds=-29,
                     expected_sha256=None)


def tarball(name: str, body: bytes) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as archive:
        info = tarfile.TarInfo(name)
        info.size = len(body)
        archive.addfile(info, io.BytesIO(body))
    return out.getvalue()


def test_the_release_fetcher_refuses_anything_off_its_pins(tmp_path, monkeypatch) -> None:
    with pytest.raises(release.ReleaseError, match="no pinned release asset"):
        release.executable("openshell-sandbox", tmp_path)
    with pytest.raises(release.ReleaseError, match="differs from its pinned digest"):
        release.executable("openshell", tmp_path, fetch=lambda url: b"tampered")
    asset = release.ASSET_OF["openshell"]
    data = tarball("openshell", b"#!/bin/sh\n")
    monkeypatch.setitem(release.pins.RELEASE_ASSETS, asset, hashlib.sha256(data).hexdigest())
    with pytest.raises(release.ReleaseError, match="openshell in .* differs"):
        release.executable("openshell", tmp_path, fetch=lambda url: data)
    monkeypatch.setitem(release.pins.BINARY_SHA256, "openshell",
                        hashlib.sha256(b"#!/bin/sh\n").hexdigest())
    path = release.executable("openshell", tmp_path, fetch=lambda url: data)
    assert path.read_bytes() == b"#!/bin/sh\n" and path.stat().st_mode & 0o111
    assert release.executable("openshell", tmp_path, fetch=None) == path
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    assert release.default_cache() == tmp_path / "xdg" / "probity-openshell" / "0.1.4"


def test_a_policy_the_prover_cannot_parse_is_refused(files, binary) -> None:
    (files / "invalid.yaml").write_bytes(NARROW.replace(b"pypi.org", b"*.example.org"))
    with pytest.raises(ContainmentRefused, match="error") as caught:
        prover.check(files / "narrow.yaml", files / "invalid.yaml", binary)
    assert caught.value.record["result"] == "error"
    assert caught.value.record["reason_code"] == "invalid_input"
