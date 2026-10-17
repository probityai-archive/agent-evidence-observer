"""The exact upstream bytes this package was written against.

Every value here was read from the upstream release on 2026-10-17. A consumer that runs a
different OpenShell build is refused by :mod:`.prover` and by the release
fetcher in ``interop/openshell-done-2026-10-17/``; nothing falls back to "latest".
"""

from __future__ import annotations

OPENSHELL_VERSION = "0.1.4"
OPENSHELL_RELEASE = f"https://github.com/NVIDIA/OpenShell/releases/download/v{OPENSHELL_VERSION}"
OPENSHELL_SOURCE_TARBALL_SHA256 = (
    "e7b80d636456eac7fea05494894f018b170d4c7b3bf89aa769e3f909554013e9")
"""SHA-256 of ``codeload.github.com/NVIDIA/OpenShell/tar.gz/refs/tags/v0.1.4``."""

RELEASE_ASSETS = {
    "openshell-x86_64-unknown-linux-musl.tar.gz":
        "2b65178e62e1ece1d90d482555e9f1f98ff0296e058409b33418104b6333df07",
    "openshell-gateway-x86_64-unknown-linux-gnu.tar.gz":
        "43f43554bcaabff2a8147444410d1ad0b7f51bdae7589c2d249982bc8b260b91",
    "openshell-prover-x86_64-unknown-linux-musl.tar.gz":
        "dcf52ed3b8c81a1ab15842653667090a28bc24eefa9ba76660a82fe0e78ecc43",
}
"""Release tarballs by name, with the SHA-256 the release's own checksum files list."""

SUPERVISOR_IMAGE = ("ghcr.io/nvidia/openshell/supervisor@sha256:"
                    "aa681d8264af6ee860e38349ed3c76609a51778eb6d0f02743df03787b80a290")
SANDBOX_RUNTIME_IMAGE = ("ghcr.io/nvidia/openshell/sandbox@sha256:"
                         "ca00c094aeaa60681b8196cda18ab3c5dd5f7d782d4c36798256427b67599070")
"""The ``:0.1.4`` tags of both runtime images, resolved to their index digests."""

NEMOCLAW_COMMIT = "1e82499a048d5a4d85b0876d8c07bd93c8a9a5de"
NEMOCLAW_NETWORK_SCHEMA_SHA256 = (
    "90ee9f927eacbadd993163edee45616a47d580c9411802fc3a24eafaa144f71c")
"""``schemas/network-policy.schema.json`` at :data:`NEMOCLAW_COMMIT`, vendored under
``vendor/nemoclaw/``."""

OCSF_VERSION = "1.8.0"
OCSF_CLASSES_SHA256 = "ceb606b97b0b948c43a0b5b01783d0a758d3a2bec3f18a2741b489f245799d33"
"""Digest of ``<sha256>  classes/<name>.json`` lines, sorted by name, over the OCSF 1.8.0
class schemas OpenShell vendors at ``crates/openshell-ocsf/schemas/ocsf/v1.8.0/`` (v0.1.4),
copied under ``vendor/ocsf-1.8.0/``."""

BINARY_SHA256 = {
    "openshell": "b4a5b7681a674d4cd0b54fa68726e104731309ff15eeb65b9d1661f7f746f9d0",
    "openshell-gateway": "b2c1b9db0e4c066458ffe4cdfa0d9e77e32d6250fa9a8b221968b250e854b892",
    "openshell-prover": "49b3c5d4c9f192c9d882e61068d08519a19176fa8e8d74cea6f3fcb1c2d8f006",
}
"""The executables inside :data:`RELEASE_ASSETS`, by SHA-256 of the extracted file."""
