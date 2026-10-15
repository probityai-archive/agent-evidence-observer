# Release the root Python package

The root distribution is `agent-evidence-observer` 0.0.1. It installs the
`probity_observer` modules and five declared console commands. Separate
`interop/` distributions keep their own names, dependencies, source pins and
qualification. Publishing the root wheel does not publish those profiles.
See [installation and profile selection](INSTALLATION.md).

## Check the artifacts

The `Python distribution` workflow runs on pushes, pull requests and manual
runs. It uses hash-pinned release tools, then builds a wheel and source
distribution. Existing distribution checks compare package metadata, commands,
dependencies, license, module bytes, every RECORD hash and declared profile
routes. Their refusal controls remain part of the check.

The workflow installs the wheel in a separate environment and runs
`scripts/check-installed.py` from an outside directory. The root broker demo
must create a replayable write, accept its retry and verify the retained packet.
A repeated demo must refuse a nonempty destination without changing its files.
An altered retained effect must fail verification. The workflow rebuilds and
installs the source distribution, then repeats the same installed consumer.

Both successful results retain `witnessScope: PEER`. The two local keys share
one operator. `noDetectedGap` concerns the broker's checked file-tree snapshots;
it does not establish complete agent coverage or an independently operated
witness. The release checks do not run every separate framework profile.

The retained workflow artifact contains both distributions, their hashes, the
source commit, install reports and consumer results. A successful build is
neither registry publication nor outside adoption.

## Publish with a bound source tag

Only a non-prerelease GitHub release can reach the publish job. Its `v0.0.1`
tag must match the root metadata and point to a commit on main. The publish job
downloads the checked files from the build job. Only that job has
`id-token: write`. It has no account-token or password fallback.

Configure an [existing or pending PyPI trusted publisher](https://docs.pypi.org/trusted-publishers/)
with owner `probityai`, repository `agent-evidence-observer`, workflow
`python-distribution.yml`, and environment `pypi`. The pinned PyPA action uploads
the wheel, source distribution and [PyPI attestations](https://docs.pypi.org/attestations/producing-attestations/).
The workflow's existence does not prove that the account binding is configured.

After publication, read the registry metadata, download both artifacts, compare
their hashes and run the installed consumer again. Confirm provenance through
PyPI's integrity API. Update current install instructions to the actual registry
version. Historical source-selected profile recipes keep their original pins.

Regenerate the release-tool lock with:

```sh
uv pip compile --python-version 3.12 --generate-hashes --no-header --no-annotate \
  requirements-release.in --output-file requirements-release.lock
```
