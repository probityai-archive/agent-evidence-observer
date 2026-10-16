# Security policy

## Reporting a vulnerability

Report a vulnerability privately through GitHub: open the repository's
**Security** tab and choose **Report a vulnerability**
(https://github.com/probityai/agent-evidence-observer/security/advisories/new).
Please do not open a public issue for it.

The most useful report is a packet and a command: a signed packet that
`agent-evidence-observer verify` accepts and should reject, or a workload whose
file change the broker misses while it reports `noDetectedGap`. Say which
version you ran.

You get an acknowledgement within three working days. A confirmed issue gets a
fix, a patch release and a GitHub security advisory, and the advisory credits the
reporter unless they ask not to be named.

## Supported versions

| Version | Supported |
|---------|-----------|
| main | Yes |
| 0.0.1 | Fixes land in the next release only |

## What the package reads and runs on the host

An observer has to look at the host, so a static scanner will see code that
reads files, starts processes and opens local sockets. This is all of it:

- **Files.** The broker hashes the file tree of the run directory you pass it,
  before and after each brokered write, and writes its signed packet, history and
  public keys into that directory. The readers read the reports and packets you
  name. The boundary probe also hashes the `bwrap` binary and the interpreter it
  launches, so the record names exactly what ran.
- **Processes.** `run-workload` and the boundary probe start `bwrap`
  (bubblewrap) with `--unshare-all --clearenv --cap-drop ALL`, exposing only the
  broker's socket. The native readers start the framework command you name, with
  a timeout. Nothing is started at import or install time.
- **Network.** The HTTP ticket service listens on `127.0.0.1` only, and its client
  calls that local address. The sandboxed probes talk to the broker over a Unix
  socket. The package makes no other network calls.
- **Keys.** Signing keys are generated per run in the same process. They are
  never read from or sent to anywhere else.

The package has no install hooks: the wheel is pure Python built with
setuptools, and installing it runs no code.

## Dynamic code

The installed package contains no `exec`, `eval` or `compile` call.
`tests/test_no_dynamic_code.py` walks the syntax tree of every module and fails
the build if one appears.

Version 0.0.1 had one such call in `selection_profile.py`. It compiled one of two
fixed checker strings bundled in the same file, after refusing any other bytes,
so it could not run code from a packet. A package scanner reported it on
2026-10-15 as GCVE-110-PYPI-2026-021429. The call has since been replaced by a
lookup from those exact bytes to two ordinary functions, and a test checks that
each function's source matches its retained text.
