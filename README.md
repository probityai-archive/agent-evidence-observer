# Agent Evidence Observer (prototype)

[![PyPI](https://img.shields.io/pypi/v/agent-evidence-observer.svg)](https://pypi.org/project/agent-evidence-observer/)
[![Downloads (PePy)](https://static.pepy.tech/badge/agent-evidence-observer)](https://pepy.tech/projects/agent-evidence-observer)

Record brokered agent writes and check selected native framework reports offline.

Use it in agent harnesses and evaluation pipelines that need replayable action records or a consumer gate for retained reports.

Install the root package: `pip install agent-evidence-observer==0.0.2`.

## Quick start

Run the demo from the released package. You need Python 3.12 or later and [`uv`](https://docs.astral.sh/uv/); there is nothing to clone.

```sh
uvx agent-evidence-observer==0.0.2 demo ./sample-run
uvx agent-evidence-observer==0.0.2 verify ./sample-run
```

The two commands print:

```text
{"noDetectedGap": "true", "retryReplayed": "true", "status": "verified", "witnessScope": "PEER"}
{"noDetectedGap": "true", "status": "verified", "witnessScope": "PEER"}
```

`sample-run/` now holds the signed packet, the history, the public keys and the file tree. The demo
writes a file, retries it, and the retry returns the first effect. `noDetectedGap` means the broker's
file-tree snapshots found no change it did not make. It does not mean every agent effect was seen.
To run from a pinned source checkout instead, see [Run the source quick start](https://github.com/probityai/agent-evidence-observer/blob/main/docs/INSTALLATION.md#run-the-source-quick-start).

## Status

The root distribution is version 0.0.2. Every record says `witnessScope: PEER`: the witness key runs on the same
host under the same operator, so the records show what this broker saw, not what an independent
observer saw. Linux runs can launch a fixed probe, or a Python script given to `run-workload`, under
bubblewrap with only the broker's socket exposed. Running a real agent that way, and a separately operated
witness, are the next steps.

## Documentation

Start with [worked examples](https://github.com/probityai/agent-evidence-observer/blob/main/docs/README.md) to follow a practical question,
then open its technical reference for commands and exact evidence.

| page | read it for |
| --- | --- |
| [Start a project](https://github.com/new?template_name=evidence-starter&template_owner=probityai) | a template that records a write with this package and checks it with probity-verify, pinned and in CI |
| [Component tour](https://github.com/probityai/agent-evidence-observer/blob/main/docs/OVERVIEW.md) | every part of the prototype in one paragraph each, with links: ticket service, replay, evaluation history, A2A, AAE, protected dispatch |
| <a name="run-the-demo"></a>[Running the demo](https://github.com/probityai/agent-evidence-observer/blob/main/docs/RUNNING.md) | the full install with tests, and what each output field means |
| <a name="claim-and-trust-boundary"></a><a name="tests-and-remaining-gaps"></a><a name="linux-boundary-gate"></a><a name="consumer-admission"></a><a name="roadmap"></a>[Design, trust boundary and roadmap](https://github.com/probityai/agent-evidence-observer/blob/main/docs/DESIGN.md) | what each mechanism checks and does not establish, the Linux boundary gate, recovery, consumer admission, and the roadmap |
| [Isolated producer](https://github.com/probityai/agent-evidence-observer/blob/main/docs/ISOLATED-PRODUCER.md) | the acceptance criteria for running an unmodified agent behind the broker |
| [Brokered workload](https://github.com/probityai/agent-evidence-observer/blob/main/docs/WORKLOAD.md) | run a Python script behind the write broker with `run-workload`, then check it offline with `verify-workload` |
| [Witness ledger](https://github.com/probityai/agent-evidence-observer/blob/main/docs/WITNESS-LEDGER.md) | signed begin and terminal receipts, and how a reader checks them |
| [Installation and profile selection](https://github.com/probityai/agent-evidence-observer/blob/main/docs/INSTALLATION.md) | choose the root wheel, a separate profile wheel or a selected source reader; runtime requirements and installed examples |
| [Release the root package](https://github.com/probityai/agent-evidence-observer/blob/main/docs/RELEASING.md) | qualify a wheel and source distribution, then publish with a bound source tag |
| [Atomic native reader](https://github.com/probityai/agent-evidence-observer/blob/main/docs/ATOMIC-NATIVE-READER.md) | install an offline reader for selected native delegation runs and their refusal controls |
| [Witnessed run selection](https://github.com/probityai/agent-evidence-observer/blob/main/docs/WITNESSED-RUN-SELECTION.md) | check a selected run against consumer-retained opening and closing checkpoints |
| [Approved refund retries](https://github.com/probityai/agent-evidence-observer/blob/main/docs/APS-REFUND-RETRIES.md) | run the APS approval and local SQLite example, then check retries and refusals with a separately installed reader |
| [Refund handoff conformance](https://github.com/probityai/agent-evidence-observer/blob/main/docs/REFUND-HANDOFF-CONFORMANCE.md) | verify admission, recovery, handoff, effect and reconciliation bindings against 80 public vectors |

## License

Apache License 2.0; see [LICENSE](https://github.com/probityai/agent-evidence-observer/blob/main/LICENSE).
