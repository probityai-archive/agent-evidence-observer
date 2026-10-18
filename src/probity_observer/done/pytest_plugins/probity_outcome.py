"""The compile-time pytest plugin ``probity_outcome``: print each test's outcome as it runs.

Every report of a test's call (and of a setup or teardown that did not pass) prints one line,
``PROBITY-OUTCOME <outcome> <seconds> <nodeid>``. The contract compiler loads it with ``-p``
when it harvests guard tests from a repository's own suite and builds the kill matrix; it is
never part of a sealed acceptance argv.

This file uses the standard library and pytest only: it runs in the task's image.
"""

from __future__ import annotations

import os

MARKER = "PROBITY-OUTCOME"


def pytest_runtest_logreport(report) -> None:
    if report.when == "call" or report.outcome != "passed":
        line = f"\n{MARKER} {report.outcome} {report.duration:.6f} {report.nodeid}\n"
        os.write(1, line.encode("utf-8", "replace"))
