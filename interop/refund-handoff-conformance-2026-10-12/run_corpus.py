"""Run every committed vector through the installed public CLI and retain bytes."""

from __future__ import annotations

import argparse
import base64
import contextlib
import csv
import hashlib
import io
import json
import os
import platform
import queue
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import zipfile
from importlib import metadata
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, NamedTuple
from urllib.parse import urlsplit
from urllib.request import url2pathname

CONTRACT_ID = (
    "https://probityai.github.io/agent-evidence-observer/contract/refund-handoff/0.1"
)
SCHEMA = "refund-handoff/0.1"
MAX_BUNDLE_RECORDS = 512
MAX_DOCUMENT_BYTES = 1_048_576
SAFE_INTEGER_LIMIT = 2**53
CASE_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,99}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
GIT_OBJECT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
WHEEL_FILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}\.whl\Z")
WINDOWS_RESERVED_NAME = re.compile(
    r"(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?\Z",
    re.IGNORECASE,
)
MAX_STREAM_BYTES = 1_048_576
MAX_SOURCE_ARCHIVE_BYTES = 67_108_864
MAX_SOURCE_MEMBERS = 8192
MAX_WHEEL_BYTES = 16_777_216
MAX_EXECUTABLE_BYTES = 134_217_728
PROCESS_TIMEOUT_SECONDS = 30
BUILD_TIMEOUT_SECONDS = 600
CONTAINMENT_TIMEOUT_SECONDS = 5
DIST_NAME = "agent-evidence-observer"
ENTRY_POINT_NAME = "agent-evidence-read-refund-handoff"
ENTRY_POINT_VALUE = "probity_observer.refund_handoff:main"
CONTRACT_ARTIFACTS = (
    "docs/contract/refund-handoff/0.1/contract.schema.json",
    "docs/contract/refund-handoff/0.1/reason-codes.json",
    "docs/contract/refund-handoff/0.1/reason-codes.schema.json",
    "docs/contract/refund-handoff/0.1/report.schema.json",
    "docs/contract/refund-handoff/0.1/run-provenance.schema.json",
)
class VerificationError(ValueError):
    """A retained input or result does not satisfy the closed run contract."""


def _validate_json(value: Any) -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) >= SAFE_INTEGER_LIMIT:
            raise VerificationError("integer exceeds the safe JSON range")
        return
    if isinstance(value, str):
        if not value.isascii():
            raise VerificationError("non-ASCII string is outside the profile")
        return
    if isinstance(value, list):
        _validate_json_sequence(value)
        return
    if isinstance(value, dict):
        _validate_json_object(value)
        return
    raise VerificationError("value is outside the JSON profile")


def _validate_json_sequence(value: list[Any]) -> None:
    for item in value:
        _validate_json(item)


def _validate_json_object(value: dict[Any, Any]) -> None:
    for key, item in value.items():
        if not isinstance(key, str):
            raise VerificationError("JSON object keys must be strings")
        _validate_json(key)
        _validate_json(item)


def canonical(value: Any) -> bytes:
    _validate_json(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("ascii")


def _decode_json(data: bytes) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise VerificationError("duplicate JSON member")
            result[key] = value
        return result

    try:
        value = json.loads(data, object_pairs_hook=unique)
    except VerificationError:
        raise
    except (ValueError, UnicodeError) as error:
        raise VerificationError("invalid JSON document") from error
    _validate_json(value)
    return value


def strict_loads(data: bytes) -> Any:
    value = _decode_json(data)
    if canonical(value) != data:
        raise VerificationError("JSON document is not canonical")
    return value


def _regular_lstat(path: Path, label: str) -> os.stat_result:
    try:
        before = os.lstat(path)
    except OSError as error:
        raise VerificationError(label + " is not a readable regular file") from error
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if (
        stat.S_ISLNK(before.st_mode)
        or getattr(before, "st_file_attributes", 0) & reparse_flag
        or not stat.S_ISREG(before.st_mode)
    ):
        raise VerificationError(label + " is not a readable regular file")
    return before


def _open_bounded_regular(path: Path, *, limit: int, label: str) -> tuple[int, int]:
    before = _regular_lstat(path, label)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise VerificationError(label + " is not a readable regular file") from error
    try:
        current = os.fstat(descriptor)
        if not os.path.samestat(before, current):
            raise VerificationError(label + " changed while opening")
        if not stat.S_ISREG(current.st_mode):
            raise VerificationError(label + " is not a readable regular file")
        if current.st_size > limit:
            raise VerificationError(label + " exceeds its byte limit")
    except Exception:
        os.close(descriptor)
        raise
    return descriptor, current.st_size


def read_document_bytes(path: Path) -> bytes:
    """Read one bounded regular file through one no-follow file descriptor."""
    descriptor, size = _open_bounded_regular(
        path,
        limit=MAX_DOCUMENT_BYTES,
        label="input",
    )
    try:
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                raise VerificationError("input changed while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if os.read(descriptor, 1):
            raise VerificationError("input changed while reading")
    finally:
        os.close(descriptor)
    return raw


class _RetainedInputs(NamedTuple):
    provenance_bytes: bytes
    provenance: dict[str, Any]
    requirements_bytes: bytes
    contract_bytes: dict[str, bytes]
    trust_bytes: dict[str, bytes]
    manifest_bytes: bytes
    manifest: dict[str, Any]
    vectors: list[dict[str, Any]]
    trust_root: Path
    vector_root: Path


def _json_document(data: bytes) -> Any:
    """Parse an ASCII JSON document without requiring canonical whitespace."""

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise VerificationError("duplicate JSON member")
            result[key] = value
        return result

    try:
        value = json.loads(data, object_pairs_hook=unique)
        canonical(value)
    except VerificationError:
        raise
    except (ValueError, UnicodeError) as error:
        raise VerificationError("invalid JSON document") from error
    return value


def _safe_error(error: BaseException | str) -> str:
    """Return bounded ASCII for a retained error field or diagnostic."""
    text = str(error).encode("ascii", "backslashreplace").decode("ascii")
    return text[:2048]


def _hash_regular_file(path: Path, *, limit: int, label: str) -> tuple[str, int]:
    """Hash one bounded regular file through one no-follow descriptor."""
    descriptor, size = _open_bounded_regular(path, limit=limit, label=label)
    try:
        if size == 0:
            raise VerificationError(label + " is empty")
        digest = hashlib.sha256()
        remaining = size
        while remaining:
            block = os.read(descriptor, min(65_536, remaining))
            if not block:
                raise VerificationError(label + " changed while reading")
            digest.update(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise VerificationError(label + " changed while reading")
    finally:
        os.close(descriptor)
    return digest.hexdigest(), size


def _closed(value: Any, fields: set[str], reason: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise VerificationError(reason + " has fields outside the closed profile")
    return value


def _check_expected(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("exit") not in {0, 2, 3}:
        raise VerificationError("vector has an invalid expected result")
    if value["exit"] == 2:
        expected = _closed(
            value,
            {"exit", "refusal", "stderr_sha256"},
            "refusal expectation",
        )
        if (
            not isinstance(expected["refusal"], str)
            or not expected["refusal"].isascii()
        ):
            raise VerificationError("vector has an invalid refusal")
        if (
            not isinstance(expected["stderr_sha256"], str)
            or SHA256.fullmatch(expected["stderr_sha256"]) is None
        ):
            raise VerificationError("vector has an invalid refusal digest")
        return expected
    expected = _closed(
        value,
        {"exit", "overall", "claims", "report_sha256"},
        "classification expectation",
    )
    states = {"ESTABLISHED", "CONTRADICTED", "NOT_ESTABLISHED"}
    if expected["overall"] not in states or not isinstance(expected["claims"], dict):
        raise VerificationError("classification expectation has an invalid state")
    if (
        not isinstance(expected["report_sha256"], str)
        or SHA256.fullmatch(expected["report_sha256"]) is None
    ):
        raise VerificationError(
            "classification expectation has an invalid report digest"
        )
    return expected


def _check_contract_artifacts(
    value: Any,
    contract_bytes: dict[str, bytes],
) -> None:
    if not isinstance(value, list) or len(value) != len(CONTRACT_ARTIFACTS):
        raise VerificationError("vector manifest has invalid contract artifacts")
    selected: set[str] = set()
    for raw in value:
        item = _closed(raw, {"file", "sha256"}, "contract artifact")
        filename = item["file"]
        if filename not in CONTRACT_ARTIFACTS or filename in selected:
            raise VerificationError(
                "vector manifest selects an unknown contract artifact"
            )
        if item["sha256"] != hashlib.sha256(contract_bytes[filename]).hexdigest():
            raise VerificationError("contract artifact digest differs: " + filename)
        selected.add(filename)
    if selected != set(CONTRACT_ARTIFACTS):
        raise VerificationError("vector manifest omits a contract artifact")


def _check_trust_snapshots(
    value: Any,
    trust_bytes: dict[str, bytes],
) -> set[str]:
    if not isinstance(value, list) or not value or len(value) > MAX_BUNDLE_RECORDS:
        raise VerificationError("vector manifest has invalid trust snapshots")
    selected: set[str] = set()
    for raw in value:
        item = _closed(raw, {"id", "file", "sha256"}, "trust snapshot entry")
        trust_id = item["id"]
        if not isinstance(trust_id, str) or CASE_ID.fullmatch(trust_id) is None:
            raise VerificationError("trust snapshot id is not a safe identifier")
        if item["file"] != "trust/" + trust_id + ".json":
            raise VerificationError("trust snapshot file does not match its identifier")
        if trust_id in selected or trust_id not in trust_bytes:
            raise VerificationError(
                "vector manifest repeats or invents a trust snapshot"
            )
        if item["sha256"] != hashlib.sha256(trust_bytes[trust_id]).hexdigest():
            raise VerificationError("trust snapshot digest differs: " + trust_id)
        selected.add(trust_id)
    if selected != set(trust_bytes):
        raise VerificationError("trust directory differs from the finite manifest")
    return selected


def _check_vectors(value: Any, trust_ids: set[str]) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value or len(value) > MAX_BUNDLE_RECORDS:
        raise VerificationError("vector manifest has an invalid vector count")
    result = []
    cases: set[str] = set()
    files: set[str] = set()
    used_trust_ids: set[str] = set()
    for raw in value:
        item = _closed(
            raw,
            {"case", "file", "sha256", "trust_snapshot", "expected"},
            "vector entry",
        )
        case = item["case"]
        if not isinstance(case, str) or CASE_ID.fullmatch(case) is None:
            raise VerificationError("vector case is not a safe identifier")
        if item["file"] != case + ".json":
            raise VerificationError("vector file does not match its case identifier")
        if item["trust_snapshot"] not in trust_ids:
            raise VerificationError("vector selects an unknown trust snapshot")
        used_trust_ids.add(item["trust_snapshot"])
        if (
            not isinstance(item["sha256"], str)
            or SHA256.fullmatch(item["sha256"]) is None
        ):
            raise VerificationError("vector digest is invalid")
        if case in cases or item["file"] in files:
            raise VerificationError("vector manifest repeats a member")
        cases.add(case)
        files.add(item["file"])
        _check_expected(item["expected"])
        result.append(item)
    if used_trust_ids != trust_ids:
        raise VerificationError("vector manifest contains an untested trust snapshot")
    return result


def _check_manifest(
    value: Any,
    trust_bytes: dict[str, bytes],
    contract_bytes: dict[str, bytes],
) -> list[dict[str, Any]]:
    manifest = _closed(
        value,
        {
            "profile",
            "schema",
            "generator",
            "contract_artifacts",
            "trust_snapshots",
            "vectors",
        },
        "vector manifest",
    )
    if manifest["profile"] != CONTRACT_ID or manifest["schema"] != SCHEMA:
        raise VerificationError("vector manifest selects a different profile")
    if manifest["generator"] != "generate_vectors.py":
        raise VerificationError("vector manifest selects an unknown generator")
    _check_contract_artifacts(manifest["contract_artifacts"], contract_bytes)
    trust_ids = _check_trust_snapshots(manifest["trust_snapshots"], trust_bytes)
    return _check_vectors(manifest["vectors"], trust_ids)


def _drain_stream(
    stream: BinaryIO,
    buffer: bytearray,
    overflow: threading.Event,
    errors: queue.SimpleQueue[str],
) -> None:
    """Drain one child stream while retaining no more than limit plus one byte."""
    try:
        while chunk := stream.read(65_536):
            capacity = MAX_STREAM_BYTES + 1 - len(buffer)
            if capacity > 0:
                buffer.extend(chunk[:capacity])
            if len(chunk) > capacity or len(buffer) > MAX_STREAM_BYTES:
                overflow.set()
    except OSError as error:
        errors.put(type(error).__name__ + ": " + _safe_error(error))


def _wait_bounded(
    process: subprocess.Popen[bytes],
    process_tree: _ProcessTree,
    overflow: threading.Event,
    errors: queue.SimpleQueue[str],
    timeout_seconds: int,
) -> tuple[int, str | None]:
    deadline = time.monotonic() + timeout_seconds
    problem = None
    while _leader_running(process) and problem is None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            problem = f"child process exceeded {timeout_seconds} seconds"
        elif overflow.wait(timeout=min(remaining, 0.05)):
            problem = "verifier output exceeds the retained byte limit"
        elif not errors.empty():
            problem = "verifier output could not be retained: " + errors.get()
    containment_problem = process_tree.stop()
    if problem is None and containment_problem is not None:
        problem = containment_problem
    try:
        return process.wait(timeout=5), problem
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
        return -1, problem or "verifier process did not stop with its process tree"


def _leader_running(process: subprocess.Popen[bytes]) -> bool:
    if sys.platform == "linux":
        # WNOWAIT pins the leader PID/PGID until descendants have been killed.
        return (
            os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            is None
        )
    return process.poll() is None


def _linux_group_live_members(group_id: int) -> list[int]:
    """Find runnable members without mistaking unreaped zombies for work."""
    live: list[int] = []
    try:
        entries = list(os.scandir("/proc"))
    except OSError as error:
        raise VerificationError("Linux process state is unavailable") from error
    for entry in entries:
        if not entry.name.isdecimal():
            continue
        try:
            raw = Path(entry.path, "stat").read_bytes()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise VerificationError("Linux process state is unreadable") from error
        # A process name may contain arbitrary bytes. Only the numeric fields
        # after the final closing parenthesis need interpretation here.
        end_of_name = raw.rfind(b")")
        if end_of_name < 0:
            raise VerificationError("Linux process state is malformed")
        tail = raw[end_of_name + 2 :].split()
        if len(tail) < 3:
            raise VerificationError("Linux process state is malformed")
        try:
            process_group = int(tail[2])
        except ValueError as error:
            raise VerificationError("Linux process group is malformed") from error
        if process_group == group_id and tail[0] not in (b"Z", b"X", b"x"):
            live.append(int(entry.name))
    return live


class _LinuxProcessGroup:
    """Kill inherited-filter descendants while the leader still pins its PGID."""

    def __init__(self, group_id: int) -> None:
        self.group_id = group_id
        self.stopped = False
        self.problem: str | None = None

    def stop(self) -> str | None:
        if self.stopped:
            return self.problem
        # Never retry after the leader may have been reaped: its numeric PGID
        # could then refer to an unrelated process group.
        self.stopped = True
        deadline = time.monotonic() + CONTAINMENT_TIMEOUT_SECONDS
        try:
            while True:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(self.group_id, signal.SIGKILL)
                if not _linux_group_live_members(self.group_id):
                    return None
                if time.monotonic() >= deadline:
                    raise OSError("Linux process group did not stop")
                time.sleep(0.01)
        except (OSError, VerificationError) as error:
            self.problem = "Linux process-group cleanup failed: " + _safe_error(error)
            return self.problem


class _ProcessTree:
    """Stop direct descendants; this is not a hostile same-UID sandbox."""

    def __init__(
        self,
        process: subprocess.Popen[bytes],
        windows_job: Any | None,
        linux_group: _LinuxProcessGroup | None,
    ) -> None:
        self.process = process
        self.windows_job = windows_job
        self.linux_group = linux_group
        self.stopped = False
        self.problem: str | None = None

    def stop(self) -> str | None:
        if self.stopped:
            return self.problem
        self.stopped = True
        problem = None
        try:
            if os.name == "nt":
                _close_windows_job(self.windows_job)
                self.windows_job = None
            elif self.linux_group is not None:
                problem = self.linux_group.stop()
            else:
                problem = "no supported process containment mechanism is active"
        except OSError as error:
            problem = "process containment cleanup failed: " + _safe_error(error)
        if problem is not None:
            if sys.platform == "linux":
                with contextlib.suppress(ProcessLookupError):
                    os.kill(self.process.pid, signal.SIGKILL)
            elif self.process.poll() is None:
                with contextlib.suppress(OSError):
                    self.process.kill()
        self.problem = problem
        return problem


def _create_windows_job() -> Any:
    """Create a Windows job that kills every member when its handle closes."""
    import ctypes
    from ctypes import wintypes

    class _IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class _BasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _ExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BasicLimitInformation),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    )
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL

    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    limits = _ExtendedLimitInformation()
    limits.BasicLimitInformation.LimitFlags = 0x00002000
    if not kernel32.SetInformationJobObject(
        job,
        9,
        ctypes.byref(limits),
        ctypes.sizeof(limits),
    ):
        error = ctypes.WinError(ctypes.get_last_error())
        kernel32.CloseHandle(job)
        raise error
    return job


def _assign_and_resume_windows_process(
    job: Any,
    process: subprocess.Popen[bytes],
) -> None:
    """Assign a suspended Windows process before it can create descendants."""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    process_handle = wintypes.HANDLE(int(process._handle))
    if not kernel32.AssignProcessToJobObject(job, process_handle):
        raise ctypes.WinError(ctypes.get_last_error())

    ntdll = ctypes.WinDLL("ntdll")
    ntdll.NtResumeProcess.argtypes = (wintypes.HANDLE,)
    ntdll.NtResumeProcess.restype = ctypes.c_long
    status = ntdll.NtResumeProcess(process_handle)
    if status < 0:
        code = status & 0xFFFFFFFF
        raise OSError(f"NtResumeProcess failed with NTSTATUS 0x{code:08x}")


def _close_windows_job(job: Any | None) -> None:
    if job is None:
        return
    import ctypes
    from ctypes import wintypes

    class _BasicAccounting(ctypes.Structure):
        _fields_ = [
            ("TotalUserTime", ctypes.c_longlong),
            ("TotalKernelTime", ctypes.c_longlong),
            ("ThisPeriodTotalUserTime", ctypes.c_longlong),
            ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
            ("TotalPageFaultCount", wintypes.DWORD),
            ("TotalProcesses", wintypes.DWORD),
            ("ActiveProcesses", wintypes.DWORD),
            ("TotalTerminatedProcesses", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.QueryInformationJobObject.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    )
    kernel32.QueryInformationJobObject.restype = wintypes.BOOL
    kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL

    def active_processes() -> int:
        accounting = _BasicAccounting()
        if not kernel32.QueryInformationJobObject(
            job, 1, ctypes.byref(accounting), ctypes.sizeof(accounting), None
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return int(accounting.ActiveProcesses)

    problem: OSError | None = None
    try:
        if active_processes():
            if not kernel32.TerminateJobObject(job, 1):
                raise ctypes.WinError(ctypes.get_last_error())
            deadline = time.monotonic() + CONTAINMENT_TIMEOUT_SECONDS
            while active_processes():
                if time.monotonic() >= deadline:
                    raise OSError("Windows job still has active processes")
                time.sleep(0.01)
    except OSError as error:
        problem = error
    if not kernel32.CloseHandle(job) and problem is None:
        problem = ctypes.WinError(ctypes.get_last_error())
    if problem is not None:
        raise problem


def _await_linux_containment_ack(descriptor: int) -> None:
    deadline = time.monotonic() + CONTAINMENT_TIMEOUT_SECONDS
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise VerificationError("Linux process containment timed out")
            readable, _, _ = select.select([descriptor], [], [], remaining)
            if not readable:
                continue
            if os.read(descriptor, 2) != b"1":
                raise VerificationError("Linux process containment failed")
            return
    finally:
        os.close(descriptor)


def _stop_failed_spawn(
    process: subprocess.Popen[bytes],
    process_tree: _ProcessTree,
) -> None:
    process_tree.stop()
    if process.poll() is None:
        process.kill()
    process.wait()


def _spawn_windows_contained(
    command: list[str],
    *,
    cwd: Path | None,
    env: dict[str, str] | None,
) -> tuple[subprocess.Popen[bytes], _ProcessTree]:
    windows_job = _create_windows_job()
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=0x00000004,
            env=env,
        )
        process_tree = _ProcessTree(process, windows_job, None)
        _assign_and_resume_windows_process(windows_job, process)
        return process, process_tree
    except Exception:
        if process is not None:
            _stop_failed_spawn(process, _ProcessTree(process, windows_job, None))
        else:
            with contextlib.suppress(OSError):
                _close_windows_job(windows_job)
        raise


def _spawn_linux_contained(
    command: list[str],
    *,
    cwd: Path | None,
    env: dict[str, str] | None,
) -> tuple[subprocess.Popen[bytes], _ProcessTree]:
    acknowledgement_read, acknowledgement_write = os.pipe()
    process: subprocess.Popen[bytes] | None = None
    try:
        wrapped_command = [
            sys.executable,
            "-I",
            "-S",
            "-B",
            str(Path(__file__).with_name("linux_containment.py").resolve(strict=True)),
            str(acknowledgement_write),
            *command,
        ]
        process = subprocess.Popen(
            wrapped_command,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            env=env,
            pass_fds=(acknowledgement_write,),
        )
        process_tree = _ProcessTree(process, None, _LinuxProcessGroup(process.pid))
        os.close(acknowledgement_write)
        acknowledgement_write = -1
        acknowledgement_descriptor = acknowledgement_read
        acknowledgement_read = -1
        _await_linux_containment_ack(acknowledgement_descriptor)
        return process, process_tree
    except Exception:
        if acknowledgement_read >= 0:
            os.close(acknowledgement_read)
        if acknowledgement_write >= 0:
            os.close(acknowledgement_write)
        if process is not None:
            _stop_failed_spawn(
                process, _ProcessTree(process, None, _LinuxProcessGroup(process.pid))
            )
        raise


def _spawn_contained(
    command: list[str],
    *,
    cwd: Path | None,
    env: dict[str, str] | None,
) -> tuple[subprocess.Popen[bytes], _ProcessTree]:
    """Start a child inside the platform's direct-descendant cleanup boundary."""
    if os.name == "nt":
        return _spawn_windows_contained(command, cwd=cwd, env=env)
    if sys.platform == "linux":
        return _spawn_linux_contained(command, cwd=cwd, env=env)
    raise VerificationError("process containment is unavailable on this platform")


def _run_bounded(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout_seconds: int = PROCESS_TIMEOUT_SECONDS,
) -> tuple[int, bytes, bytes, str | None]:
    """Run one verifier and return bounded output on POSIX and Windows."""
    process, process_tree = _spawn_contained(command, cwd=cwd, env=env)
    assert process.stdout is not None and process.stderr is not None
    stdout = bytearray()
    stderr = bytearray()
    overflow = threading.Event()
    errors: queue.SimpleQueue[str] = queue.SimpleQueue()
    threads = [
        threading.Thread(
            target=_drain_stream,
            args=(stream, buffer, overflow, errors),
            daemon=True,
        )
        for stream, buffer in ((process.stdout, stdout), (process.stderr, stderr))
    ]
    for thread in threads:
        thread.start()
    status = -1
    problem: str | None = None
    try:
        status, problem = _wait_bounded(
            process,
            process_tree,
            overflow,
            errors,
            timeout_seconds,
        )
    except (OSError, subprocess.SubprocessError, VerificationError) as error:
        # Preserve bytes already drained from a child even if process-state
        # inspection fails after launch.
        problem = type(error).__name__ + ": " + _safe_error(error)
    finally:
        containment_problem = process_tree.stop()
        if process.poll() is None:
            process.kill()
            process.wait()
        for thread in threads:
            thread.join(timeout=5)
    if containment_problem is not None:
        problem = (
            containment_problem
            if problem is None
            else problem + "; cleanup: " + containment_problem
        )
    if problem is None and not errors.empty():
        problem = "verifier output could not be retained: " + errors.get()
    if problem is None and overflow.is_set():
        problem = "verifier output exceeds the retained byte limit"
    if problem is None and any(thread.is_alive() for thread in threads):
        problem = "verifier output readers did not terminate"
    if problem is not None and status == 0:
        status = -1
    return status, bytes(stdout), bytes(stderr), problem


def _classification_errors(
    stdout: bytes,
    stderr: bytes,
    expected: dict[str, Any],
) -> tuple[list[str], dict[str, Any]]:
    errors = []
    actual: dict[str, Any] = {}
    if stderr:
        errors.append("classified report wrote stderr")
    if not stdout.endswith(b"\n") or stdout.endswith(b"\n\n"):
        errors.append("vector report lacks exactly one terminal newline")
        return errors, actual
    try:
        report = strict_loads(stdout[:-1])
    except (VerificationError, RecursionError) as error:
        errors.append("vector report is not canonical JSON: " + str(error))
        return errors, actual
    try:
        report_sha256 = hashlib.sha256(stdout).hexdigest()
        if report["overall"] != expected["overall"]:
            errors.append("vector classification differs")
        if report["claims"] != expected["claims"]:
            errors.append("vector claims or exact reasons differ")
        if report_sha256 != expected["report_sha256"]:
            errors.append("vector report digest differs")
        actual["overall"] = report["overall"]
        actual["report_sha256"] = report_sha256
    except (KeyError, TypeError) as error:
        errors.append("vector report structure differs: " + str(error))
    return errors, actual


def _case_errors(
    returncode: int,
    stdout: bytes,
    stderr: bytes,
    runner_error: str | None,
    expected: dict[str, Any],
) -> tuple[list[str], dict[str, Any]]:
    errors = []
    actual: dict[str, Any] = {}
    if runner_error is not None:
        errors.append(runner_error)
    if returncode != expected["exit"]:
        errors.append("vector exit differs")
    if expected["exit"] == 2:
        if stdout:
            errors.append("refused vector wrote stdout")
        expected_stderr = (
            "Refund handoff bundle refused: " + expected["refusal"] + "\n"
        ).encode("ascii")
        if stderr != expected_stderr:
            errors.append("vector refusal differs")
        if hashlib.sha256(stderr).hexdigest() != expected["stderr_sha256"]:
            errors.append("vector refusal digest differs")
        actual["refusal_matched"] = stderr == expected_stderr
    else:
        classification_errors, classification_actual = _classification_errors(
            stdout, stderr, expected
        )
        errors.extend(classification_errors)
        actual.update(classification_actual)
    return errors, actual


def _check_ascii_text(value: Any, reason: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or not value.isascii()
    ):
        raise VerificationError(reason + " is not bounded ASCII text")


def _check_provenance_source(value: Any) -> None:
    source = _closed(
        value,
        {
            "commit",
            "dirty",
            "bundle_file",
            "bundle_sha256",
            "archive_file",
            "archive_sha256",
        },
        "provenance source",
    )
    if GIT_OBJECT.fullmatch(source["commit"]) is None:
        raise VerificationError("provenance source commit is invalid")
    if (
        source["dirty"] is not False
        or source["bundle_file"] != "source.bundle"
        or source["archive_file"] != "source-at-commit.tar"
    ):
        raise VerificationError("provenance source is not a clean retained archive")
    for field in ("bundle_sha256", "archive_sha256"):
        if SHA256.fullmatch(source[field]) is None:
            raise VerificationError("provenance source digest is invalid")


def _check_provenance_wheel(value: Any) -> None:
    wheel = _closed(value, {"file", "sha256", "size"}, "provenance wheel")
    if (
        not isinstance(wheel["file"], str)
        or WHEEL_FILE.fullmatch(wheel["file"]) is None
    ):
        raise VerificationError("provenance wheel file is invalid")
    if SHA256.fullmatch(wheel["sha256"]) is None:
        raise VerificationError("provenance wheel digest is invalid")
    if type(wheel["size"]) is not int or not 0 < wheel["size"] <= 9_007_199_254_740_991:
        raise VerificationError("provenance wheel size is invalid")


def _check_provenance_environment(value: Any) -> None:
    environment = _closed(
        value,
        {
            "python",
            "python_implementation",
            "python_sha256",
            "platform",
            "uv",
            "uv_sha256",
        },
        "provenance environment",
    )
    for name in ("python", "python_implementation", "platform", "uv"):
        item = environment[name]
        _check_ascii_text(item, "provenance environment " + name)
    for name in ("python_sha256", "uv_sha256"):
        if SHA256.fullmatch(environment[name]) is None:
            raise VerificationError("provenance environment digest is invalid")


def _check_provenance_locks(value: Any) -> None:
    locks = _closed(
        value,
        {"requirements_file", "requirements_sha256"},
        "provenance locks",
    )
    if locks["requirements_file"] != "requirements.lock":
        raise VerificationError("provenance selects an unknown requirements file")
    if SHA256.fullmatch(locks["requirements_sha256"]) is None:
        raise VerificationError("provenance requirements digest is invalid")


def _check_provenance(value: Any) -> dict[str, Any]:
    provenance = _closed(
        value,
        {"schema", "profile", "source", "wheel", "environment", "locks"},
        "run provenance",
    )
    if provenance["schema"] != "probity-refund-handoff-run-provenance-v0.1":
        raise VerificationError("run provenance selects an unknown schema")
    if provenance["profile"] != CONTRACT_ID:
        raise VerificationError("run provenance selects a different profile")
    _check_provenance_source(provenance["source"])
    _check_provenance_wheel(provenance["wheel"])
    _check_provenance_environment(provenance["environment"])
    _check_provenance_locks(provenance["locks"])
    return provenance


def _expect_digest(
    *, label: str, expected: str, actual: str, expected_size: int | None = None,
    actual_size: int | None = None,
) -> None:
    if expected != actual:
        raise VerificationError(
            f"{label} digest differs: expected {expected}, actual {actual}"
        )
    if expected_size is not None and expected_size != actual_size:
        raise VerificationError(
            f"{label} size differs: expected {expected_size}, actual {actual_size}"
        )


def _git_checked(arguments: list[str], *, cwd: Path | None = None) -> bytes:
    returncode, stdout, stderr, problem = _run_bounded(["git", *arguments], cwd=cwd)
    if problem is not None:
        raise VerificationError("source bundle Git check failed: " + problem)
    if returncode != 0:
        diagnostic = stderr or stdout
        raise VerificationError(
            "source bundle Git check failed: "
            + _safe_error(diagnostic.decode("utf-8", "backslashreplace"))
        )
    return stdout


def _reconstruct_source_archive(
    source: dict[str, Any],
    bundle_path: Path,
    retained_source: Path,
) -> str:
    """Recreate the source tar from a complete verified Git bundle."""
    retained_source.mkdir()
    with tempfile.TemporaryDirectory(prefix="refund-handoff-source-") as temporary:
        repository = Path(temporary) / "source.git"
        _git_checked(["init", "--bare", str(repository)])
        _git_checked(["-C", str(repository), "bundle", "verify", str(bundle_path)])
        heads = _git_checked(["bundle", "list-heads", str(bundle_path)])
        expected_head = (source["commit"] + " HEAD\n").encode("ascii")
        if heads != expected_head:
            raise VerificationError("source bundle does not expose the selected commit")
        _git_checked(
            [
                "-C",
                str(repository),
                "fetch",
                "--no-tags",
                str(bundle_path),
                "HEAD",
            ]
        )
        _git_checked(
            ["-C", str(repository), "cat-file", "-e", source["commit"] + "^{commit}"]
        )
        _git_checked(["-C", str(repository), "fsck", "--full", "--strict"])
        reconstruction = retained_source / "source-at-commit.reconstructed.tar"
        _git_checked(
            [
                "-C",
                str(repository),
                "archive",
                "--format=tar",
                "--output=" + str(reconstruction),
                source["commit"],
            ]
        )
    reconstructed_digest, _ = _hash_regular_file(
        reconstruction,
        limit=MAX_SOURCE_ARCHIVE_BYTES,
        label="reconstructed source archive",
    )
    return reconstructed_digest


def _check_provenance_artifacts(
    provenance: dict[str, Any],
    provenance_path: Path,
    requirements_bytes: bytes,
    retained_source: Path,
) -> None:
    """Check the actual retained source, wheel, and lock bytes."""
    retained_root = provenance_path.parent
    source = provenance["source"]
    bundle_path = retained_root / source["bundle_file"]
    bundle_digest, _ = _hash_regular_file(
        bundle_path,
        limit=MAX_SOURCE_ARCHIVE_BYTES,
        label="provenance source bundle",
    )
    _expect_digest(
        label="provenance source bundle",
        expected=source["bundle_sha256"],
        actual=bundle_digest,
    )
    source_path = retained_root / source["archive_file"]
    source_digest, _ = _hash_regular_file(
        source_path,
        limit=MAX_SOURCE_ARCHIVE_BYTES,
        label="provenance source archive",
    )
    _expect_digest(
        label="provenance source archive",
        expected=source["archive_sha256"],
        actual=source_digest,
    )
    try:
        with tarfile.open(source_path, "r:") as source_archive:
            archive_commit = source_archive.pax_headers.get("comment")
    except (OSError, tarfile.TarError) as error:
        raise VerificationError(
            "provenance source archive is not a readable tar"
        ) from error
    if archive_commit != source["commit"]:
        raise VerificationError(
            "provenance source commit differs: expected "
            + source["commit"]
            + ", actual "
            + _safe_error(archive_commit)
        )
    reconstructed_digest = _reconstruct_source_archive(
        source,
        bundle_path,
        retained_source,
    )
    _expect_digest(
        label="reconstructed source archive",
        expected=source["archive_sha256"],
        actual=reconstructed_digest,
    )

    wheel = provenance["wheel"]
    wheel_digest, wheel_size = _hash_regular_file(
        retained_root / "dist" / wheel["file"],
        limit=MAX_WHEEL_BYTES,
        label="provenance wheel",
    )
    _expect_digest(
        label="provenance wheel",
        expected=wheel["sha256"],
        actual=wheel_digest,
        expected_size=wheel["size"],
        actual_size=wheel_size,
    )

    lock_digest = hashlib.sha256(requirements_bytes).hexdigest()
    _expect_digest(
        label="provenance requirements lock",
        expected=provenance["locks"]["requirements_sha256"],
        actual=lock_digest,
    )


def _source_member_key(member: tarfile.TarInfo) -> tuple[str, ...]:
    name = member.name
    path = PurePosixPath(name)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or "\\" in name
        or "\x00" in name
    ):
        raise VerificationError("source archive contains an unsafe member path")
    if any(
        ":" in part
        or part.rstrip(" .") != part
        or WINDOWS_RESERVED_NAME.fullmatch(part) is not None
        for part in path.parts
    ):
        raise VerificationError("source archive path is not portable to Windows")
    if not (member.isfile() or member.isdir()):
        raise VerificationError("source archive contains a non-regular member")
    if member.size < 0 or member.size > MAX_SOURCE_ARCHIVE_BYTES:
        raise VerificationError("source archive member exceeds the byte limit")
    return tuple(part.casefold() for part in path.parts)


def _extract_verified_source(source_archive: Path, destination: Path) -> int:
    """Extract a finite regular source tree and return its fixed source epoch."""
    destination.mkdir()
    try:
        with tarfile.open(source_archive, "r:") as archive:
            members = archive.getmembers()
            if not members or len(members) > MAX_SOURCE_MEMBERS:
                raise VerificationError("source archive has an invalid member count")
            keys: set[tuple[str, ...]] = set()
            epochs: set[int] = set()
            total_size = 0
            for member in members:
                key = _source_member_key(member)
                if key in keys:
                    raise VerificationError("source archive repeats a member path")
                keys.add(key)
                if type(member.mtime) is not int or member.mtime < 0:
                    raise VerificationError("source archive has an invalid member time")
                epochs.add(member.mtime)
                total_size += member.size
                if total_size > MAX_SOURCE_ARCHIVE_BYTES:
                    raise VerificationError(
                        "source archive expands past its byte limit"
                    )
            if len(epochs) != 1:
                raise VerificationError("source archive has no single source epoch")
            # Every path and member type is closed above. Preserve Git's exact
            # modes because wheel metadata records the LICENSE file mode.
            archive.extractall(destination, members=members, filter="fully_trusted")
    except VerificationError:
        raise
    except (OSError, OverflowError, tarfile.TarError) as error:
        raise VerificationError("source archive cannot be safely extracted") from error
    return epochs.pop()


def _same_regular_file_bytes(left: Path, right: Path, *, limit: int) -> bool:
    left_descriptor, left_size = _open_bounded_regular(
        left,
        limit=limit,
        label="original wheel",
    )
    try:
        right_descriptor, right_size = _open_bounded_regular(
            right,
            limit=limit,
            label="rebuilt wheel",
        )
    except Exception:
        os.close(left_descriptor)
        raise
    try:
        if left_size != right_size:
            return False
        remaining = left_size
        while remaining:
            block_size = min(65_536, remaining)
            if os.read(left_descriptor, block_size) != os.read(
                right_descriptor, block_size
            ):
                return False
            remaining -= block_size
        return not os.read(left_descriptor, 1) and not os.read(right_descriptor, 1)
    finally:
        os.close(left_descriptor)
        os.close(right_descriptor)


def _select_rebuilt_wheel(directory: Path) -> Path:
    entries = sorted(directory.iterdir(), key=lambda item: item.name)
    auxiliary = [item for item in entries if item.name == ".gitignore"]
    wheels = [item for item in entries if WHEEL_FILE.fullmatch(item.name)]
    if len(auxiliary) != 1 or len(wheels) != 1 or len(entries) != 2:
        raise VerificationError("source rebuild output has unknown artifacts")
    _regular_lstat(auxiliary[0], "rebuilt wheel output marker")
    if read_document_bytes(auxiliary[0]) != b"*":
        raise VerificationError("source rebuild output marker differs")
    wheel = wheels[0]
    _regular_lstat(wheel, "rebuilt wheel")
    return wheel


def _retain_process_result(
    retained: Path,
    *,
    status: int,
    stdout: bytes,
    stderr: bytes,
    problem: str | None,
) -> None:
    (retained / "rebuild.stdout").write_bytes(stdout)
    (retained / "rebuild.stderr").write_bytes(stderr)
    (retained / "rebuild.exit").write_text(str(status) + "\n", encoding="ascii")
    if problem is not None:
        (retained / "rebuild.runner-error").write_text(
            problem + "\n",
            encoding="ascii",
        )


def _check_runtime_executable(path: Path, *, label: str, expected: str) -> None:
    digest, _ = _hash_regular_file(
        path,
        limit=MAX_EXECUTABLE_BYTES,
        label=label,
    )
    _expect_digest(label=label, expected=expected, actual=digest)


def _check_reproducible_wheel(
    provenance: dict[str, Any],
    provenance_path: Path,
    retained_source: Path,
    profile_relative: str,
    requirements_bytes: bytes,
    python_path: Path,
    uv_path: Path,
) -> None:
    """Rebuild from verified source and require byte-identical wheel output."""
    environment = provenance["environment"]
    _check_runtime_executable(
        python_path,
        label="Python executable before rebuild",
        expected=environment["python_sha256"],
    )
    _check_runtime_executable(
        uv_path,
        label="uv executable before rebuild",
        expected=environment["uv_sha256"],
    )
    source = provenance["source"]
    source_archive = retained_source / "source-at-commit.reconstructed.tar"
    source_digest, _ = _hash_regular_file(
        source_archive,
        limit=MAX_SOURCE_ARCHIVE_BYTES,
        label="source archive for rebuild",
    )
    _expect_digest(
        label="source archive for rebuild",
        expected=source["archive_sha256"],
        actual=source_digest,
    )
    rebuilt_dist = retained_source / "rebuilt-dist"
    rebuilt_dist.mkdir()
    with tempfile.TemporaryDirectory(prefix="refund-handoff-rebuild-") as temporary:
        rebuild_root = Path(temporary) / "source"
        source_epoch = _extract_verified_source(source_archive, rebuild_root)
        extracted_lock = rebuild_root / profile_relative / "requirements.lock"
        if read_document_bytes(extracted_lock) != requirements_bytes:
            raise VerificationError(
                "rebuild lock differs from the retained source lock"
            )
        command = [
            str(uv_path),
            "build",
            "--wheel",
            "--python",
            str(python_path),
            "--build-constraints",
            str(extracted_lock),
            "--require-hashes",
            "--out-dir",
            str(rebuilt_dist.resolve()),
            ".",
        ]
        build_environment = os.environ.copy()
        build_environment["SOURCE_DATE_EPOCH"] = str(source_epoch)
        (retained_source / "rebuild-command.json").write_bytes(
            canonical(
                {
                    "argv": command,
                    "cwd": "verified-source-root",
                    "environment": {"SOURCE_DATE_EPOCH": str(source_epoch)},
                }
            )
        )
        try:
            status, stdout, stderr, problem = _run_bounded(
                command,
                cwd=rebuild_root,
                env=build_environment,
                timeout_seconds=BUILD_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.SubprocessError, VerificationError) as error:
            status = -1
            stdout = b""
            stderr = b""
            problem = type(error).__name__ + ": " + _safe_error(error)
        # Keep the native command result even if Windows cannot remove a
        # temporary source tree because a child kept a file handle open.
        _retain_process_result(
            retained_source,
            status=status,
            stdout=stdout,
            stderr=stderr,
            problem=problem,
        )
    final_source_digest, _ = _hash_regular_file(
        source_archive,
        limit=MAX_SOURCE_ARCHIVE_BYTES,
        label="source archive after rebuild",
    )
    _expect_digest(
        label="source archive after rebuild",
        expected=source["archive_sha256"],
        actual=final_source_digest,
    )
    _check_runtime_executable(
        python_path,
        label="Python executable after rebuild",
        expected=environment["python_sha256"],
    )
    _check_runtime_executable(
        uv_path,
        label="uv executable after rebuild",
        expected=environment["uv_sha256"],
    )
    if problem is not None:
        raise VerificationError("source wheel rebuild failed: " + problem)
    if status != 0:
        diagnostic = stderr or stdout
        raise VerificationError(
            "source wheel rebuild failed: "
            + _safe_error(diagnostic.decode("utf-8", "backslashreplace"))
        )

    rebuilt_wheel = _select_rebuilt_wheel(rebuilt_dist)
    wheel = provenance["wheel"]
    if rebuilt_wheel.name != wheel["file"]:
        raise VerificationError(
            "rebuilt wheel filename differs from the retained wheel"
        )
    rebuilt_digest, rebuilt_size = _hash_regular_file(
        rebuilt_wheel,
        limit=MAX_WHEEL_BYTES,
        label="rebuilt wheel",
    )
    _expect_digest(
        label="rebuilt wheel",
        expected=wheel["sha256"],
        actual=rebuilt_digest,
        expected_size=wheel["size"],
        actual_size=rebuilt_size,
    )
    retained_wheel = provenance_path.parent / "dist" / wheel["file"]
    if not _same_regular_file_bytes(
        retained_wheel,
        rebuilt_wheel,
        limit=MAX_WHEEL_BYTES,
    ):
        raise VerificationError("rebuilt wheel bytes differ from the retained wheel")


def _check_selected_source_bytes(
    source_archive: Path,
    selected: dict[str, bytes],
    *,
    retained_inventory: Path | None = None,
) -> None:
    """Match each executed or selected source file to the verified Git archive."""
    inventory: dict[str, str] = {}
    try:
        with tarfile.open(source_archive, "r:") as archive:
            for relative, actual in selected.items():
                try:
                    member = archive.getmember(relative)
                    source = archive.extractfile(member)
                except (KeyError, tarfile.TarError) as error:
                    raise VerificationError(
                        "selected source is absent from the Git archive: "
                        + relative
                    ) from error
                if (
                    not member.isfile()
                    or source is None
                    or member.size > MAX_DOCUMENT_BYTES
                ):
                    raise VerificationError(
                        "selected source is not a bounded regular member: "
                        + relative
                    )
                with source:
                    archived = source.read(MAX_DOCUMENT_BYTES + 1)
                if archived != actual:
                    raise VerificationError(
                        "selected source differs from the Git archive: " + relative
                    )
                inventory[relative] = hashlib.sha256(actual).hexdigest()
                if retained_inventory is not None:
                    retained_inventory.write_bytes(canonical(inventory))
    except (OSError, tarfile.TarError) as error:
        raise VerificationError("source archive is not a readable tar") from error


def _safe_wheel_member(name: str) -> None:
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or ".." in path.parts or "\\" in name:
        raise VerificationError("wheel contains an unsafe member path")


def _read_wheel_member(archive: zipfile.ZipFile, name: str) -> bytes:
    try:
        return archive.read(name)
    except (
        EOFError,
        KeyError,
        OSError,
        RuntimeError,
        ValueError,
        zipfile.BadZipFile,
    ) as error:
        raise VerificationError("wheel member cannot be read: " + name) from error


def _wheel_index(archive: zipfile.ZipFile) -> tuple[list[str], str]:
    infos = archive.infolist()
    names = [item.filename for item in infos if not item.is_dir()]
    if len(names) != len(set(names)) or len(names) > 4096:
        raise VerificationError("wheel has duplicate or excessive members")
    for name in names:
        _safe_wheel_member(name)
    if sum(item.file_size for item in infos) > MAX_SOURCE_ARCHIVE_BYTES:
        raise VerificationError("wheel uncompressed bytes exceed the limit")
    records = [name for name in names if name.endswith(".dist-info/RECORD")]
    if len(records) != 1:
        raise VerificationError("wheel does not contain one RECORD")
    return names, records[0]


def _wheel_record(
    archive: zipfile.ZipFile,
    record_name: str,
) -> dict[str, tuple[str, str]]:
    try:
        record_text = _read_wheel_member(archive, record_name).decode("utf-8")
        parsed_rows = list(csv.reader(io.StringIO(record_text), strict=True))
    except (UnicodeError, ValueError, csv.Error) as error:
        raise VerificationError("wheel RECORD is not readable UTF-8 CSV") from error
    rows: dict[str, tuple[str, str]] = {}
    for row in parsed_rows:
        if len(row) != 3 or row[0] in rows:
            raise VerificationError("wheel RECORD is malformed")
        _safe_wheel_member(row[0])
        rows[row[0]] = (row[1], row[2])
    return rows


def _check_wheel_member(
    *,
    name: str,
    raw: bytes,
    recorded: tuple[str, str],
    record_name: str,
) -> None:
    recorded_hash, recorded_size = recorded
    if name == record_name:
        if recorded_hash or recorded_size:
            raise VerificationError("wheel RECORD self-entry is not empty")
        return
    actual_hash = "sha256=" + base64.urlsafe_b64encode(
        hashlib.sha256(raw).digest()
    ).decode("ascii").rstrip("=")
    if recorded_hash != actual_hash or recorded_size != str(len(raw)):
        raise VerificationError("wheel member differs from wheel RECORD: " + name)


def _verified_wheel_members(wheel_path: Path) -> dict[str, bytes]:
    """Verify each wheel member against the wheel's own RECORD."""
    try:
        with zipfile.ZipFile(wheel_path) as archive:
            names, record_name = _wheel_index(archive)
            rows = _wheel_record(archive, record_name)
            if set(rows) != set(names):
                raise VerificationError("wheel members differ from wheel RECORD")
            members: dict[str, bytes] = {}
            for name in names:
                raw = _read_wheel_member(archive, name)
                _check_wheel_member(
                    name=name,
                    raw=raw,
                    recorded=rows[name],
                    record_name=record_name,
                )
                members[name] = raw
            return members
    except VerificationError:
        raise
    except (
        EOFError,
        OSError,
        OverflowError,
        NotImplementedError,
        RuntimeError,
        ValueError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
    ) as error:
        raise VerificationError(
            "retained wheel is not a readable wheel archive"
        ) from error


def _installed_distribution(environment_root: Path) -> metadata.Distribution:
    try:
        distribution = metadata.distribution(DIST_NAME)
    except metadata.PackageNotFoundError as error:
        raise VerificationError("installed verifier distribution is missing") from error
    distribution_root = Path(distribution.locate_file("")).resolve(strict=True)
    if not distribution_root.is_relative_to(environment_root):
        raise VerificationError(
            "installed distribution is outside the runner environment"
        )
    return distribution


def _check_entry_point(distribution: metadata.Distribution) -> None:
    entry_points = [
        item
        for item in distribution.entry_points
        if item.group == "console_scripts" and item.name == ENTRY_POINT_NAME
    ]
    if len(entry_points) != 1 or entry_points[0].value != ENTRY_POINT_VALUE:
        raise VerificationError("installed verifier entry point differs")


def _check_installed_members(
    distribution: metadata.Distribution,
    environment_root: Path,
    wheel_members: dict[str, bytes],
) -> None:
    for name, raw in wheel_members.items():
        if name.endswith(".dist-info/RECORD"):
            continue
        if ".data/" in name:
            raise VerificationError("wheel data relocation is outside this profile")
        installed_path = Path(distribution.locate_file(name)).resolve(strict=True)
        if not installed_path.is_relative_to(environment_root):
            raise VerificationError("installed wheel member is outside the environment")
        installed_digest, installed_size = _hash_regular_file(
            installed_path,
            limit=MAX_SOURCE_ARCHIVE_BYTES,
            label="installed wheel member " + name,
        )
        if (
            installed_size != len(raw)
            or installed_digest != hashlib.sha256(raw).hexdigest()
        ):
            raise VerificationError("installed wheel member differs: " + name)


def _retain_install_metadata(
    distribution: metadata.Distribution,
    retained_runtime: Path,
) -> bytes:
    retained_runtime.mkdir(exist_ok=True)
    values: dict[str, str] = {}
    for name in ("direct_url.json", "entry_points.txt", "RECORD"):
        value = distribution.read_text(name)
        if value is None:
            raise VerificationError("installed distribution has no " + name)
        values[name] = value
        (retained_runtime / name).write_bytes(value.encode("utf-8"))
    return values["direct_url.json"].encode("utf-8")


def _check_install_origin(
    direct_url_bytes: bytes,
    wheel: dict[str, Any],
    wheel_path: Path,
) -> None:
    direct_url = _json_document(direct_url_bytes)
    if (
        not isinstance(direct_url, dict)
        or set(direct_url) != {"url", "archive_info"}
        or direct_url["archive_info"] != {}
    ):
        raise VerificationError("installed distribution origin is invalid")
    origin = direct_url["url"]
    if not isinstance(origin, str):
        raise VerificationError("installed distribution origin URL is invalid")
    parsed_origin = urlsplit(origin)
    if (
        parsed_origin.scheme != "file"
        or parsed_origin.netloc not in {"", "localhost"}
        or parsed_origin.query
        or parsed_origin.fragment != "sha256=" + wheel["sha256"]
    ):
        raise VerificationError("installed distribution origin is not a pinned file")
    origin_path = Path(url2pathname(parsed_origin.path)).resolve(strict=True)
    if not os.path.samefile(origin_path, wheel_path):
        raise VerificationError(
            "installed distribution origin is not the retained wheel"
        )


def _check_runtime_binding(
    provenance: dict[str, Any],
    provenance_path: Path,
    retained_runtime: Path,
) -> None:
    """Bind all installed package bytes to the retained wheel."""
    environment_root = Path(os.path.abspath(sys.executable)).parent.parent.resolve(
        strict=True
    )
    distribution = _installed_distribution(environment_root)
    _check_entry_point(distribution)
    wheel = provenance["wheel"]
    wheel_path = provenance_path.parent / "dist" / wheel["file"]
    wheel_members = _verified_wheel_members(wheel_path)
    direct_url_bytes = _retain_install_metadata(distribution, retained_runtime)
    inventory: dict[str, dict[str, str | int]] = {}
    inventory_path = retained_runtime / "verified-wheel-members.json"
    for name, raw in sorted(wheel_members.items()):
        inventory[name] = {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
        }
        inventory_path.write_bytes(canonical(inventory))
    _check_installed_members(distribution, environment_root, wheel_members)
    _check_install_origin(direct_url_bytes, wheel, wheel_path)


def _runtime_executable_paths() -> tuple[Path, Path]:
    uv_path_raw = shutil.which("uv")
    if uv_path_raw is None:
        raise VerificationError("uv executable is unavailable")
    uv_path = Path(uv_path_raw).resolve(strict=True)
    python_path = Path(sys.executable).resolve(strict=True)
    return python_path, uv_path


def _runtime_environment(retained_runtime: Path) -> dict[str, str]:
    python_path, uv_path = _runtime_executable_paths()
    retained_runtime.mkdir(parents=True, exist_ok=True)
    try:
        uv_status, uv_stdout, uv_stderr, uv_problem = _run_bounded(
            [str(uv_path), "--version"]
        )
    except (OSError, subprocess.SubprocessError, VerificationError) as error:
        uv_status, uv_stdout, uv_stderr = -1, b"", b""
        uv_problem = type(error).__name__ + ": " + _safe_error(error)
    (retained_runtime / "uv-version.stdout").write_bytes(uv_stdout)
    (retained_runtime / "uv-version.stderr").write_bytes(uv_stderr)
    (retained_runtime / "uv-version.exit").write_text(
        str(uv_status) + "\n", encoding="ascii"
    )
    if uv_problem is not None:
        (retained_runtime / "uv-version.runner-error").write_text(
            _safe_error(uv_problem) + "\n", encoding="ascii"
        )
    if uv_problem is not None or uv_status != 0 or uv_stderr:
        raise VerificationError("uv version cannot be measured")
    try:
        uv_version = uv_stdout.decode("ascii").strip()
    except UnicodeError as error:
        raise VerificationError("uv version is not ASCII") from error
    python_digest, _ = _hash_regular_file(
        python_path,
        limit=MAX_EXECUTABLE_BYTES,
        label="Python executable",
    )
    uv_digest, _ = _hash_regular_file(
        uv_path,
        limit=MAX_EXECUTABLE_BYTES,
        label="uv executable",
    )
    return {
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "python_sha256": python_digest,
        "platform": platform.platform(),
        "uv": uv_version,
        "uv_sha256": uv_digest,
    }


def _check_runtime_environment(
    expected: dict[str, str],
    retained_runtime: Path,
) -> None:
    actual = _runtime_environment(retained_runtime)
    retained_runtime.mkdir(exist_ok=True)
    (retained_runtime / "environment.json").write_bytes(canonical(actual))
    for name, actual_value in actual.items():
        if expected[name] != actual_value:
            raise VerificationError(
                "runtime environment differs for "
                + name
                + ": expected "
                + expected[name]
                + ", actual "
                + actual_value
            )


def _write_failure_summary(
    output: Path,
    *,
    stage: str,
    error: Exception,
) -> None:
    summary = {
        "profile": CONTRACT_ID,
        "schema": SCHEMA,
        "status": "FAIL",
        "stage": stage,
        "error": type(error).__name__ + ": " + _safe_error(error),
        "vectors_run": 0,
        "results": [],
    }
    (output / "summary.json").write_bytes(canonical(summary))


def _capture_json_directory(
    source: Path,
    retained: Path,
    *,
    label: str,
    key_from_stem: bool,
) -> dict[str, bytes]:
    if source.is_symlink() or not source.is_dir():
        raise VerificationError(label + " directory is not a regular directory")
    entries = sorted(source.iterdir(), key=lambda item: item.name)
    if not entries or len(entries) > MAX_BUNDLE_RECORDS:
        raise VerificationError(label + " directory has an invalid member count")
    by_name: dict[str, bytes] = {}
    capture_errors: list[str] = []
    for path in entries:
        if path.is_symlink() or not path.is_file():
            capture_errors.append(label + " directory has a non-regular member")
            continue
        try:
            raw = read_document_bytes(path)
        except VerificationError as error:
            capture_errors.append(_safe_error(error))
            continue
        (retained / path.name).write_bytes(raw)
        by_name[path.name] = raw
    if capture_errors:
        raise VerificationError("; ".join(capture_errors))

    captured: dict[str, bytes] = {}
    for name, raw in by_name.items():
        path = Path(name)
        if path.suffix != ".json":
            raise VerificationError(label + " directory has a non-JSON member")
        key = path.stem if key_from_stem else path.name
        if CASE_ID.fullmatch(path.stem) is None or key in captured:
            raise VerificationError(label + " directory has an unsafe member")
        captured[key] = raw
    return captured


def _selected_source_bytes(
    *,
    profile_relative: str,
    runner_bytes: bytes,
    helper_bytes: bytes,
    requirements_bytes: bytes,
    manifest_bytes: bytes,
    contract_bytes: dict[str, bytes],
    trust_bytes: dict[str, bytes],
    vector_bytes: dict[str, bytes],
) -> dict[str, bytes]:
    selected: dict[str, bytes] = {}
    selected[profile_relative + "/run_corpus.py"] = runner_bytes
    selected[profile_relative + "/linux_containment.py"] = helper_bytes
    selected[profile_relative + "/requirements.lock"] = requirements_bytes
    selected[profile_relative + "/fixtures/vector-manifest.json"] = manifest_bytes
    for relative, raw in contract_bytes.items():
        selected[relative] = raw
    for trust_id, raw in trust_bytes.items():
        relative = profile_relative + "/fixtures/trust/" + trust_id + ".json"
        selected[relative] = raw
    for filename, raw in vector_bytes.items():
        relative = profile_relative + "/fixtures/vectors/" + filename
        selected[relative] = raw
    return selected


def _materialize_inputs(
    profile: Path,
    output: Path,
    provenance: Path,
) -> _RetainedInputs:
    """Retain every selected byte before validation or verifier execution."""
    retained = output / "inputs"
    retained_vectors = retained / "vectors"
    retained_trust = retained / "trust"
    retained_contract = retained / "contract"
    retained_vectors.mkdir(parents=True)
    retained_trust.mkdir()
    retained_contract.mkdir()

    # Capture all bounded inputs before interpreting JSON or checking a digest.
    provenance_bytes = read_document_bytes(provenance)
    (output / "provenance.json").write_bytes(provenance_bytes)

    requirements_bytes = read_document_bytes(profile / "requirements.lock")
    (retained / "requirements.lock").write_bytes(requirements_bytes)

    manifest_source = profile / "fixtures/vector-manifest.json"
    manifest_bytes = read_document_bytes(manifest_source)
    (retained / "vector-manifest.json").write_bytes(manifest_bytes)

    root = profile.resolve(strict=True).parents[1]
    runner_path = Path(__file__).resolve(strict=True)
    expected_runner_path = (profile / "run_corpus.py").resolve(strict=True)
    if not os.path.samefile(runner_path, expected_runner_path):
        raise VerificationError("runner does not come from the selected profile")
    runner_bytes = read_document_bytes(runner_path)
    (retained / "run_corpus.py").write_bytes(runner_bytes)
    helper_bytes = read_document_bytes(profile / "linux_containment.py")
    (retained / "linux_containment.py").write_bytes(helper_bytes)
    contract_bytes: dict[str, bytes] = {}
    for relative in CONTRACT_ARTIFACTS:
        raw = read_document_bytes(root / relative)
        (retained_contract / Path(relative).name).write_bytes(raw)
        contract_bytes[relative] = raw

    trust_bytes = _capture_json_directory(
        profile / "fixtures/trust",
        retained_trust,
        label="trust",
        key_from_stem=True,
    )
    vector_bytes = _capture_json_directory(
        profile / "fixtures/vectors",
        retained_vectors,
        label="vector",
        key_from_stem=False,
    )
    # Interpretation starts only after the complete bounded snapshot exists.
    provenance_document = _check_provenance(strict_loads(provenance_bytes))
    manifest = strict_loads(manifest_bytes)
    for raw in contract_bytes.values():
        _json_document(raw)
    for raw in trust_bytes.values():
        strict_loads(raw)
    vectors = _check_manifest(manifest, trust_bytes, contract_bytes)
    actual_files = set(vector_bytes)
    selected_files = {item["file"] for item in vectors}
    if actual_files != selected_files:
        raise VerificationError("vector directory differs from the finite manifest")
    for item in vectors:
        actual_digest = hashlib.sha256(vector_bytes[item["file"]]).hexdigest()
        if actual_digest != item["sha256"]:
            raise VerificationError(
                "vector digest differs: "
                + item["case"]
                + "; expected "
                + item["sha256"]
                + ", actual "
                + actual_digest
            )
    _check_provenance_artifacts(
        provenance_document,
        provenance,
        requirements_bytes,
        retained / "source",
    )
    profile_relative = profile.resolve(strict=True).relative_to(root).as_posix()
    selected_source_bytes = _selected_source_bytes(
        profile_relative=profile_relative,
        runner_bytes=runner_bytes,
        helper_bytes=helper_bytes,
        requirements_bytes=requirements_bytes,
        manifest_bytes=manifest_bytes,
        contract_bytes=contract_bytes,
        trust_bytes=trust_bytes,
        vector_bytes=vector_bytes,
    )
    _check_selected_source_bytes(
        provenance.parent / provenance_document["source"]["archive_file"],
        selected_source_bytes,
        retained_inventory=retained / "source" / "selected-source.json",
    )
    _check_runtime_binding(
        provenance_document,
        provenance,
        retained / "runtime",
    )
    _check_runtime_environment(
        provenance_document["environment"],
        retained / "runtime",
    )
    python_path, uv_path = _runtime_executable_paths()
    _check_reproducible_wheel(
        provenance_document,
        provenance,
        retained / "source",
        profile_relative,
        requirements_bytes,
        python_path,
        uv_path,
    )

    return _RetainedInputs(
        provenance_bytes=provenance_bytes,
        provenance=provenance_document,
        requirements_bytes=requirements_bytes,
        contract_bytes=contract_bytes,
        trust_bytes=trust_bytes,
        manifest_bytes=manifest_bytes,
        manifest=manifest,
        vectors=vectors,
        trust_root=retained_trust,
        vector_root=retained_vectors,
    )


def _run_case(
    inputs: _RetainedInputs,
    output: Path,
    pycache_root: Path,
    item: dict[str, Any],
) -> dict[str, Any]:
    """Run and retain one case without allowing a failure to stop later cases."""
    case = item["case"]
    source = inputs.vector_root / item["file"]
    try:
        returncode, stdout, stderr, runner_error = _run_bounded(
            [
                sys.executable,
                "-I",
                "-B",
                "-X",
                "pycache_prefix=" + str(pycache_root),
                "-m",
                "probity_observer.refund_handoff",
                "--bundle",
                str(source),
                "--trust-snapshot",
                str(inputs.trust_root / (item["trust_snapshot"] + ".json")),
            ]
        )
    except (OSError, subprocess.SubprocessError, VerificationError) as error:
        returncode = -1
        stdout = b""
        stderr = b""
        runner_error = type(error).__name__ + ": " + _safe_error(error)

    prefix = output / case
    prefix.with_suffix(".stdout").write_bytes(stdout)
    prefix.with_suffix(".stderr").write_bytes(stderr)
    prefix.with_suffix(".exit").write_text(str(returncode) + "\n", encoding="ascii")
    if runner_error is not None:
        prefix.with_suffix(".runner-error").write_text(
            runner_error + "\n", encoding="ascii"
        )
    errors, actual = _case_errors(
        returncode,
        stdout,
        stderr,
        runner_error,
        item["expected"],
    )
    actual.update(
        {
            "case": case,
            "exit": returncode,
            "status": "FAIL" if errors else "PASS",
            "errors": errors,
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        }
    )
    return actual


def _build_summary(
    inputs: _RetainedInputs,
    completed: list[dict[str, Any]],
) -> dict[str, Any]:
    failures = [result["case"] for result in completed if result["errors"]]
    incomplete = len(completed) != len(inputs.vectors)
    return {
        "profile": inputs.manifest["profile"],
        "schema": inputs.manifest["schema"],
        "status": "FAIL" if failures or incomplete else "PASS",
        "manifest_sha256": hashlib.sha256(inputs.manifest_bytes).hexdigest(),
        "contract_artifact_sha256s": {
            filename: hashlib.sha256(raw).hexdigest()
            for filename, raw in sorted(inputs.contract_bytes.items())
        },
        "trust_snapshot_sha256s": {
            trust_id: hashlib.sha256(raw).hexdigest()
            for trust_id, raw in sorted(inputs.trust_bytes.items())
        },
        "provenance_sha256": hashlib.sha256(inputs.provenance_bytes).hexdigest(),
        "vectors_selected": len(inputs.vectors),
        "vectors_run": len(completed),
        "vectors_passed": len(completed) - len(failures),
        "vectors_failed": len(failures),
        "failed_cases": failures,
        "results": completed,
    }


def run(
    profile: Path,
    output: Path,
    provenance: Path,
) -> dict[str, Any]:
    """Run the installed verifier against immutable retained input snapshots."""
    if output.exists():
        raise VerificationError("result path already exists")
    output.mkdir(parents=True)
    try:
        inputs = _materialize_inputs(profile, output, provenance)
    except Exception as error:
        _write_failure_summary(output, stage="preflight", error=error)
        raise

    pycache_root = output / "isolated-pycache"
    pycache_root.mkdir()
    completed: list[dict[str, Any]] = []
    summary = _build_summary(inputs, completed)
    (output / "summary.json").write_bytes(canonical(summary))
    for item in inputs.vectors:
        completed.append(_run_case(inputs, output, pycache_root, item))
        summary = _build_summary(inputs, completed)
        (output / "summary.json").write_bytes(canonical(summary))
    if summary["failed_cases"]:
        raise VerificationError(
            f"{summary['vectors_failed']} vector results differed; "
            "complete results are retained"
        )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--provenance", required=True, type=Path)
    args = parser.parse_args()
    try:
        run(args.profile, args.output, args.provenance)
    except (
        VerificationError,
        OSError,
        subprocess.SubprocessError,
        KeyError,
        TypeError,
        RecursionError,
    ) as error:
        print("Refund handoff corpus refused: " + _safe_error(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
