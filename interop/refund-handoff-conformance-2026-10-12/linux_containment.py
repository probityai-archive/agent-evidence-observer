"""Install a non-removable process-group boundary before executing a child.

This is descendant cleanup for a local conformance runner, not a sandbox for
hostile same-UID code. The parent must create a new session before starting us.
"""

from __future__ import annotations

import ctypes
import errno
import os
import platform
import sys


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_ushort),
        ("instructions", ctypes.POINTER(_SockFilter)),
    ]


def _instruction(code: int, value: int, jt: int = 0, jf: int = 0) -> _SockFilter:
    return _SockFilter(code, jt, jf, value)


def _install_filter() -> None:
    machines = {
        "x86_64": (0xC000003E, 109, 112, 435, 272, 308, 56),
        "aarch64": (0xC00000B7, 154, 157, 435, 97, 268, 220),
    }
    machine = platform.machine().lower()
    if machine not in machines:
        raise OSError(errno.ENOTSUP, "Linux containment architecture is unsupported")
    arch, setpgid, setsid, clone3, unshare, setns, clone = machines[machine]

    # BPF loads seccomp_data.arch and seccomp_data.nr, then allows ordinary
    # syscalls. A process cannot remove this inherited filter after exec.
    deny = 0x00050000 | errno.EPERM
    instructions = [
        _instruction(0x20, 4),
        _instruction(0x15, arch, jt=1),
        _instruction(0x06, 0x80000000),
        _instruction(0x20, 0),
    ]
    if machine == "x86_64":
        # x32 uses the same audit architecture with a high syscall-number bit.
        instructions.extend(
            (_instruction(0x45, 0x40000000, jf=1), _instruction(0x06, deny))
        )
    for number, outcome in (
        (setpgid, deny),
        (setsid, deny),
        # ENOSYS lets libraries fall back to clone while forbidding clone3's
        # alternative namespace and process-group creation paths.
        (clone3, 0x00050000 | errno.ENOSYS),
        (unshare, deny),
        (setns, deny),
    ):
        instructions.extend(
            (_instruction(0x15, number, jf=1), _instruction(0x06, outcome))
        )
    instructions.extend(
        (
            _instruction(0x15, clone, jf=4),
            _instruction(0x20, 16),
            _instruction(0x54, 0x7E020080),
            _instruction(0x15, 0, jt=1),
            _instruction(0x06, deny),
            _instruction(0x06, 0x7FFF0000),
        )
    )
    filters = (_SockFilter * len(instructions))(*instructions)
    program = _SockFprog(len(instructions), filters)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = (
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    )
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(38, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
    if libc.prctl(22, 2, ctypes.addressof(program), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_SECCOMP failed")


def main() -> None:
    if len(sys.argv) < 3:
        raise SystemExit("usage: linux_containment.py ACK_FD COMMAND [ARG ...]")
    acknowledgement = int(sys.argv[1])
    command = sys.argv[2:]
    if os.getpid() != os.getpgrp() or os.getpid() != os.getsid(0):
        raise OSError("Linux containment child is not its session leader")
    _install_filter()
    if os.write(acknowledgement, b"1") != 1:
        raise OSError("short containment acknowledgement")
    os.close(acknowledgement)
    os.execvpe(command[0], command, os.environ)


if __name__ == "__main__":
    main()
