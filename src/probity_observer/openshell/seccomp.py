"""OpenShell's sandbox seccomp block list, compiled to the classic BPF program bubblewrap loads.

The rules are those of ``crates/openshell-sandbox/src/sandbox/linux/seccomp.rs`` at OpenShell
v0.1.4 (``build_filter_rules`` and ``build_compatibility_filter``): default allow, with

1. a socket domain allowlist (``AF_UNIX``, ``AF_NETLINK``, and ``AF_INET``/``AF_INET6`` only
   when networking is allowed; ``socketpair`` only ``AF_UNIX``), and ``AF_NETLINK`` only for
   ``NETLINK_ROUTE``;
2. unconditional blocks of the escape primitives: ``memfd_create``, ``ptrace``, ``bpf``,
   ``process_vm_readv``/``writev``, ``pidfd_getfd``, ``pidfd_send_signal``,
   ``io_uring_setup``, the mount family, ``setns``, ``umount2``, ``pivot_root``,
   ``userfaultfd`` and ``perf_event_open``;
3. conditional blocks: ``execveat`` with ``AT_EMPTY_PATH``, ``unshare`` and ``clone`` with
   ``CLONE_NEWUSER``, and ``seccomp(SECCOMP_SET_MODE_FILTER)``;

each refused with ``EPERM``; and ``clone3`` and ``pidfd_open`` refused with ``ENOSYS``, so
runtimes fall back to calls whose flags the filter can read. A call from another
architecture's ABI kills the process. Arguments compare on their low 32 bits, as
OpenShell's ``SeccompCmpArgLen::Dword`` does.

:func:`program` returns the program bytes (``struct sock_filter`` array) that
``bwrap --seccomp FD`` reads; :func:`describe` returns the rule set the launch record carries.
"""

from __future__ import annotations

import hashlib
import platform
import struct
from typing import Any

from . import pins

SOURCE = (f"NVIDIA/OpenShell@v{pins.OPENSHELL_VERSION}:"
          "crates/openshell-sandbox/src/sandbox/linux/seccomp.rs")

AF_UNIX, AF_INET, AF_INET6, AF_NETLINK = 1, 2, 10, 16
AT_EMPTY_PATH = 0x1000
CLONE_NEWUSER = 0x10000000
SECCOMP_SET_MODE_FILTER = 1
EPERM, ENOSYS = 1, 38

UNCONDITIONAL = ("memfd_create", "ptrace", "bpf", "process_vm_readv", "process_vm_writev",
                 "pidfd_getfd", "pidfd_send_signal", "io_uring_setup", "mount", "fsopen",
                 "fsconfig", "fsmount", "fspick", "move_mount", "open_tree", "setns", "umount2",
                 "pivot_root", "userfaultfd", "perf_event_open")
UNAVAILABLE = ("clone3", "pidfd_open")

SYSCALLS = {
    "x86_64": {
        "memfd_create": 319, "ptrace": 101, "bpf": 321, "process_vm_readv": 310,
        "process_vm_writev": 311, "pidfd_getfd": 438, "pidfd_send_signal": 424,
        "io_uring_setup": 425, "mount": 165, "fsopen": 430, "fsconfig": 431, "fsmount": 432,
        "fspick": 433, "move_mount": 429, "open_tree": 428, "setns": 308, "umount2": 166,
        "pivot_root": 155, "userfaultfd": 323, "perf_event_open": 298, "execveat": 322,
        "unshare": 272, "clone": 56, "seccomp": 317, "socket": 41, "socketpair": 53,
        "clone3": 435, "pidfd_open": 434,
    },
    "aarch64": {
        "memfd_create": 279, "ptrace": 117, "bpf": 280, "process_vm_readv": 270,
        "process_vm_writev": 271, "pidfd_getfd": 438, "pidfd_send_signal": 424,
        "io_uring_setup": 425, "mount": 40, "fsopen": 430, "fsconfig": 431, "fsmount": 432,
        "fspick": 433, "move_mount": 429, "open_tree": 428, "setns": 268, "umount2": 39,
        "pivot_root": 41, "userfaultfd": 282, "perf_event_open": 241, "execveat": 281,
        "unshare": 97, "clone": 220, "seccomp": 277, "socket": 198, "socketpair": 199,
        "clone3": 435, "pidfd_open": 434,
    },
}
AUDIT_ARCH = {"x86_64": 0xC000003E, "aarch64": 0xC00000B7}
X32_BIT = 0x40000000

LD_W_ABS, JEQ, JSET, JGE, RET = 0x20, 0x15, 0x45, 0x35, 0x06
RET_ALLOW, RET_KILL_PROCESS = 0x7FFF0000, 0x80000000
OFF_NR, OFF_ARCH = 0, 4


def _arg(index: int) -> int:
    """Offset of the low 32 bits of syscall argument ``index`` in ``struct seccomp_data``."""
    return 16 + 8 * index


def _errno(value: int) -> int:
    return 0x00050000 | value


class _Assembler:
    """A linear cBPF program with symbolic jump targets."""

    def __init__(self) -> None:
        self.code: list[tuple[int, Any, Any, int]] = []
        self.labels: dict[str, int] = {}

    def emit(self, op: int, k: int, true: Any = 0, false: Any = 0) -> None:
        self.code.append((op, true, false, k))

    def label(self, name: str) -> None:
        self.labels[name] = len(self.code)

    def assemble(self) -> bytes:
        out = b""
        for index, (op, true, false, k) in enumerate(self.code):
            offsets = []
            for target in (true, false):
                if isinstance(target, str):
                    distance = self.labels[target] - index - 1
                    if not 0 <= distance <= 255:
                        raise ValueError("seccomp jump out of range")
                    offsets.append(distance)
                else:
                    offsets.append(target)
            out += struct.pack("<HBBI", op, offsets[0], offsets[1], k)
        return out


def machine() -> str:
    name = platform.machine()
    return {"amd64": "x86_64", "arm64": "aarch64"}.get(name, name)


def program(allow_inet: bool = False, arch: str | None = None) -> bytes:
    """The filter as ``struct sock_filter`` bytes, for ``bwrap --seccomp``."""
    arch = arch or machine()
    if arch not in SYSCALLS:
        raise ValueError(f"no seccomp syscall table for {arch}")
    nr = SYSCALLS[arch]
    code = _Assembler()
    code.emit(LD_W_ABS, OFF_ARCH)
    code.emit(JEQ, AUDIT_ARCH[arch], 0, "kill")
    code.emit(LD_W_ABS, OFF_NR)
    if arch == "x86_64":
        code.emit(JGE, X32_BIT, "kill", 0)
    for name in UNCONDITIONAL:
        code.emit(JEQ, nr[name], "eperm", 0)
    for name in UNAVAILABLE:
        code.emit(JEQ, nr[name], "enosys", 0)
    for name, target in (("socket", "socket"), ("socketpair", "socketpair"),
                         ("execveat", "execveat"), ("unshare", "newuser"),
                         ("clone", "newuser"), ("seccomp", "seccomp")):
        code.emit(JEQ, nr[name], target, 0)
    code.emit(RET, RET_ALLOW)

    code.label("socket")
    code.emit(LD_W_ABS, _arg(0))
    code.emit(JEQ, AF_NETLINK, "netlink", 0)
    allowed = [AF_UNIX] + ([AF_INET, AF_INET6] if allow_inet else [])
    for domain in allowed:
        code.emit(JEQ, domain, "allow", 0)
    code.emit(RET, _errno(EPERM))
    code.label("netlink")
    code.emit(LD_W_ABS, _arg(2))
    code.emit(JEQ, 0, "allow", "eperm")

    code.label("socketpair")
    code.emit(LD_W_ABS, _arg(0))
    code.emit(JEQ, AF_UNIX, "allow", "eperm")

    code.label("execveat")
    code.emit(LD_W_ABS, _arg(4))
    code.emit(JSET, AT_EMPTY_PATH, "eperm", "allow")

    code.label("newuser")
    code.emit(LD_W_ABS, _arg(0))
    code.emit(JSET, CLONE_NEWUSER, "eperm", "allow")

    code.label("seccomp")
    code.emit(LD_W_ABS, _arg(0))
    code.emit(JEQ, SECCOMP_SET_MODE_FILTER, "eperm", "allow")

    code.label("allow")
    code.emit(RET, RET_ALLOW)
    code.label("eperm")
    code.emit(RET, _errno(EPERM))
    code.label("enosys")
    code.emit(RET, _errno(ENOSYS))
    code.label("kill")
    code.emit(RET, RET_KILL_PROCESS)
    return code.assemble()


def describe(allow_inet: bool = False, arch: str | None = None) -> dict[str, Any]:
    """The rule set and program digest a launch record carries."""
    arch = arch or machine()
    data = program(allow_inet, arch)
    return {
        "source": SOURCE, "arch": arch, "default": "allow",
        "eperm": list(UNCONDITIONAL),
        "enosys": list(UNAVAILABLE),
        "socket_domains": ["AF_UNIX", "AF_NETLINK"] + (["AF_INET", "AF_INET6"] if allow_inet else []),
        "netlink_protocols": ["NETLINK_ROUTE"],
        "socketpair_domains": ["AF_UNIX"],
        "conditional": ["execveat AT_EMPTY_PATH", "unshare CLONE_NEWUSER", "clone CLONE_NEWUSER",
                        "seccomp SECCOMP_SET_MODE_FILTER"],
        "program_sha256": hashlib.sha256(data).hexdigest(),
        "instructions": len(data) // 8,
    }
