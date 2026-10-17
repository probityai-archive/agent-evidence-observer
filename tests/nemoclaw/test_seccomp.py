"""OpenShell's seccomp block list as the BPF program the brokered workload launch loads."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from probity_observer.openshell import seccomp

PROBE = r'''
import ctypes, errno, json, os, socket, sys
libc = ctypes.CDLL(None, use_errno=True)
data = open(sys.argv[1], "rb").read()
class Filter(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_char_p)]
prog = Filter(len(data) // 8, data)
assert libc.prctl(38, 1, 0, 0, 0) == 0  # PR_SET_NO_NEW_PRIVS
if libc.prctl(22, 2, ctypes.byref(prog), 0, 0) != 0:  # PR_SET_SECCOMP, FILTER
    raise SystemExit("load failed %d" % ctypes.get_errno())
nr = {k: v for k, v in json.loads(sys.argv[2]).items()}
def call(name, *args):
    ctypes.set_errno(0)
    result = libc.syscall(nr[name], *[ctypes.c_long(a) for a in args])
    return "ok" if result >= 0 else errno.errorcode.get(ctypes.get_errno(), "?")
out = {
    "memfd_create": call("memfd_create", 0, 0),
    "ptrace": call("ptrace", 0, 0, 0, 0),
    "bpf": call("bpf", 0, 0, 0),
    "process_vm_readv": call("process_vm_readv", os.getpid(), 0, 0, 0, 0, 0),
    "io_uring_setup": call("io_uring_setup", 1, 0),
    "mount": call("mount", 0, 0, 0, 0, 0),
    "setns": call("setns", -1, 0),
    "userfaultfd": call("userfaultfd", 0),
    "unshare_newuser": call("unshare", 0x10000000),
    "clone3": call("clone3", 0, 0),
    "pidfd_open": call("pidfd_open", os.getpid(), 0),
    "execveat_empty_path": call("execveat", -1, 0, 0, 0, 0x1000),
    "seccomp_filter": call("seccomp", 1, 0, 0),
    "socket_inet": call("socket", 2, 1, 0),
    "socket_unix": call("socket", 1, 1, 0),
    "socket_netlink_route": call("socket", 16, 3, 0),
    "socket_netlink_audit": call("socket", 16, 3, 9),
    "socketpair_inet": call("socketpair", 2, 1, 0, 0),
    "getpid": call("getpid") if "getpid" in nr else "ok",
}
print(json.dumps(out))
'''

EXPECTED = {
    "memfd_create": "EPERM", "ptrace": "EPERM", "bpf": "EPERM", "process_vm_readv": "EPERM",
    "io_uring_setup": "EPERM", "mount": "EPERM", "setns": "EPERM", "userfaultfd": "EPERM",
    "unshare_newuser": "EPERM", "clone3": "ENOSYS", "pidfd_open": "ENOSYS",
    "execveat_empty_path": "EPERM", "seccomp_filter": "EPERM", "socket_inet": "EPERM",
    "socket_unix": "ok", "socket_netlink_route": "ok", "socket_netlink_audit": "EPERM",
    "socketpair_inet": "EPERM", "getpid": "ok",
}


def run_probe(tmp_path: Path, allow_inet: bool) -> dict:
    path = tmp_path / "filter.bpf"
    path.write_bytes(seccomp.program(allow_inet))
    table = dict(seccomp.SYSCALLS[seccomp.machine()])
    table["getpid"] = {"x86_64": 39, "aarch64": 172}[seccomp.machine()]
    done = subprocess.run([sys.executable, "-I", "-c", PROBE, str(path), json.dumps(table)],
                          capture_output=True, text=True, timeout=60, check=True)
    return json.loads(done.stdout)


def test_the_kernel_refuses_exactly_what_openshell_blocks(tmp_path) -> None:
    assert run_probe(tmp_path, allow_inet=False) == EXPECTED


def test_networking_adds_only_the_inet_families(tmp_path) -> None:
    found = run_probe(tmp_path, allow_inet=True)
    assert found == {**EXPECTED, "socket_inet": "ok"}


def test_the_rule_set_and_digest_are_stable_per_architecture() -> None:
    for arch in ("x86_64", "aarch64"):
        record = seccomp.describe(arch=arch)
        assert record["program_sha256"] == seccomp.describe(arch=arch)["program_sha256"]
        assert record["arch"] == arch and record["source"].startswith("NVIDIA/OpenShell@v0.1.4:")
        assert "AF_INET" not in record["socket_domains"]
    assert seccomp.describe(True, "x86_64")["program_sha256"] != seccomp.describe(
        False, "x86_64")["program_sha256"]
    assert len(seccomp.program(arch="x86_64")) % 8 == 0
    with pytest.raises(ValueError, match="no seccomp syscall table"):
        seccomp.program(arch="riscv64")


def test_a_jump_out_of_range_is_refused() -> None:
    code = seccomp._Assembler()
    code.emit(seccomp.JEQ, 1, "far", 0)
    for _ in range(300):
        code.emit(seccomp.RET, 0)
    code.label("far")
    with pytest.raises(ValueError, match="out of range"):
        code.assemble()


def test_the_workload_launch_loads_and_records_the_filter(tmp_path, monkeypatch) -> None:
    from probity_observer import workload
    from probity_observer.crypto import VerificationError, strict_loads

    from test_workload import FakeServer, keys

    monkeypatch.setattr(workload, "_WriteServer", FakeServer)
    seen = {}

    def child(command, server):
        if "--seccomp" in command:
            seen["command"] = command
            at = command.index("--seccomp")
            seen["bytes"] = os.read(int(command[at + 1]), 1 << 16)
        server.broker.write("one", "/work/result", b"effect")
        return 0, b"", b""

    monkeypatch.setattr(workload, "_run_workload_child", child)
    script = tmp_path / "agent.py"
    script.write_bytes(b"pass\n")
    output = tmp_path / "run"
    report = workload.run_workload(output, script)
    assert report["status"] == "completed"
    assert seen["bytes"] == seccomp.program()
    assert seen["command"].index("--seccomp") < seen["command"].index("--")
    launch = strict_loads((output / "launch-policy.json").read_bytes())
    assert launch["seccomp"] == seccomp.describe()
    assert workload.verify_workload_bundle(output, *keys(output)) == report
    (output / "seccomp.bpf").write_bytes(seccomp.program(allow_inet=True))
    with pytest.raises(VerificationError, match="seccomp filter differs"):
        workload.verify_workload_bundle(output, *keys(output))
    plain = workload.run_workload(tmp_path / "plain", script, seccomp_filter=False)
    assert "seccomp" not in strict_loads((tmp_path / "plain" / "launch-policy.json").read_bytes())
    assert plain["status"] == "completed"


BWRAP_IMAGE = "probity-observer-bwrap-test:local"
ESCAPES = (
    "import json, os, socket\n"
    "out = {}\n"
    "try:\n    os.memfd_create('x'); out['memfd'] = 'ok'\n"
    "except OSError as e:\n    out['memfd'] = e.errno\n"
    "try:\n    socket.socket(socket.AF_INET); out['inet'] = 'ok'\n"
    "except OSError as e:\n    out['inet'] = e.errno\n"
    "request = {'requestId': 'r1', 'path': '/work/result.txt', 'contentHex': b'done\\n'.hex()}\n"
    "with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:\n"
    "    client.connect('/broker/write.sock')\n"
    "    client.sendall(json.dumps(request, sort_keys=True, separators=(',', ':')).encode() + b'\\n')\n"
    "    reply = json.loads(client.makefile('rb').readline(65537))\n"
    "print(json.dumps(out))\n"
    "raise SystemExit(0 if reply.get('ok') else 1)\n"
)


def test_bwrap_runs_the_workload_under_the_filter(tmp_path) -> None:
    """A real bubblewrap launch, inside a privileged container that provides bwrap."""
    context = Path(__file__).with_name("bwrap-image")
    subprocess.run(["docker", "build", "-q", "-t", BWRAP_IMAGE, str(context)], check=True,
                   capture_output=True)
    source = Path(__file__).resolve().parents[2] / "src"
    deps = Path(next(path for path in sys.path if path.endswith("site-packages")))
    (tmp_path / "agent.py").write_text(ESCAPES)
    os.chmod(tmp_path, 0o755)  # bwrap's user namespace has no DAC override on the mount
    driver = ("import json, sys\nfrom pathlib import Path\n"
              "from probity_observer.workload import run_workload\n"
              "for name, on in (('filtered', True), ('plain', False)):\n"
              "    report = run_workload(Path('/out') / name, Path('/out/agent.py'),\n"
              "                          interpreter=Path('/usr/local/bin/python3'),\n"
              "                          seccomp_filter=on)\n"
              "    print(name, json.dumps(report))\n"
              "import os\n"
              "for root, dirs, files in os.walk('/out'):\n"
              "    for item in dirs + files:\n"
              "        os.lchown(os.path.join(root, item), int(sys.argv[1]), int(sys.argv[2]))\n")
    done = subprocess.run(
        ["docker", "run", "--rm", "--privileged", "--network", "none",
         "-v", f"{source}:/src:ro", "-v", f"{deps}:/deps:ro", "-v", f"{tmp_path}:/out",
         "-e", "PYTHONPATH=/src:/deps", BWRAP_IMAGE, "python3", "-c", driver,
         str(os.getuid()), str(os.getgid())],
        capture_output=True, text=True, timeout=300)
    assert done.returncode == 0, done.stderr[-3000:]
    for name, memfd in (("filtered", 1), ("plain", "ok")):
        report = json.loads(next(line for line in done.stdout.splitlines()
                                 if line.startswith(name + " ")).split(" ", 1)[1])
        assert report["status"] == "completed", (
            name, report, (tmp_path / name / "workload-stderr.bin").read_text()[-2000:])
        escapes = json.loads((tmp_path / name / "workload-stdout.bin").read_text())
        assert escapes["memfd"] == memfd
        assert escapes["inet"] == 1 if name == "filtered" else escapes["inet"] == "ok"
        assert (tmp_path / name / "workspace" / "result.txt").read_text() == "done\n"
