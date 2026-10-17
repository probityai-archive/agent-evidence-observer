"""S2 parser: events, exits and origins from ``strace -f -ttt -xx -y`` text."""

import pytest

from probity_observer.sensors import strace

WS = "/workspace"


def hx(text: str) -> str:
    return '"' + "".join(f"\\x{byte:02x}" for byte in text.encode()) + '"'


def fd(path: str, number: str = "3") -> str:
    return f"{number}<" + hx(path)[1:-1] + ">"


def cwd(path: str = WS) -> str:
    return "AT_FDCWD<" + hx(path)[1:-1] + ">"


def execve(pid, t, *argv):
    args = ", ".join(hx(item) for item in argv)
    return f"{pid} {t:.6f} execve({hx(argv[0])}, [{args}], 0x7ffd /* 3 vars */) = 0"


def line(pid, t, body):
    return f"{pid} {t:.6f} {body}"


def build(lines):
    return strace.read("\n".join(lines) + "\n", WS)


def kinds(found, kind):
    return [event for event in found.events if event.kind == kind]


def test_flags_name_every_family_and_print_exits():
    expression = strace.TRACE_EXPRESSION
    for name in ("execve", "execveat", "open", "openat", "openat2", "creat", "mkdir", "rename",
                 "renameat2", "link", "linkat", "unlink", "unlinkat", "rmdir", "truncate",
                 "ftruncate", "chmod", "fchmodat2", "mmap", "connect", "clone3", "vfork"):
        assert name in expression.removeprefix("trace=").split(",")
    assert "-qq" not in strace.FLAGS and "-q" in strace.FLAGS
    assert {"-f", "-y", "-xx", "-ttt", "-z"} <= set(strace.FLAGS)


def test_raw_open_syscall_is_a_write():
    found = build([
        execve(10, 1.0, "agent"),
        line(10, 1.1, f'open({hx("tests/test_a.py")}, O_WRONLY|O_CREAT|O_TRUNC, 0644) = '
                      f'{fd("/workspace/tests/test_a.py")}'),
        line(10, 1.2, "+++ exited with 0 +++"),
    ])
    writes = kinds(found, "write")
    assert [event.path for event in writes] == ["/workspace/tests/test_a.py"]


def test_read_only_open_is_a_read_and_directory_open_is_skipped():
    found = build([
        execve(10, 1.0, "agent"),
        line(10, 1.1, f"openat({cwd()}, {hx('a.txt')}, O_RDONLY|O_CLOEXEC) = "
                      f"{fd('/workspace/a.txt')}"),
        line(10, 1.2, f"openat({cwd()}, {hx('.')}, O_RDONLY|O_DIRECTORY) = {fd('/workspace')}"),
    ])
    assert [event.path for event in kinds(found, "read")] == ["/workspace/a.txt"]


def test_exit_status_goes_to_the_last_exec_of_each_process():
    found = build([
        execve(10, 1.0, "sh", "-c", "x"),
        execve(10, 1.1, "agent"),
        line(10, 1.2, "vfork() = 11"),
        execve(11, 1.3, "python3", "-m", "pytest"),
        line(11, 1.4, "+++ exited with 1 +++"),
        line(10, 1.5, "+++ killed by SIGKILL +++"),
    ])
    execs = kinds(found, "exec")
    assert [(event.argv[0], event.exit) for event in execs] == [
        ("sh", None), ("agent", 137), ("python3", 1)]
    assert found.root_exited


def test_missing_root_exit_means_the_tracer_was_lost():
    found = build([execve(10, 1.0, "agent")])
    assert not found.root_exited


def test_origin_is_the_command_root_exec_and_the_agent_has_none():
    found = build([
        execve(10, 1.0, "agent"),
        line(10, 1.1, f"openat({cwd()}, {hx('src/app.py')}, O_WRONLY|O_TRUNC) = "
                      f"{fd('/workspace/src/app.py')}"),
        line(10, 1.2, "clone(child_stack=NULL, flags=CLONE_CHILD_SETTID|SIGCHLD) = 11"),
        execve(11, 1.3, "sh", "-c", "python3 -m pytest"),
        line(11, 1.4, "vfork() = 12"),
        execve(12, 1.5, "python3", "-m", "pytest"),
        line(12, 1.6, f"openat({cwd()}, {hx('tests/__pycache__/t.pyc')}, O_WRONLY|O_CREAT) = "
                      f"{fd('/workspace/tests/__pycache__/t.pyc')}"),
        line(12, 1.7, "clone(child_stack=NULL, flags=CLONE_CHILD_SETTID|SIGCHLD) = 13"),
        line(13, 1.8, f"openat({cwd()}, {hx('grand.txt')}, O_WRONLY|O_CREAT) = "
                      f"{fd('/workspace/grand.txt')}"),
    ])
    by_path = {event.path: event for event in found.events if event.kind == "write"}
    shell = kinds(found, "exec")[1]
    assert by_path["/workspace/src/app.py"].origin is None
    assert by_path["/workspace/tests/__pycache__/t.pyc"].origin == shell.id
    assert by_path["/workspace/grand.txt"].origin == shell.id
    assert kinds(found, "exec")[2].origin == shell.id
    assert shell.origin is None


def test_interactive_shell_children_are_separate_commands():
    found = build([
        execve(10, 1.0, "agent"),
        line(10, 1.1, "vfork() = 11"),
        execve(11, 1.2, "/bin/bash", "--noprofile"),
        line(11, 1.3, "vfork() = 12"),
        execve(12, 1.4, "sed", "-i", "s/a/b/", "src/app.py"),
        line(12, 1.5, f"openat({cwd()}, {hx('src/app.py')}, O_WRONLY|O_CREAT) = "
                      f"{fd('/workspace/src/app.py')}"),
        line(11, 1.6, "vfork() = 13"),
        execve(13, 1.7, "python3", "-m", "pytest"),
    ])
    sed, pytest_exec = kinds(found, "exec")[2], kinds(found, "exec")[3]
    write = kinds(found, "write")[0]
    assert write.origin == sed.id
    assert pytest_exec.origin is None
    assert write.origin != pytest_exec.id


def test_threads_belong_to_their_process():
    found = build([
        execve(10, 1.0, "agent"),
        line(10, 1.1, "clone3({flags=CLONE_VM|CLONE_FS|CLONE_THREAD|CLONE_SIGHAND, "
                      "exit_signal=0}, 88) = 20"),
        line(20, 1.2, f"openat({cwd()}, {hx('t.txt')}, O_WRONLY|O_CREAT) = "
                      f"{fd('/workspace/t.txt')}"),
    ])
    assert kinds(found, "write")[0].pid == 10


def test_relative_paths_follow_chdir_and_dirfd():
    found = build([
        execve(10, 1.0, "agent"),
        line(10, 1.1, f"mkdir({hx('a b')}, 0777) = 0"),
        line(10, 1.2, f"chdir({hx('a b')}) = 0"),
        line(10, 1.3, f"mkdir({hx('c')}, 0777) = 0"),
        line(10, 1.4, f"unlinkat({fd('/workspace/x', '5')}, {hx('y')}, 0) = 0"),
        line(10, 1.5, f"rename({hx('c')}, {hx('../d')}) = 0"),
        line(10, 1.6, f"linkat({cwd('/workspace/a b')}, {hx('f')}, {cwd('/workspace')}, "
                      f"{hx('tests/g')}, 0) = 0"),
    ])
    assert [(event.kind, event.path, event.target) for event in found.events[1:]] == [
        ("create", "/workspace/a b", None),
        ("create", "/workspace/a b/c", None),
        ("unlink", "/workspace/x/y", None),
        ("rename", "/workspace/a b/c", "/workspace/d"),
        ("link", "/workspace/a b/f", "/workspace/tests/g"),
    ]


def test_descriptor_without_a_path_is_unresolved_not_guessed():
    found = build([
        execve(10, 1.0, "agent"),
        line(10, 1.1, f"mkdirat(3, {hx('b')}, 0777) = 0"),
        line(10, 1.2, f"mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, 4, 0) = 0x7f"),
        line(10, 1.3, f"mkdirat(3, {hx('/workspace/abs')}, 0777) = 0"),
    ])
    assert [item["syscall"] for item in found.unresolved] == ["mkdirat", "mmap"]
    assert [event.path for event in kinds(found, "create")] == ["/workspace/abs"]


def test_shared_writable_mmap_is_a_write_and_private_is_not():
    path = fd("/workspace/data.bin")
    found = build([
        execve(10, 1.0, "agent"),
        line(10, 1.1, f"mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, {path}, 0) = 0x7f"),
        line(10, 1.2, f"mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE, {path}, 0) = 0x7e"),
        line(10, 1.3, f"mmap(NULL, 4096, PROT_READ, MAP_SHARED, {path}, 0) = 0x7d"),
    ])
    assert len(kinds(found, "write")) == 1


def test_metadata_truncate_and_connect_are_recorded():
    found = build([
        execve(10, 1.0, "agent"),
        line(10, 1.1, f"fchmodat2({cwd()}, {hx('tests/t.py')}, 0444, 0) = 0"),
        line(10, 1.2, f"ftruncate({fd('/workspace/out.log')}, 0) = 0"),
        line(10, 1.3, f"utimensat({cwd()}, {hx('tests/t.py')}, NULL, 0) = 0"),
        line(10, 1.4, "connect(4<socket:[1]>, {sa_family=AF_INET, sin_port=htons(443), "
                      f"sin_addr=inet_addr({hx('1.2.3.4')})}}, 16) = 0"),
    ])
    assert [(event.kind, event.path) for event in found.events[1:]] == [
        ("chmod", "/workspace/tests/t.py"), ("truncate", "/workspace/out.log"),
        ("chmod", "/workspace/tests/t.py"), ("connect", None)]
    assert "443" in found.events[-1].address


def test_unfinished_calls_are_joined_with_their_resumption():
    found = build([
        execve(10, 1.0, "agent"),
        line(10, 1.1, f"openat({cwd()}, {hx('slow.txt')}, O_WRONLY|O_CREAT <unfinished ...>"),
        line(11, 1.2, "+++ exited with 0 +++"),
        line(10, 1.3, f"<... openat resumed>, 0644) = {fd('/workspace/slow.txt')}"),
    ])
    assert kinds(found, "write")[0].path == "/workspace/slow.txt"


def test_escape_syscalls_are_reported():
    found = build([execve(10, 1.0, "agent"), line(10, 1.1, "io_uring_setup(8, 0x7ff) = 3")])
    assert found.escapes and found.escapes[0]["syscall"] == "io_uring_setup"


def test_lines_from_another_writer_are_kept_as_unparsed():
    trace = strace.parse("strace: something went wrong\n" + execve(10, 1.0, "agent") + "\n")
    assert trace.unparsed == ["strace: something went wrong"]


def test_hex_decoding_refuses_a_short_escape():
    with pytest.raises(strace.TraceError):
        strace.decode_hex("\\x2")


def test_within_keeps_only_workspace_paths():
    assert strace.within("/workspace/a/b", WS) == "a/b"
    assert strace.within("/workspace", WS) is None
    assert strace.within("/workspacex/a", WS) is None
    assert strace.within("/tmp/a", WS) is None
