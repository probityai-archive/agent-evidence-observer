"""S1: host inotify over a real directory tree."""

import os
import struct
import subprocess
import time

from probity_observer.sensors import inotify


def run(tmp_path, action):
    watcher = inotify.Watcher(tmp_path)
    watcher.start()
    action()
    time.sleep(0.2)
    return watcher.stop()


def paths(report, kind=None):
    return {change.path for change in report.changes if kind is None or change.kind == kind}


def test_writes_creates_renames_and_deletes_are_seen(tmp_path):
    (tmp_path / "keep.txt").write_text("a")

    def act():
        (tmp_path / "new.txt").write_text("b")
        os.rename(tmp_path / "new.txt", tmp_path / "moved.txt")
        os.chmod(tmp_path / "keep.txt", 0o600)
        (tmp_path / "keep.txt").unlink()

    report = run(tmp_path, act)
    assert {"new.txt", "moved.txt", "keep.txt"} <= paths(report)
    assert "keep.txt" in paths(report, "unlink")
    assert "keep.txt" in paths(report, "chmod")
    assert not report.lost


def test_nested_mkdir_race_is_closed_by_scanning(tmp_path):
    def act():
        subprocess.run(["sh", "-c", "mkdir -p a/b/c/d && echo x > a/b/c/d/f"],
                       cwd=tmp_path, check=True)

    report = run(tmp_path, act)
    assert "a/b/c/d/f" in paths(report)
    assert {"a", "a/b", "a/b/c", "a/b/c/d"} <= {watch["path"] for watch in report.watches}


def test_overflow_marks_the_report_lost(tmp_path):
    watcher = inotify.Watcher(tmp_path)
    watcher.start()
    watcher.handle(struct.pack("iIII", -1, inotify.IN_Q_OVERFLOW, 0, 0), time.time())
    report = watcher.stop()
    assert report.overflow and report.lost


def test_failed_watch_marks_the_report_lost(tmp_path):
    watcher = inotify.Watcher(tmp_path)
    watcher._fd = -1
    assert watcher._watch("missing-descriptor") is False
    assert watcher.report.lost


def test_decode_reads_names_with_padding():
    name = b"file.txt\0\0\0\0\0\0\0\0"
    buffer = struct.pack("iIII", 1, inotify.IN_CREATE, 0, len(name)) + name
    assert inotify.decode(buffer, {1: "dir"}, 0.0) == [(1, inotify.IN_CREATE, 0, "dir/file.txt")]
