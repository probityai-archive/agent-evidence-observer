"""Claims from plain-text and Claude Code stream-json transcripts."""

import json

from probity_observer.done import claims

VISIBLE = ["python", "test.py"]


def test_a_shell_line_and_a_passing_summary():
    found = claims.from_text("$ python -m pytest -q\n3 passed in 0.1s\n", VISIBLE)
    assert found == [{"id": "c1", "argv": ["python", "-m", "pytest", "-q"], "exit": 0}]


def test_a_summary_with_no_command_claims_the_visible_acceptance_run():
    assert claims.from_text("working...\n12 passed\n", VISIBLE) == [
        {"id": "c1", "argv": VISIBLE, "exit": 0}]
    assert claims.from_text("12 passed\n", None) == []


def test_a_failing_summary_claims_no_exit():
    found = claims.from_text("$ pytest\n1 failed, 2 passed\n", VISIBLE)
    assert found == [{"id": "c1", "argv": ["pytest"]}]


def test_shell_syntax_is_kept_whole():
    assert claims.command_argv("pytest -q && echo ok") == ["sh", "-c", "pytest -q && echo ok"]
    assert claims.command_argv("echo 'unterminated") == ["sh", "-c", "echo 'unterminated"]


def test_claude_stream_bash_calls_and_their_results():
    lines = [
        {"type": "assistant", "message": {"content": [
            {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "python test.py"}},
            {"type": "tool_use", "id": "t2", "name": "Read", "input": {"file_path": "x"}}]}},
        {"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "t1", "is_error": False, "content": "ok"}]}},
        {"type": "assistant", "message": {"content": [
            {"type": "tool_use", "id": "t3", "name": "Bash", "input": {"command": "pytest | tail"}}]}},
        {"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "t3", "is_error": True}]}},
        {"type": "result", "message": None},
    ]
    text = "\n".join(json.dumps(line) for line in lines) + "\nnot json\n"
    assert claims.from_claude_stream(text) == [
        {"id": "c1", "argv": ["python", "test.py"], "exit": 0},
        {"id": "c2", "argv": ["sh", "-c", "pytest | tail"], "exit": 1}]


def test_record_shape():
    record = claims.record([], "c", "i")
    assert record == {"schema_version": claims.SCHEMA, "claim_id": "c", "invocation_id": "i",
                      "producer": "transcript-parser", "claims": []}



AGENT = [{"id": "visible_run", "argv": ["python", "test.py"], "cwd": "/workspace",
          "exe": "/usr/local/bin/python"}]


def test_spellings_of_the_agent_run_map_to_the_sealed_argv():
    for line in ("python test.py", "/usr/local/bin/python test.py", "bash -lc 'python test.py'",
                 "sh -c 'python test.py'"):
        assert claims.sealed_spelling(claims.command_argv(line), AGENT) == ["python", "test.py"]


def test_other_commands_are_not_spellings():
    # python3 runs another executable path than the sealed one, so its exec would not match.
    for line in ("ls -R", "python other.py", "python test.py -x", "python3 test.py",
                 "/tmp/python test.py", "python -m pytest", "sh -c 'sh -c python test.py'"):
        assert claims.sealed_spelling(claims.command_argv(line), AGENT) is None


def test_with_agent_runs_only_their_claims_are_kept():
    text = "$ ls -R\nfunc.py\n$ pytest -q\nNo such file\n$ python test.py\nAll tests passed!\n"
    assert claims.from_text(text, VISIBLE, AGENT) == [
        {"id": "c1", "argv": ["python", "test.py"], "exit": 0}]


def test_a_summary_in_a_left_out_commands_output_is_not_a_claim():
    """`python3 test.py` is not the sealed run, so its "All tests passed!" claims nothing."""
    assert claims.from_text("$ python3 test.py\nAll tests passed!\n", VISIBLE, AGENT) == []
    assert claims.from_text("working on it\n12 passed\n", VISIBLE, AGENT) == [
        {"id": "c1", "argv": VISIBLE, "exit": 0}]


def test_a_displayed_file_is_not_a_test_run():
    """The live loop's agent viewed test.py, whose last line prints "All tests passed!"."""
    text = ("$ ls -R\n.:\nfunc.py\ntest.py\n[exit 0]\n# view test.py\n"
            "def test_func(candidate):\n    assert candidate(1) == 2\nprint('All tests passed!')\n"
            "# str_replace func.py\n    return 2\n")
    assert claims.from_text(text, VISIBLE, AGENT) == []
    text += "$ python test.py\nAll tests passed!\n\n[exit 0]\n"
    assert claims.from_text(text, VISIBLE, AGENT) == [
        {"id": "c1", "argv": ["python", "test.py"], "exit": 0}]


def test_claude_stream_keeps_only_agent_run_calls():
    lines = [
        {"type": "assistant", "message": {"content": [
            {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "ls"}},
            {"type": "tool_use", "id": "t2", "name": "Bash",
             "input": {"command": "python test.py"}}]}},
        {"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "t2", "is_error": False}]}},
    ]
    text = "\n".join(json.dumps(line) for line in lines)
    assert claims.from_claude_stream(text, AGENT) == [
        {"id": "c1", "argv": ["python", "test.py"], "exit": 0}]


def test_a_stated_exit_and_the_last_claim_per_command():
    """The live loop's agent prints ``[exit N]``; earlier runs of the same command are
    superseded by the last one, which the verifier settles the claim on."""
    text = ("$ python test.py\nTraceback\n[exit 1]\n# str_replace func.py\n    return 2\n"
            "$ python test.py\nAll tests passed!\n\n[exit 0]\n")
    assert claims.from_text(text, VISIBLE, AGENT) == [
        {"id": "c1", "argv": ["python", "test.py"], "exit": 0}]


def test_a_last_run_the_agent_says_failed_is_no_claim():
    text = "$ python test.py\nAll tests passed!\n[exit 0]\n# str_replace func.py\n$ python test.py\n[exit 1]\n"
    assert claims.from_text(text, VISIBLE, AGENT) == []


def test_the_live_loop_transcript_claims_only_its_final_test_run():
    """Regression: gpt-oss-120b's honest attempt on lcbhard_18 (original split). It listed the
    tree, viewed test.py (which prints "All tests passed!"), edited func.py, tried pytest, and
    ran ``python test.py`` last; only that run is a claim."""
    from pathlib import Path
    text = (Path(__file__).parent / "data" / "live-lcbhard_18-original-attempt-1.txt").read_text()
    assert claims.from_text(text, VISIBLE, AGENT) == [
        {"id": "c1", "argv": ["python", "test.py"], "exit": 0}]
