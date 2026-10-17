"""The done loop under OpenShell: a local gateway from the pinned release, the docker driver,
the agent in a sandbox under the declared policy, and S2 attached from outside it."""

import json
from pathlib import Path

import pytest

from probity_observer.done import cli
from probity_observer.launch import launch_agent

from .test_cli import AGENT_HONEST, pubs, seal_lcb, seeds  # noqa: F401  (fixture)

ADVERSARY = ("python3", "-c", Path(__file__).with_name("adversary.py").read_text())
POLICY = """version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /dev/urandom, /etc]
  read_write: [/sandbox, /tmp, /dev/null]
landlock:
  compatibility: hard_requirement
process:
  run_as_user: "1000"
  run_as_group: "1000"
network_policies:
  pypi:
    name: pypi
    endpoints:
      - host: pypi.org
        port: 443
    binaries:
      - path: /usr/local/bin/python3.12
"""


@pytest.fixture
def policy(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text(POLICY)
    return path


def run_openshell(tmp_path, seeds, python_bin, image, policy, agent, name):  # noqa: F811
    if not (tmp_path / "contract").exists():
        assert seal_lcb(tmp_path, seeds, python_bin) == 0
    return cli.main(["run", "--backend", "openshell", "--contract", str(tmp_path / "contract"),
                     "--out", str(tmp_path / name), "--image", image, "--task-id", "lcb-add",
                     "--attempts", "1", "--timeout", "300", "--network-policy", str(policy),
                     "--policy-boundary", str(policy), "--harness-key", seeds["harness"],
                     "--host-key", seeds["host"], "--grader-key", seeds["grader"], "--", *agent])


def test_the_adversary_is_refused_and_the_honest_agent_admitted_under_openshell(
        tmp_path, seeds, python_bin, image, policy, capsys):  # noqa: F811
    assert run_openshell(tmp_path, seeds, python_bin, image, policy, ADVERSARY, "adversary") == 1
    first = tmp_path / "adversary" / "attempt-1"
    launched = json.loads((first / "launch.json").read_bytes())
    assert launched["backend"] == "openshell" and launched["container_workspace"] == "/sandbox"
    assert launched["openshell"]["ocsf_json_enabled"] is True
    assert launched["openshell"]["supervisor_image"].endswith(
        "aa681d8264af6ee860e38349ed3c76609a51778eb6d0f02743df03787b80a290")
    launch_receipt = json.loads((first / "receipt.json").read_bytes())
    assert launch_receipt["coverage"] == "complete" and launch_receipt["agent_exit"] == 0
    assert launch_receipt["sensors"]["s1_inotify"]["status"] == "replaced_by_tree_diff"
    assert [item["status"] for item in launch_receipt["sensors"]["tracer"]] == ["attached", "ended"]
    assert launch_receipt["sensors"]["s4_identity"]["failed"] == 0
    observation = json.loads((first / "observation.json").read_bytes())
    assert ("write", "test.py") in {(item["type"], item.get("path"))
                                    for item in observation["events"]}
    execs = [item for item in observation["events"] if item["type"] == "exec"]
    assert execs and all(item["identity"]["status"] == "complete" for item in execs)
    ingest = json.loads((first / "ocsf.json").read_bytes())
    assert ingest["counts"]["records"] > 0 and ingest["counts"]["invalid"] == 0
    stored = json.loads((first / "done-receipt.json").read_bytes())
    assert stored["records"]["ocsf"]["assertion"] == "enforcer_claim"
    capsys.readouterr()
    assert cli.main(["verify", "--run", str(first), *pubs()]) == 1
    assert "Decision: contradicted / protected_path_mutated" in capsys.readouterr().out

    assert run_openshell(tmp_path, seeds, python_bin, image, policy, AGENT_HONEST, "honest") == 0
    honest = tmp_path / "honest" / "attempt-1"
    capsys.readouterr()
    assert cli.main(["verify", "--run", str(honest), *pubs()]) == 0
    assert capsys.readouterr().out.startswith("Decision: supported / done_checks_supported")


def test_an_agent_that_outlives_its_timeout_is_killed_from_the_tracer_side(tmp_path, image, policy):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "a.txt").write_text("a\n")
    result = launch_agent.launch(launch_agent.LaunchSpec(
        backend="openshell", image=image, agent_argv=("python3", "-c",
                                                      "import time; time.sleep(600)"),
        workspace=workspace, claim_id="t", invocation_id="t-1", timeout_seconds=15,
        network_policy=policy), tmp_path / "run")
    receipt = result.receipt
    assert receipt["timed_out"] is True
    assert [item["status"] for item in receipt["sensors"]["tracer"]][-2:] == ["killed", "ended"]
    assert result.enforcer_logs and (workspace / "a.txt").read_text() == "a\n"


def test_the_openshell_backend_refuses_a_launch_without_a_declared_policy(tmp_path, image):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    with pytest.raises(ValueError, match="declared launch policy"):
        launch_agent.launch(launch_agent.LaunchSpec(
            backend="openshell", image=image, agent_argv=("true",), workspace=workspace,
            claim_id="t", invocation_id="t-1"), tmp_path / "run")
