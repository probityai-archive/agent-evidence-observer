"""A real OpenShell launch whose agent image ships a fake ``strace``.

This needs docker and network access to fetch the pinned OpenShell release; it runs on the
gate boxes (``box_run.sh``). The agent image's ``/usr/bin/strace`` prints a genuine version line
and traces nothing. The launch must still record a complete trace and resolve every exec's
identity, because the tracer and the resolver run from the pinned tracer image.
"""

import json
import subprocess
from pathlib import Path

import pytest

from probity_observer.launch import backend_openshell, launch_agent

IMAGE = "probity-observer-fake-strace:local"
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
network_policies: {}
"""


@pytest.fixture(scope="module")
def image():
    context = Path(__file__).with_name("fake-strace-image")
    subprocess.run(["docker", "build", "-q", "-t", IMAGE, str(context)], check=True,
                   capture_output=True)
    fake = subprocess.run(["docker", "run", "--rm", "--network", "none", "--entrypoint", "sh", IMAGE,
                           "-c", "strace -V; strace -f -p 1; echo rc=$?"],
                          check=True, capture_output=True, text=True).stdout
    assert fake.splitlines() == ["strace -- version 6.13", "strace -- version 6.13", "rc=0"]
    yield IMAGE
    subprocess.run(["docker", "image", "rm", "-f", IMAGE], check=False, capture_output=True)


def test_a_fake_strace_in_the_agent_image_does_not_reach_the_trace(image, tmp_path) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "a.txt").write_text("before\n")
    policy = tmp_path / "policy.yaml"
    policy.write_text(POLICY)
    agent = ("python3", "-c", "import pathlib, subprocess; pathlib.Path('a.txt').write_text('after\\n');"
             " subprocess.run(['/bin/true'], check=True)")
    spec = launch_agent.LaunchSpec(backend="openshell", image=image, agent_argv=agent,
                                   workspace=workspace, claim_id="fake-strace",
                                   invocation_id="fake-strace-1", network_policy=policy,
                                   timeout_seconds=300)
    result = launch_agent.launch(spec, tmp_path / "run")
    launch = json.loads((result.run_dir / "launch.json").read_bytes())
    receipt = json.loads((result.run_dir / "receipt.json").read_bytes())
    tracer = launch["tracer_argv"]
    assert tracer[tracer.index("--entrypoint") + 2] == backend_openshell.TRACER_IMAGE_DIGEST
    assert launch["image_id"] not in tracer
    assert launch["tracer_image"]["image"] == backend_openshell.TRACER_IMAGE_DIGEST
    assert launch["tracer_image"]["binaries_sha256"]["/usr/bin/strace"] == (
        "69f88291a4e47f258b8e32b089c919a247509f063ef3d6afe5389939051102b3")
    assert [item["status"] for item in receipt["sensors"]["tracer"]] == ["attached", "ended"]
    assert receipt["agent_exit"] == 0 and receipt["coverage"] == "complete"
    assert receipt["sensors"]["s2_strace"]["tracer"] == "complete"
    assert receipt["sensors"]["s2_strace"]["calls"] > 0
    identity = receipt["sensors"]["s4_identity"]
    assert identity["requests"] >= 2 and identity["failed"] == 0
    assert identity["complete"] == identity["requests"]
    assert receipt["sensors"]["join"]["unattributed"] == []
    observation = json.loads((result.run_dir / "observation.json").read_bytes())
    assert "a.txt" in json.dumps(observation)
    assert (workspace / "a.txt").read_text() == "after\n"
