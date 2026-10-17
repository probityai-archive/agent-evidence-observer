"""OpenShell backend: OpenShell enforces, the observer records from outside the sandbox.

One launch is one local OpenShell gateway and one sandbox, both started from the pinned
release (:mod:`..openshell.pins`): the ``openshell`` and ``openshell-gateway`` executables
fetched and checked by digest, the supervisor and sandbox runtime images by digest, and the
docker compute driver. The order:

1. Start the gateway on a free loopback port with its own state directory, mint its sandbox
   JWT keys (``generate-certs``) and register it with the CLI in that directory only.
2. Turn on OpenShell's OCSF JSON export for every sandbox
   (``settings set --global --key ocsf_json_enabled --value true --yes``).
3. Create the sandbox from the agent image with ``--policy`` set to the declared launch policy,
   so the policy the launch record carries is the one OpenShell enforces. Upload the workspace
   to ``/sandbox`` and download it back: the start tree inside the sandbox must equal the sealed
   start tree, or the launch is refused before the agent runs.
4. Run the agent through ``openshell sandbox exec``. OpenShell's seccomp filter refuses
   ``ptrace`` inside the sandbox, so S2 (``strace``) attaches from a tracer container that shares
   only the sandbox's process namespace (:mod:`.tracer_attach`), and the exec gate's resolver
   runs there too. The agent's argv starts behind a wrapper that runs no instruction of the
   agent's until the tracer is attached.
5. Download the final tree into the host workspace; it is S3. The difference between the
   sealed start tree and the final tree stands in for S1: every changed path the trace does
   not account for is joined into the observation as an unattributed change with a gap.
6. Collect ``docker logs`` of the sandbox and supervisor containers (OpenShell's OCSF lines,
   :mod:`..openshell.ocsf`), then delete the sandbox and stop the gateway.

The agent runs under the policy's numeric ``process.run_as_user``; the tracer runs as root in
another container, so the agent can neither signal it nor read its descriptors.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..openshell import pins, release
from ..openshell import policy as network_policy
from ..sensors import binary_identity, inotify, strace, treedigest
from . import tracer_attach

NAME = "openshell"
WORKSPACE = "/sandbox"
IDENTITY_GATE = True
STARTUP_EXEC = False
TRACER_CAPABILITIES = ("SYS_PTRACE", "KILL")
ATTACH_WAIT = 60.0
READY_WAIT = 60.0
COMMAND_WAIT = 300.0
NAMESPACE_LABEL = "openshell.ai/sandbox-namespace"
ROLE_LABEL = "openshell.ai/isolation-role"
SANDBOX_LABEL = "openshell.ai/sandbox-name"
WRAPPER = ('while :; do t=0; while read -r k v; do [ "$k" = TracerPid: ] && t=$v; done '
           '< /proc/self/status; [ "$t" != 0 ] && break; done; exec "$@" 2>&1')
"""Spin on shell builtins until a tracer is attached, then exec the agent's argv with its
stderr merged into stdout. It starts no process before the tracer is in place."""


class BackendError(RuntimeError):
    """OpenShell or the docker runtime cannot run a traced agent."""


@dataclass(frozen=True)
class Identity:
    image: str
    image_id: str
    strace_version: str
    runtime_version: str
    openshell: dict[str, Any] = field(default_factory=dict)


def uid_separated(identity: Identity) -> bool:
    """The tracer is root in its own container; the agent runs under the policy's uid."""
    return True


def tracer_flags() -> tuple[str, ...]:
    flags = list(strace.FLAGS)
    at = flags.index("signal=none")
    del flags[at - 1:at + 1]
    return (*flags, *binary_identity.TRACER_FLAGS)


def policy_uid(policy: network_policy.Policy) -> int:
    """The policy's numeric ``process.run_as_user``; the backend refuses any other form."""
    value = (policy.document.get("process") or {}).get("run_as_user")
    if not isinstance(value, str) or not value.isdigit() or int(value) == 0:
        raise BackendError("the openshell backend needs a numeric non-root "
                           "process.run_as_user in the declared policy")
    return int(value)


def _run(argv: list[str], *, env: dict[str, str] | None = None, timeout: float = COMMAND_WAIT,
         check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        done = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=timeout,
                              check=False)
    except subprocess.TimeoutExpired as error:
        raise BackendError(f"{' '.join(argv[:4])} did not finish in {timeout:.0f} s") from error
    if check and done.returncode != 0:
        detail = (done.stderr or done.stdout).strip().splitlines()
        raise BackendError(f"{' '.join(argv[:4])} failed: {detail[-1] if detail else done.returncode}")
    return done


def _image_present(reference: str, docker: str) -> bool:
    return _run([docker, "image", "inspect", "--format", "{{.Id}}", reference],
                check=False).returncode == 0


def preflight(image: str, docker: str = "docker", cache: Path | None = None) -> Identity:
    """Pin the agent image, the release executables and both runtime images."""
    binaries = {name: release.executable(name, cache) for name in ("openshell", "openshell-gateway")}
    for reference in (pins.SUPERVISOR_IMAGE, pins.SANDBOX_RUNTIME_IMAGE):
        if not _image_present(reference, docker):
            _run([docker, "pull", "--quiet", reference], timeout=900)
    image_id = _run([docker, "image", "inspect", "--format", "{{.Id}}", image]).stdout.strip()
    runtime = _run([docker, "version", "--format", "{{.Server.Version}}"]).stdout.strip()
    probe = _run([docker, "run", "--rm", "--network", "none", "--entrypoint", "/bin/sh", image_id,
                  "-c", "strace -V | head -n 1; command -v python3"]).stdout.splitlines()
    if len(probe) != 2 or not probe[0].startswith("strace -- version"):
        raise BackendError("image lacks strace or python3 (the attached tracer and the resolver)")
    version = _run([str(binaries["openshell"]), "--version"]).stdout.strip()
    if version != f"openshell {pins.OPENSHELL_VERSION}":
        raise BackendError(f"openshell reports {version!r}, not {pins.OPENSHELL_VERSION}")
    return Identity(image, image_id, probe[0], runtime, {
        "version": pins.OPENSHELL_VERSION,
        "binaries": {name: {"path": str(path), "sha256": pins.BINARY_SHA256[name]}
                     for name, path in binaries.items()},
        "supervisor_image": pins.SUPERVISOR_IMAGE,
        "sandbox_runtime_image": pins.SANDBOX_RUNTIME_IMAGE,
        "compute_driver": "docker",
    })


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def gateway_config(state: Path, port: int, namespace: str) -> str:
    """The gateway's TOML: docker driver, loopback plaintext, pinned runtime images."""
    jwt = state / "tls" / "jwt"
    return "\n".join([
        "[openshell]", "version = 2", "",
        "[openshell.gateway]", f'bind_address = "127.0.0.1:{port}"', 'compute_driver = "docker"',
        "disable_tls = true", "",
        "[openshell.gateway.auth]", "allow_unauthenticated_users = true", "",
        "[openshell.gateway.gateway_jwt]", f'signing_key_path = "{jwt / "signing.pem"}"',
        f'public_key_path = "{jwt / "public.pem"}"', f'kid_path = "{jwt / "kid"}"',
        f'gateway_id = "{namespace}"', "",
        "[openshell.drivers.docker]", f'sandbox_runtime_image = "{pins.SANDBOX_RUNTIME_IMAGE}"',
        f'supervisor_image = "{pins.SUPERVISOR_IMAGE}"', 'image_pull_policy = "never"',
        f'sandbox_label = "{namespace}"', ""])


def _replace_tree(source: Path, target: Path) -> None:
    """Make ``target`` hold exactly the entries of ``source``."""
    for entry in list(target.iterdir()):
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry)
        else:
            entry.unlink()
    for entry in source.iterdir():
        shutil.move(str(entry), str(target / entry.name))


def tree_changes(before: treedigest.Tree, after: treedigest.Tree, when: float) -> list[inotify.Change]:
    """The S1 stand-in: one change per path whose entry differs between the two trees."""
    def entries(tree: treedigest.Tree) -> dict[str, tuple[str, str]]:
        found = {name: ("file", digest) for name, digest in tree.files.items()}
        found.update({name: ("link", target) for name, target in tree.symlinks.items()})
        found.update({name: ("special", kind) for name, kind in tree.special.items()})
        return found

    old, new = entries(before), entries(after)
    old_x, new_x = set(before.executable), set(after.executable)
    changes = []
    for name in sorted(set(old) | set(new)):
        if name not in new:
            kind = "unlink"
        elif name not in old:
            kind = "create"
        elif old[name] != new[name]:
            kind = "write"
        elif (name in old_x) != (name in new_x):
            kind = "chmod"
        else:
            continue
        changes.append(inotify.Change(time=when, kind=kind, path=name, mask=0))
    return changes


NAME_LENGTH = 19
"""OpenShell 0.1.4 refuses a sandbox name longer than this."""


class Session:
    """One gateway and one sandbox for one launch; :meth:`close` removes both.

    ``name`` labels the tracer container; the sandbox itself gets a fresh short name.
    """

    def __init__(self, identity: Identity, *, policy_path: Path, name: str,
                 docker: str = "docker") -> None:
        self.identity = identity
        self.policy_path = Path(policy_path)
        self.name = f"probity-{uuid.uuid4().hex[:NAME_LENGTH - 8]}"
        self.docker = docker
        self.namespace = f"probity-{uuid.uuid4().hex[:12]}"
        self.marker = f"probity-agent-{uuid.uuid4().hex}"
        self.tracer_name = f"{name}-tracer"
        self.state = Path(tempfile.mkdtemp(prefix="probity-openshell-"))
        self.port = free_port()
        self.gateway: subprocess.Popen[bytes] | None = None
        self.sandbox_container: str | None = None
        self.supervisor_container: str | None = None
        self.record: dict[str, Any] = {}

    @property
    def cli(self) -> list[str]:
        return [self.identity.openshell["binaries"]["openshell"]["path"], "-g", self.namespace]

    @property
    def env(self) -> dict[str, str]:
        base = {key: value for key, value in os.environ.items()
                if not key.startswith("OPENSHELL_")}
        return {**base, "HOME": str(self.state), "XDG_CONFIG_HOME": str(self.state / "config"),
                "XDG_STATE_HOME": str(self.state / "state"),
                "XDG_DATA_HOME": str(self.state / "data"), "NO_COLOR": "1"}

    def _cli(self, *args: str, timeout: float = COMMAND_WAIT) -> str:
        return _run([*self.cli, *args], env=self.env, timeout=timeout).stdout

    def start_gateway(self) -> None:
        gateway = self.identity.openshell["binaries"]["openshell-gateway"]["path"]
        _run([gateway, "generate-certs", "--output-dir", str(self.state / "tls")], env=self.env)
        config = self.state / "gateway.toml"
        config.write_text(gateway_config(self.state, self.port, self.namespace))
        env = {**self.env, "OPENSHELL_DB_URL": f"sqlite:{self.state / 'gateway.db'}?mode=rwc"}
        log = open(self.state / "gateway.log", "wb")  # noqa: SIM115 (closed by the process exit)
        self.gateway = subprocess.Popen([gateway, "--config", str(config), "--name", self.namespace],
                                        stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=env)
        deadline = time.monotonic() + READY_WAIT
        added = False
        while time.monotonic() < deadline:
            if self.gateway.poll() is not None:
                raise BackendError("openshell-gateway exited: "
                                   + (self.state / "gateway.log").read_text("utf-8", "replace")[-400:])
            if not added:
                added = _run([*self.cli[:1], "gateway", "add", f"http://127.0.0.1:{self.port}",
                              "--local", "--name", self.namespace], env=self.env,
                             check=False).returncode == 0
            if added and "Connected" in _run([*self.cli, "status"], env=self.env,
                                             check=False).stdout:
                self.record["gateway"] = {"port": self.port, "name": self.namespace,
                                          "config_sha256": hashlib.sha256(config.read_bytes()).hexdigest()}
                return
            time.sleep(0.25)
        raise BackendError("openshell-gateway did not become ready")

    def _container(self, role: str) -> str:
        found = _run([self.docker, "ps", "-q", "--filter", f"label={NAMESPACE_LABEL}={self.namespace}",
                      "--filter", f"label={SANDBOX_LABEL}={self.name}",
                      "--filter", f"label={ROLE_LABEL}={role}"]).stdout.split()
        if len(found) != 1:
            raise BackendError(f"expected one {role} container for sandbox {self.name}, found {len(found)}")
        return found[0]

    def create(self) -> None:
        self._cli("settings", "set", "--global", "--key", "ocsf_json_enabled", "--value", "true",
                  "--yes")
        self._cli("sandbox", "create", "--name", self.name, "--from", self.identity.image_id,
                  "--policy", str(self.policy_path), "--detach", "--no-tty",
                  "--no-auto-providers", "--", "sleep", "infinity", timeout=900)
        self.sandbox_container = self._container("sandbox")
        self.supervisor_container = self._container("supervisor")
        inspect = json.loads(_run([self.docker, "inspect", self.sandbox_container]).stdout)[0]
        self.record.update(sandbox=self.name, sandbox_container=inspect["Id"],
                           sandbox_image=inspect["Image"],
                           supervisor_container=self.supervisor_container,
                           ocsf_json_enabled=True)

    def upload(self, workspace: Path) -> None:
        """Copy the workspace into ``/sandbox`` entry by entry (a directory upload nests)."""
        for entry in sorted(Path(workspace).iterdir()):
            self._cli("sandbox", "upload", "--no-git-ignore", self.name, str(entry), f"{WORKSPACE}/")

    def download(self, target: Path) -> Path:
        """Download ``/sandbox`` into the empty directory ``target``; return the tree's root."""
        target.mkdir(parents=True, exist_ok=False)
        self._cli("sandbox", "download", self.name, WORKSPACE, str(target))
        nested = target / Path(WORKSPACE).name
        entries = list(target.iterdir())
        if entries == [nested] and nested.is_dir() and not nested.is_symlink():
            return nested
        return target

    def verify_start(self, workspace: Path) -> treedigest.Tree:
        """Refuse the launch unless the uploaded tree equals the host workspace tree."""
        expected = treedigest.scan(workspace)
        root = self.download(self.state / "start-check")
        found = treedigest.scan(root)
        shutil.rmtree(self.state / "start-check")
        if found.sha256 != expected.sha256:
            raise BackendError("the tree uploaded to /sandbox differs from the sealed start tree")
        self.record["start_tree_sha256"] = expected.sha256
        return expected

    def exec_argv(self, agent_argv: list[str], env: dict[str, str]) -> list[str]:
        argv = [*self.cli, "sandbox", "exec", "-n", self.name, "--no-tty", "--no-login-shell",
                "--workdir", WORKSPACE]
        for key in sorted(env):
            argv += ["--env", f"{key}={env[key]}"]
        return [*argv, "--", "/bin/sh", "-c", WRAPPER, self.marker, *agent_argv]

    def tracer_argv(self) -> list[str]:
        argv = [self.docker, "run", "--rm", "--name", self.tracer_name,
                "--pid", f"container:{self.sandbox_container}", "--network", "none",
                "--cap-drop", "ALL"]
        for capability in TRACER_CAPABILITIES:
            argv += ["--cap-add", capability]
        source = Path(tracer_attach.__file__).read_text(encoding="utf-8")
        return [*argv, "--security-opt", "no-new-privileges", "--user", "0:0",
                "--entrypoint", "python3", self.identity.image_id, "-I", "-c", source,
                self.marker, str(ATTACH_WAIT), *tracer_flags()]

    def resolver_argv(self) -> list[str]:
        source = Path(binary_identity.__file__).read_text(encoding="utf-8")
        return [self.docker, "exec", "-i", "--user", "0:0", "--workdir", "/", self.tracer_name,
                "python3", "-I", "-c", source, "serve", "1"]

    def stop_agent(self) -> None:
        """The launcher's timeout: the tracer kills the traced tree and then ends."""
        _run([self.docker, "kill", "--signal", "TERM", self.tracer_name], check=False)

    def logs(self) -> dict[str, bytes]:
        found = {}
        for label, container in (("sandbox.log", self.sandbox_container),
                                 ("supervisor.log", self.supervisor_container)):
            if container is None:
                continue
            done = subprocess.run([self.docker, "logs", container], capture_output=True,
                                  check=False, timeout=COMMAND_WAIT)
            found[label] = done.stdout + done.stderr
        return found

    def close(self) -> None:
        if self.gateway is not None and self.gateway.poll() is None:
            _run([*self.cli, "sandbox", "delete", self.name], env=self.env, check=False)
        _run([self.docker, "rm", "-f", self.tracer_name], check=False)
        for container in _run([self.docker, "ps", "-aq", "--filter",
                               f"label={NAMESPACE_LABEL}={self.namespace}"], check=False).stdout.split():
            _run([self.docker, "rm", "-f", container], check=False)
        if self.gateway is not None and self.gateway.poll() is None:
            self.gateway.terminate()
            try:
                self.gateway.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.gateway.kill()
                self.gateway.wait()
        shutil.rmtree(self.state, ignore_errors=True)
