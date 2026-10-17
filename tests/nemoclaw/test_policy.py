"""The OpenShell sandbox policy as a declared launch policy, and which rule allows an effect."""

from __future__ import annotations

from pathlib import Path

import pytest

from probity_observer.crypto import VerificationError, strict_loads
from probity_observer.openshell import policy
from probity_observer.openshell.policy import Effect, PolicyError

FIXTURES = Path(__file__).with_name("fixtures")
NEMOCLAW = FIXTURES / "openclaw-sandbox.yaml"
GITHUB = FIXTURES / "github.yaml"

DEMO = b"""version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /etc]
  read_write: [/tmp]
landlock:
  compatibility: hard_requirement
network_policies:
  pypi:
    name: pypi
    endpoints:
      - host: pypi.org
        port: 443
      - host: "*.pythonhosted.org"
        ports: [443, 8443]
    binaries:
      - path: /usr/local/bin/python3.12
  github_api:
    name: github_api
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow: {method: GET, path: "/repos/**"}
        deny_rules:
          - {method: GET, path: "/repos/private/**"}
    binaries:
      - path: /usr/bin/git
      - path: /usr/lib/git-core/*
  docs:
    name: docs
    endpoints:
      - host: docs.example.com
        port: 443
        protocol: rest
        access: read-only
    binaries:
      - path: /usr/bin/curl
  internal:
    name: internal
    endpoints:
      - allowed_ips: ["10.20.0.0/16"]
        port: 5432
    binaries:
      - path: /usr/bin/psql
  audited:
    name: audited
    endpoints:
      - host: audit.example.com
        port: 443
        protocol: rest
        rules:
          - allow: {method: GET, path: "/ok"}
    binaries:
      - path: /usr/bin/curl
  realtime:
    name: realtime
    endpoints:
      - host: ws.example.com
        port: 443
        protocol: websocket
        access: full
    binaries:
      - path: /usr/bin/node
"""


@pytest.fixture
def demo() -> policy.Policy:
    return policy.load(DEMO)


def test_nemoclaw_default_policy_loads_and_validates() -> None:
    loaded = policy.load(NEMOCLAW)
    assert [rule.key for rule in loaded.rules] == [
        "clawhub", "managed_inference", "npm_registry", "nvidia", "openclaw_api", "openclaw_docs"]
    nvidia = policy.match(loaded, Effect(443, ("/usr/local/bin/openclaw",),
                                         host="integrate.api.nvidia.com", method="POST",
                                         path="/v1/chat/completions"))
    assert nvidia.record() == {"decision": "allowed", "rules": ["nvidia"], "l7": "evaluated",
                               "reason": "rest_rule_matched"}


def test_the_declaration_is_stable_and_follows_every_byte_of_meaning(demo) -> None:
    again = policy.load(DEMO)
    assert policy.declaration(again) == policy.declaration(demo)
    reformatted = policy.load(DEMO.replace(b"port: 5432", b"port:   5432  # comment"))
    assert reformatted.canonical_sha256 == demo.canonical_sha256
    assert reformatted.source_sha256 != demo.source_sha256
    widened = policy.load(DEMO.replace(b"port: 5432", b"port: 5433"))
    assert widened.canonical_sha256 != demo.canonical_sha256
    record = policy.declaration(demo)
    assert record["schema"]["sha256"] == policy.pins.NEMOCLAW_NETWORK_SCHEMA_SHA256
    assert record["rules"] == ["audited", "docs", "github_api", "internal", "pypi", "realtime"]


@pytest.mark.parametrize("text,needle", [
    (DEMO.replace(b"  docs:\n", b"  pypi:\n", 1), "duplicate key 'pypi'"),
    (b"version: 1\nx: &a [1]\ny: *a\n", "aliases"),
    (DEMO + b"extra: true\n", "unknown top-level field(s): extra"),
    (DEMO.replace(b"version: 1", b"version: 2"), "version must be 1"),
    (DEMO.replace(b"        port: 5432", b"        port: 5432\n        ports: [1]"), "network_policies/internal"),
    (DEMO.replace(b"name: docs\n", b"name: d\xc3\xb6cs\n"), "canonical profile"),
    (b"- just a list\n", "must be a mapping"),
    (b"version: [\n", "not valid YAML"),
    (b"\xff\xfe", "UTF-8"),
])
def test_a_policy_openshell_would_refuse_is_refused(text: bytes, needle: str) -> None:
    with pytest.raises(PolicyError) as caught:
        policy.load(text)
    assert needle in str(caught.value)


def test_presets_compose_and_may_not_redefine_a_rule() -> None:
    composed = policy.compose(NEMOCLAW.read_bytes(), GITHUB.read_bytes())
    assert "github" in [rule.key for rule in composed.rules]
    git = policy.match(composed, Effect(443, ("/usr/bin/git",), host="api.github.com",
                                        method="DELETE", path="/repos/x"))
    assert git.record()["rules"] == ["github"] and git.decision == "allowed"
    with pytest.raises(PolicyError, match="redefines rule 'github'"):
        policy.compose(NEMOCLAW.read_bytes(), GITHUB.read_bytes(), GITHUB.read_bytes())
    with pytest.raises(PolicyError, match="only 'preset'"):
        policy.compose(NEMOCLAW.read_bytes(), b"version: 1\n")


@pytest.mark.parametrize("effect,expected", [
    (Effect(443, ("/usr/local/bin/python3.12",), host="pypi.org"),
     ("allowed", ["pypi"], "not_applicable", "l4_rule_matched")),
    (Effect(443, ("/usr/local/bin/python3.12",), host="PyPI.org."),
     ("allowed", ["pypi"], "not_applicable", "l4_rule_matched")),
    (Effect(8443, ("/usr/local/bin/python3.12",), host="files.pythonhosted.org"),
     ("allowed", ["pypi"], "not_applicable", "l4_rule_matched")),
    (Effect(443, ("/usr/local/bin/python3.12",), host="a.files.pythonhosted.org"),
     ("denied", [], "not_applicable", "no_matching_rule")),
    (Effect(80, ("/usr/local/bin/python3.12",), host="pypi.org"),
     ("denied", [], "not_applicable", "no_matching_rule")),
    (Effect(443, ("/usr/bin/curl",), host="pypi.org"),
     ("denied", [], "not_applicable", "no_matching_rule")),
    (Effect(443, ("/usr/bin/curl", "/usr/local/bin/python3.12"), host="pypi.org"),
     ("allowed", ["pypi"], "not_applicable", "l4_rule_matched")),
    (Effect(443, ("/usr/bin/git",), host="api.github.com", method="GET", path="/repos/a/b"),
     ("allowed", ["github_api"], "evaluated", "rest_rule_matched")),
    (Effect(443, ("/usr/lib/git-core/git-remote-https",), host="api.github.com",
            method="GET", path="/repos/private/x"),
     ("denied", ["github_api"], "evaluated", "deny_rule_matched")),
    (Effect(443, ("/usr/bin/git",), host="api.github.com", method="POST", path="/repos/a"),
     ("denied", ["github_api"], "evaluated", "no_allow_rule_matched")),
    (Effect(443, ("/usr/bin/git",), host="api.github.com", method="GET", path="/repos"),
     ("denied", ["github_api"], "evaluated", "no_allow_rule_matched")),
    (Effect(443, ("/usr/bin/git",), host="api.github.com"),
     ("allowed", ["github_api"], "not_evaluated", "request_not_observed")),
    (Effect(443, ("/usr/bin/curl",), host="docs.example.com", method="HEAD", path="/a"),
     ("allowed", ["docs"], "evaluated", "rest_rule_matched")),
    (Effect(443, ("/usr/bin/curl",), host="docs.example.com", method="PUT", path="/a"),
     ("allowed_audit", ["docs"], "evaluated", "no_allow_rule_matched")),
    (Effect(443, ("/usr/bin/curl",), host="audit.example.com", method="POST", path="/ok"),
     ("allowed_audit", ["audited"], "evaluated", "no_allow_rule_matched")),
    (Effect(5432, ("/usr/bin/psql",), ip="10.20.3.4"),
     ("allowed", ["internal"], "not_applicable", "l4_rule_matched")),
    (Effect(5432, ("/usr/bin/psql",), ip="10.21.3.4"),
     ("denied", [], "not_applicable", "no_matching_rule")),
    (Effect(5432, ("/usr/bin/psql",)),
     ("denied", [], "not_applicable", "destination_unknown")),
    (Effect(443, ("/usr/bin/node",), host="ws.example.com", method="GET", path="/"),
     ("allowed", ["realtime"], "not_evaluated", "protocol_not_modelled")),
])
def test_match_names_the_rule_that_allows_each_effect(demo, effect, expected) -> None:
    found = policy.match(demo, effect)
    assert (found.decision, list(found.rules), found.l7, found.reason) == expected


def test_globs_follow_openshell_matcher_semantics() -> None:
    assert policy.host_matches("**.example.com", "a.b.example.com")
    assert not policy.host_matches("**.example.com", "example.com")
    assert not policy.host_matches("*.example.com", "a.b.example.com")
    assert policy.host_matches("api.*.example.com", "api.eu.example.com")
    assert policy.host_matches("*-api.example.com", "eu-api.example.com")
    assert policy.path_matches("/usr/lib/jvm/*/bin/java", "/usr/lib/jvm/17/bin/java")
    assert not policy.path_matches("/usr/lib/jvm/*/bin/java", "/usr/lib/jvm/a/b/bin/java")
    assert policy.path_matches("/repos/**", "/repos/a/b")
    assert not policy.path_matches("/repos/**", "/repos")
    assert policy.path_matches("/v[0-9]/x?", "/v1/xy")
    assert policy.path_matches("/a[!b]c", "/axc") and not policy.path_matches("/a[!b]c", "/abc")
    assert policy.path_matches("/a[b", "/a[b")
    assert policy.endpoint_path_matches(None, "/x")
    assert policy.endpoint_path_matches("/v1/**", "/v1")
    assert policy.endpoint_path_matches("/v1/**", "/v1/a/b")
    assert not policy.endpoint_path_matches("/v1/**", "/v2")
    assert policy.endpoint_path_matches("/a*z", "/a/b/z")
    assert policy.binaries_chain([{"path": "/bin/a"}, {"pid": 1}, {"path": "/bin/b"}]) == (
        "/bin/a", "/bin/b")
    assert policy.match_all(policy.load(DEMO), [Effect(1, ())])[0]["reason"] == "destination_unknown"


def test_a_tampered_vendored_schema_is_refused(monkeypatch) -> None:
    monkeypatch.setattr(policy.pins, "NEMOCLAW_NETWORK_SCHEMA_SHA256", "0" * 64)
    with pytest.raises(PolicyError, match="differs from its pin"):
        policy.load(DEMO)


def test_workload_launch_digest_covers_the_declared_policy(tmp_path, monkeypatch) -> None:
    from probity_observer import workload

    from test_workload import FakeServer, keys

    monkeypatch.setattr(workload, "_WriteServer", FakeServer)

    def child(_command, server):
        server.broker.write("one", "/work/result", b"effect")
        return 0, b"", b""

    monkeypatch.setattr(workload, "_run_workload_child", child)
    script = tmp_path / "agent.py"
    script.write_bytes(b"pass\n")
    source = tmp_path / "policy.yaml"
    source.write_bytes(DEMO)
    plain = workload.run_workload(tmp_path / "plain", script)
    declared = workload.run_workload(tmp_path / "declared", script, network_policy=source)
    assert plain["status"] == declared["status"] == "completed"
    launch = strict_loads((tmp_path / "declared" / "launch-policy.json").read_bytes())
    assert launch["networkPolicy"] == policy.declaration(policy.load(DEMO))
    authorities = [strict_loads((tmp_path / name / "authority.json").read_bytes())
                   for name in ("plain", "declared")]
    assert authorities[0]["launchPolicySha256"] != authorities[1]["launchPolicySha256"]
    output = tmp_path / "declared"
    assert workload.verify_workload_bundle(output, *keys(output)) == declared
    (output / "network-policy.yaml").write_bytes(DEMO.replace(b"port: 5432", b"port: 5433"))
    with pytest.raises(VerificationError, match="differs from the launch declaration"):
        workload.verify_workload_bundle(output, *keys(output))
    (output / "network-policy.yaml").write_bytes(b"version: [\n")
    with pytest.raises(VerificationError, match="does not load"):
        workload.verify_workload_bundle(output, *keys(output))
