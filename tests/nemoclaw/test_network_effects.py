"""Traced connects judged against the declared policy, without a container."""

from __future__ import annotations

from probity_observer.launch import network_effects
from probity_observer.sensors import strace

from .test_policy import DEMO


def hx(text: str) -> str:
    return "".join(f"\\x{byte:02x}" for byte in text.encode())


V4 = "{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}"
V6 = ("{sa_family=AF_INET6, sin6_port=htons(%d), sin6_flowinfo=htonl(0), "
      "inet_pton(AF_INET6, \"%s\", &sin6_addr), sin6_scope_id=0}")


def test_sockaddr_reads_inet_and_inet6_and_ignores_the_rest() -> None:
    assert network_effects.sockaddr(V4 % (443, hx("10.20.0.5"))) == ("10.20.0.5", 443)
    assert network_effects.sockaddr(V6 % (80, hx("::1"))) == ("::1", 80)
    assert network_effects.sockaddr("{sa_family=AF_UNIX, sun_path=\"x\"}") is None
    assert network_effects.sockaddr(None) is None
    assert network_effects.sockaddr("{sa_family=AF_INET, sin_port=htons(1)}") is None
    assert network_effects.sockaddr(V4 % (1, hx("not-an-ip"))) is None


def test_declare_retains_the_file_and_judge_names_each_rule(tmp_path) -> None:
    source = tmp_path / "policy.yaml"
    source.write_bytes(DEMO)
    assert network_effects.declare(None, tmp_path) is None
    declared = network_effects.declare(source, tmp_path)
    assert declared["rules"][0] == "audited"
    assert (tmp_path / network_effects.POLICY_FILE).read_bytes() == DEMO
    psql = {"status": "complete", "chain": [{"pid": 7, "path": "/usr/bin/psql", "sha256": "a" * 64}]}
    found = strace.Effects(parents={8: 7, 9: 3})
    found.events = [
        strace.Event("exec", 7, 1.0, exe="/usr/bin/psql", identity=psql),
        strace.Event("connect", 8, 1.1, address=V4 % (5432, hx("10.20.1.1"))),
        strace.Event("connect", 7, 1.2, address=V4 % (5432, hx("10.99.1.1"))),
        strace.Event("exec", 3, 1.3, exe="/usr/local/bin/python3.12"),
        strace.Event("connect", 9, 1.4, address=V4 % (443, hx("151.101.0.223"))),
        strace.Event("exec", 4, 1.5, exe="/x", identity={"status": "failed", "reason": "r"}),
        strace.Event("connect", 4, 1.6, address=V4 % (443, hx("1.1.1.1"))),
        strace.Event("connect", 4, 1.7, address="{sa_family=AF_UNIX, sun_path=\"s\"}"),
    ]
    judged = network_effects.judge(tmp_path, found)
    assert [(item["pid"], item["decision"], item["rules"], item["binary_source"])
            for item in judged] == [
        (8, "allowed", ["internal"], "identity"),
        (7, "denied", [], "identity"),
        (9, "unknown", ["pypi"], "trace"),
        (4, "denied", [], "identity_failed")]
    assert judged[2]["reason"] == "host_not_observed" and judged[2]["binaries"] == [
        "/usr/local/bin/python3.12"]
