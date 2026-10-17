"""Judge each traced network connect against the declared OpenShell network policy.

The trace sees a ``connect`` with an IP address and port, not the host name a policy rule
names, so a rule that names a host can only be confirmed for an IP literal. A connect that
only a host-named rule could allow is recorded as ``unknown`` (``host_not_observed``) with
those rules, rather than matched by guess; one that no rule could allow is ``denied``. The binary
chain is the connecting process's exec identity (its hashed ``/proc/<pid>/exe`` chain) when
the exec gate ran, and otherwise the executed paths of the process and its traced parents.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any

from ..openshell import policy as network_policy
from ..sensors import strace

POLICY_FILE = "network-policy.yaml"
_PORT = re.compile(r"sin6?_port=htons\((\d+)\)")
_V4 = re.compile(r'sin_addr=inet_addr\("((?:\\x[0-9a-f]{2})*)"\)')
_V6 = re.compile(r'inet_pton\(AF_INET6, "((?:\\x[0-9a-f]{2})*)"')


def declare(source: Path | None, run_dir: Path) -> dict[str, Any] | None:
    """Retain the policy file beside the launch record and return its declaration."""
    if source is None:
        return None
    data = Path(source).read_bytes()
    declared = network_policy.declaration(network_policy.load(data))
    (run_dir / POLICY_FILE).write_bytes(data)
    return declared


def sockaddr(text: str | None) -> tuple[str, int] | None:
    """``(ip, port)`` from a traced ``AF_INET``/``AF_INET6`` address, else ``None``."""
    if not text or "AF_INET" not in text:
        return None
    port = _PORT.search(text)
    raw = _V4.search(text) or _V6.search(text)
    if port is None or raw is None:
        return None
    try:
        ip = str(ipaddress.ip_address(strace.decode_hex(raw.group(1))))
    except ValueError:
        return None
    return ip, int(port.group(1))


def judge(run_dir: Path, found: strace.Effects) -> list[dict[str, Any]]:
    """One entry per traced connect: address, the binary chain, and the policy's decision."""
    loaded = network_policy.load(run_dir / POLICY_FILE)
    latest: dict[int, dict[str, Any]] = {}
    judged = []
    for event in found.events:
        if event.kind == "exec":
            latest[event.pid] = {"exe": event.exe, "identity": event.identity}
            continue
        if event.kind != "connect":
            continue
        parsed = sockaddr(event.address)
        if parsed is None:
            continue
        ip, port = parsed
        chain, source = _binary_chain(event.pid, latest, found.parents)
        decided = network_policy.match(loaded, network_policy.Effect(
            port=port, binaries=chain, ip=ip, host=ip)).record()
        if decided["decision"] == "denied":
            named = _named_candidates(loaded, port, chain)
            if named:
                decided = {"decision": "unknown", "rules": named, "l7": "not_applicable",
                           "reason": "host_not_observed"}
        judged.append({"pid": event.pid, "ip": ip, "port": port, "binaries": list(chain),
                       "binary_source": source, **decided})
    return judged


def _named_candidates(loaded: network_policy.Policy, port: int,
                      chain: tuple[str, ...]) -> list[str]:
    """Rules that would allow this binary chain and port for some host name."""
    names = set()
    for rule in loaded.rules:
        if not any(network_policy.path_matches(pattern, binary)
                   for pattern in rule.binaries for binary in chain):
            continue
        if any(endpoint.host is not None and port in endpoint.ports
               for endpoint in rule.endpoints):
            names.add(rule.key)
    return sorted(names)


def _binary_chain(pid: int, latest: dict[int, dict[str, Any]],
                  parents: dict[int, int]) -> tuple[tuple[str, ...], str]:
    """The nearest exec at or above ``pid``: its identity chain, or the traced exe paths."""
    paths, seen, here = [], set(), pid
    while here is not None and here not in seen:
        seen.add(here)
        current = latest.get(here)
        if current is not None:
            identity = current.get("identity")
            if identity is not None:
                if identity.get("status") == "complete":
                    return network_policy.binaries_chain(identity["chain"]), "identity"
                return (), "identity_failed"
            if current.get("exe"):
                paths.append(current["exe"])
        here = parents.get(here)
    return tuple(paths), "trace"
