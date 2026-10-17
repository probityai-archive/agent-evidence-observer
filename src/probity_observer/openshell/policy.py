"""The OpenShell sandbox policy (NemoClaw's ``openclaw-sandbox.yaml`` format) as a declaration.

A policy file is the launch policy the operator declares. :func:`load` parses it strictly
(duplicate keys, YAML aliases, non-ASCII values and unknown top-level fields are refused, as
OpenShell itself refuses them), checks ``network_policies`` against NemoClaw's vendored
``network-policy.schema.json``, and returns the canonical form. :func:`declaration` is what a
launch record carries, so the launch digest (``launchPolicySha256`` for a brokered workload,
``launch_sha256`` for a launched agent) covers the exact policy.

:func:`match` decides which rule allows one network effect, with OpenShell's documented
semantics (``docs/how-it-works/policies/schema.mdx`` and ``network-rules.mdx`` at v0.1.4): a
rule allows every listed binary, or any of its ancestors, to reach every listed endpoint;
hosts match case-insensitively by ``.``-separated labels; binary paths match by
``/``-separated segments; overlapping rules all apply; and on a ``rest`` endpoint a matching
deny rule blocks an ``enforce`` request whatever the allow rules say. Request inspection for
``websocket``, ``graphql``, ``mcp`` and ``json-rpc`` is not modelled here, and a match on
such an endpoint says so (``l7: not_evaluated``) instead of guessing.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Iterable, Sequence

from ..crypto import canonical, digest
from . import pins

DECLARATION_SCHEMA = "probity-network-policy-declaration/v1"
DIGEST_DOMAIN = "probity-openshell-policy-v1"
TOP_LEVEL = frozenset({"version", "filesystem_policy", "landlock", "process", "network_policies",
                       "network_middlewares"})
PRESET_KEYS = frozenset({"preset", "network_policies"})
READ_ONLY = frozenset({"GET", "HEAD", "OPTIONS"})
READ_WRITE = READ_ONLY | {"POST", "PUT", "PATCH"}
INSPECTED = ("rest", "websocket", "graphql", "mcp", "json-rpc")


class PolicyError(ValueError):
    """The policy file is not one OpenShell would load, or is outside this reader's profile."""


def _loader():
    import yaml

    class StrictLoader(yaml.SafeLoader):
        """SafeLoader that refuses duplicate mapping keys and aliases."""

    def construct_mapping(loader, node, deep=False):
        keys = set()
        for key_node, _ in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in keys:
                raise PolicyError(f"duplicate key {key!r} at line {key_node.start_mark.line + 1}")
            keys.add(key)
        return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)

    def refuse_alias(self):
        raise PolicyError("YAML aliases are not accepted in a policy")

    StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping)
    StrictLoader.compose_alias = refuse_alias  # type: ignore[method-assign]
    original = StrictLoader.compose_node

    def compose_node(self, parent, index):
        if self.check_event(yaml.events.AliasEvent):
            refuse_alias(self)
        return original(self, parent, index)

    StrictLoader.compose_node = compose_node  # type: ignore[method-assign]
    return yaml, StrictLoader


def parse_yaml(data: bytes) -> dict[str, Any]:
    """Parse policy bytes into a mapping under the strict profile."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise PolicyError("policy text must be UTF-8") from None
    yaml, loader = _loader()
    try:
        document = yaml.load(text, Loader=loader)  # noqa: S506 (strict SafeLoader)
    except yaml.YAMLError as error:
        raise PolicyError(f"policy is not valid YAML: {error}") from None
    if not isinstance(document, dict):
        raise PolicyError("policy must be a mapping")
    return document


def network_schema() -> dict[str, Any]:
    """NemoClaw's ``network-policy.schema.json``, checked against its pinned digest."""
    data = resources.files(__package__).joinpath(
        "vendor/nemoclaw/network-policy.schema.json").read_bytes()
    if hashlib.sha256(data).hexdigest() != pins.NEMOCLAW_NETWORK_SCHEMA_SHA256:
        raise PolicyError("vendored network policy schema differs from its pin")
    return json.loads(data)


def _validate_network(network: Any) -> None:
    import jsonschema

    try:
        jsonschema.Draft202012Validator(network_schema()).validate(network)
    except jsonschema.ValidationError as error:
        where = "/".join(str(part) for part in error.absolute_path) or "network_policies"
        raise PolicyError(f"network_policies/{where}: {error.message}") from None


@dataclass(frozen=True)
class Endpoint:
    host: str | None
    ports: tuple[int, ...]
    protocol: str | None
    enforcement: str
    access: str | None
    allow: tuple[dict[str, Any], ...]
    deny: tuple[dict[str, Any], ...]
    allowed_ips: tuple[str, ...]
    path: str | None


@dataclass(frozen=True)
class Rule:
    key: str
    name: str
    endpoints: tuple[Endpoint, ...]
    binaries: tuple[str, ...]


@dataclass(frozen=True)
class Policy:
    """A loaded policy: the canonical document, its digests and its network rules."""

    document: dict[str, Any]
    source_sha256: str
    canonical_sha256: str
    rules: tuple[Rule, ...]

    def canonical_bytes(self) -> bytes:
        return canonical(self.document)


def _endpoint(raw: dict[str, Any]) -> Endpoint:
    ports = tuple(raw["ports"]) if "ports" in raw else (raw["port"],)
    return Endpoint(
        host=raw.get("host"), ports=ports, protocol=raw.get("protocol"),
        enforcement=raw.get("enforcement", "audit"), access=raw.get("access"),
        allow=tuple(item["allow"] for item in raw.get("rules", [])),
        deny=tuple(raw.get("deny_rules", [])), allowed_ips=tuple(raw.get("allowed_ips", [])),
        path=raw.get("path"))


def from_document(document: dict[str, Any], source: bytes) -> Policy:
    """Check a parsed document and build the policy."""
    extra = set(document) - TOP_LEVEL
    if extra:
        raise PolicyError(f"unknown top-level field(s): {', '.join(sorted(extra))}")
    if document.get("version") != 1:
        raise PolicyError("policy version must be 1")
    network = document.get("network_policies", {})
    if network:
        _validate_network(network)
    try:
        encoded = canonical(document)
    except ValueError as error:
        raise PolicyError(f"policy is outside the canonical profile: {error}") from None
    rules = tuple(Rule(key, entry.get("name", key),
                       tuple(_endpoint(item) for item in entry["endpoints"]),
                       tuple(item["path"] for item in entry["binaries"]))
                  for key, entry in sorted(network.items()))
    return Policy(document=json.loads(encoded), source_sha256=hashlib.sha256(source).hexdigest(),
                  canonical_sha256=digest(DIGEST_DOMAIN, document), rules=rules)


def load(source: Path | bytes) -> Policy:
    """Load one complete policy file (the form ``openshell sandbox create --policy`` takes)."""
    data = Path(source).read_bytes() if isinstance(source, Path) else source
    return from_document(parse_yaml(data), data)


def compose(base: bytes, *presets: bytes) -> Policy:
    """Base policy plus NemoClaw presets: each preset adds rules and may not redefine one."""
    document = parse_yaml(base)
    network = dict(document.get("network_policies") or {})
    for preset in presets:
        extra = parse_yaml(preset)
        if set(extra) - PRESET_KEYS:
            raise PolicyError("a preset may carry only 'preset' and 'network_policies'")
        for key, entry in (extra.get("network_policies") or {}).items():
            if key in network:
                raise PolicyError(f"preset redefines rule {key!r}")
            network[key] = entry
    document["network_policies"] = network
    joined = b"\n---\n".join((base, *presets))
    return from_document(document, joined)


def declaration(policy: Policy) -> dict[str, Any]:
    """The record a launch carries: digests, the canonical document and the rule names."""
    return {
        "schema_version": DECLARATION_SCHEMA,
        "format": "openshell-sandbox-policy/v1",
        "schema": {"source": f"NVIDIA/NemoClaw@{pins.NEMOCLAW_COMMIT}:"
                             "schemas/network-policy.schema.json",
                   "sha256": pins.NEMOCLAW_NETWORK_SCHEMA_SHA256},
        "source_sha256": policy.source_sha256,
        "canonical_sha256": policy.canonical_sha256,
        "rules": [rule.key for rule in policy.rules],
        "document": policy.document,
    }


def _label_glob(pattern: str, label: str) -> bool:
    """One host label: ``*`` matches any characters inside the label."""
    regex = "[^.]*".join(re.escape(part) for part in pattern.split("*"))
    return re.fullmatch(regex, label) is not None


def host_matches(pattern: str, host: str) -> bool:
    """Endpoint host glob: ``*`` stays inside a label, a whole first-label ``**`` spans labels."""
    pattern, host = pattern.lower().rstrip("."), host.lower().rstrip(".")
    want, got = pattern.split("."), host.split(".")
    if want and want[0] == "**":
        tail = want[1:]
        return len(got) > len(tail) and all(
            _label_glob(item, label) for item, label in zip(tail, got[len(got) - len(tail):]))
    return len(want) == len(got) and all(_label_glob(item, label)
                                         for item, label in zip(want, got))


def _glob_segment(segment: str, separator: str) -> str:
    """One path segment: ``*`` and ``?`` never cross ``separator``; ``[...]`` is a class."""
    sep = re.escape(separator)
    out, index = "", 0
    while index < len(segment):
        char = segment[index]
        if char == "*":
            out += f"[^{sep}]*"
            while index + 1 < len(segment) and segment[index + 1] == "*":
                index += 1
        elif char == "?":
            out += f"[^{sep}]"
        elif char == "[":
            close = segment.find("]", index + 1)
            if close == -1:
                out += re.escape(char)
            else:
                body = segment[index + 1:close]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out += f"[{body}]"
                index = close
        else:
            out += re.escape(char)
        index += 1
    return out


def path_matches(pattern: str, path: str, separator: str = "/") -> bool:
    """Binary and request-path globs: whole-segment ``**`` spans one or more segments."""
    want = pattern.split(separator)
    got = path.split(separator)
    return _match_segments(want, got, separator)


def _match_segments(want: list[str], got: list[str], separator: str) -> bool:
    if not want:
        return not got
    head = want[0]
    if head == "**":
        return any(_match_segments(want[1:], got[count:], separator)
                   for count in range(1, len(got) + 1))
    if not got:
        return False
    if re.fullmatch(_glob_segment(head, separator), got[0]) is None:
        return False
    return _match_segments(want[1:], got[1:], separator)


def endpoint_path_matches(pattern: str | None, path: str | None) -> bool:
    """The endpoint ``path`` selector: empty, ``**`` and ``/**`` match all; ``/v1/**`` matches
    ``/v1`` and below; elsewhere ``*`` also matches ``/``."""
    if not pattern or pattern in ("**", "/**") or path is None:
        return True
    if pattern.endswith("/**"):
        prefix = pattern[:-3]
        return path == prefix or path.startswith(prefix + "/")
    regex = "".join(".*" if char == "*" else "." if char == "?" else re.escape(char)
                    for char in pattern)
    return re.fullmatch(regex, path) is not None


def _ip_allowed(endpoint: Endpoint, ip: str | None) -> bool:
    if not endpoint.allowed_ips:
        return True
    if ip is None:
        return False
    address = ipaddress.ip_address(ip)
    return any(address in ipaddress.ip_network(item, strict=False) for item in endpoint.allowed_ips)


def _destination(endpoint: Endpoint, host: str | None, ip: str | None, port: int) -> bool:
    if port not in endpoint.ports:
        return False
    if endpoint.host is None:
        return ip is not None and _ip_allowed(endpoint, ip)
    named = host if host is not None else ip
    if named is None or not host_matches(endpoint.host, named):
        return False
    return _ip_allowed(endpoint, ip)


def _method_matches(want: str, method: str) -> bool:
    return want == "*" or want.upper() == method.upper()


def _rest_allows(endpoint: Endpoint, method: str, path: str) -> tuple[bool, bool]:
    """(allowed by the allow side, blocked by a deny rule) for one REST request."""
    if endpoint.access == "full":
        allowed = True
    elif endpoint.access == "read-only":
        allowed = method.upper() in READ_ONLY
    elif endpoint.access == "read-write":
        allowed = method.upper() in READ_WRITE
    else:
        allowed = any(_method_matches(item["method"], method) and path_matches(item["path"], path)
                      for item in endpoint.allow)
    denied = any(_method_matches(item["method"], method) and path_matches(item["path"], path)
                 for item in endpoint.deny)
    return allowed, denied


@dataclass(frozen=True)
class Effect:
    """One network effect: destination, the executable chain that made it, and the request."""

    port: int
    binaries: tuple[str, ...]
    host: str | None = None
    ip: str | None = None
    method: str | None = None
    path: str | None = None


@dataclass(frozen=True)
class Match:
    decision: str
    rules: tuple[str, ...]
    l7: str
    reason: str

    def record(self) -> dict[str, Any]:
        return {"decision": self.decision, "rules": list(self.rules), "l7": self.l7,
                "reason": self.reason}


def match(policy: Policy, effect: Effect) -> Match:
    """Which rules allow ``effect``; ``denied`` with the reason when none does."""
    reached: list[tuple[Rule, Endpoint]] = []
    for rule in policy.rules:
        if not any(path_matches(pattern, binary) for pattern in rule.binaries
                   for binary in effect.binaries):
            continue
        for endpoint in rule.endpoints:
            if (_destination(endpoint, effect.host, effect.ip, effect.port)
                    and endpoint_path_matches(endpoint.path, effect.path)):
                reached.append((rule, endpoint))
    if not reached:
        reason = "no_matching_rule" if effect.host or effect.ip else "destination_unknown"
        return Match("denied", (), "not_applicable", reason)
    names = tuple(sorted({rule.key for rule, _ in reached}))
    inspected = [(rule, endpoint) for rule, endpoint in reached if endpoint.protocol in INSPECTED]
    if not inspected:
        return Match("allowed", names, "not_applicable", "l4_rule_matched")
    if effect.method is None:
        return Match("allowed", names, "not_evaluated", "request_not_observed")
    if any(endpoint.protocol != "rest" for _, endpoint in inspected):
        return Match("allowed", names, "not_evaluated", "protocol_not_modelled")
    allowing = sorted({rule.key for rule, endpoint in inspected
                       if _rest_allows(endpoint, effect.method, effect.path or "/")[0]})
    blocking = sorted({rule.key for rule, endpoint in inspected
                       if endpoint.enforcement == "enforce"
                       and _rest_allows(endpoint, effect.method, effect.path or "/")[1]})
    if blocking:
        return Match("denied", tuple(blocking), "evaluated", "deny_rule_matched")
    if not allowing:
        enforced = any(endpoint.enforcement == "enforce" for _, endpoint in inspected)
        return Match("denied" if enforced else "allowed_audit", names, "evaluated",
                     "no_allow_rule_matched")
    return Match("allowed", tuple(allowing), "evaluated", "rest_rule_matched")


def match_all(policy: Policy, effects: Iterable[Effect]) -> list[dict[str, Any]]:
    return [match(policy, effect).record() for effect in effects]


def binaries_chain(chain: Sequence[dict[str, Any]]) -> tuple[str, ...]:
    """The executable paths of an identity chain (process first, then its ancestors)."""
    return tuple(link["path"] for link in chain if link.get("path"))
