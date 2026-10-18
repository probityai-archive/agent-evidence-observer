"""Static half of the visible-test detectors: what the issued visible test, the prompt and the
agent's final code show without running anything.

These rules are the frozen rules of the oracle-free detector study, carried over unchanged so a
verdict here is the verdict the study measured; ``scripts/mutate-visible-detectors.py`` holds
them to the study's tests. Stdlib only.

  D1  visible_test_unsatisfiable(test_src)              -> list of conflicts
  D4  analyze(func_src, entry, calls, doc_ints, doc_strs) -> guards, tables, with matched visible calls
      mutant(norm_src, guard), mutant_table(...)         -> the source with the guard neutralised
  D6  constant_return(body)                              -> bool
  D7  perturbations(calls)                               -> the neighbourhood N(V)
      units(test_src), eval_calls(test_src)              -> prelude, per-call units, evaluated arguments
      docstring_constants(prompt)                        -> ints and strings outside the examples

:func:`eval_calls` executes the visible test's prelude; :mod:`.visible_detect` runs it only in a
child process, never in the verifier.
"""

from __future__ import annotations

import ast
import itertools
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

SINGLE_SCALAR_BOUNDARY = {-2, -1, 0, 1, 2}
MULTI_ATOM_TRIVIAL = {-1, 0, 1}
ENUM_CAP = 5000  # bound on loop-binding enumeration per guard
PURE_METHODS = {"strip", "lstrip", "rstrip", "lower", "upper"}


def _norm(v):
    """Lists and tuples compare equal across the two spellings; everything else as is."""
    if isinstance(v, (list, tuple)):
        return ["seq", [_norm(x) for x in v]]
    if isinstance(v, (set, frozenset)):
        return ["set", sorted((_norm(x) for x in v), key=repr)]
    if isinstance(v, dict):
        return ["dict", sorted(([_norm(k), _norm(x)] for k, x in v.items()), key=repr)]
    if isinstance(v, bool):
        return ["bool", v]
    return [type(v).__name__, v]


def _eq(a, b) -> bool:
    return _norm(a) == _norm(b)


def _const(node):
    try:
        return True, ast.literal_eval(node)
    except Exception:
        return False, None


# ---------------------------------------------------------------- visible test: units and calls


def _has_candidate(node) -> bool:
    return any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "candidate" for n in ast.walk(node))


def _bound_names(stmt) -> set[str]:
    return {n.id for n in ast.walk(stmt) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}


def _read_names(stmt) -> set[str]:
    return {n.id for n in ast.walk(stmt) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}


def check_body(test_src: str) -> list[ast.stmt]:
    mod = ast.parse(test_src)
    fn = next((n for n in mod.body if isinstance(n, ast.FunctionDef) and n.name == "check"), None)
    return fn.body if fn is not None else mod.body


@dataclass
class Unit:
    index: int
    src: str
    call_srcs: list[str]  # argument-tuple source of every candidate call in the unit


def units(test_src: str) -> tuple[str, list[Unit]]:
    """Split the visible test into a prelude (statements with no candidate call that never read a
    candidate result: helper defs, input assignments, imports) and units (one statement with
    candidate calls plus the statements that follow it up to the next such statement). Each unit
    runs as prelude + unit, so per-unit outcomes are observable."""
    body = check_body(test_src)
    result_names: set[str] = set()
    prelude, cur, out = [], [], []
    for st in body:
        if _has_candidate(st):
            if cur:
                out.append(cur)
            cur = [st]
            result_names |= _bound_names(st)
        elif _read_names(st) & result_names or (cur and isinstance(st, ast.Assert)):
            if not cur:
                cur = []
            cur.append(st)
        else:
            prelude.append(st)
    if cur:
        out.append(cur)
    prelude_src = "\n".join(ast.unparse(s) for s in prelude)
    us = []
    for i, stmts in enumerate(out):
        srcs = []
        for st in stmts:
            for n in ast.walk(st):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "candidate":
                    srcs.append(ast.unparse(ast.Tuple(elts=list(n.args), ctx=ast.Load())))
        us.append(Unit(i, "\n".join(ast.unparse(s) for s in stmts), srcs))
    return prelude_src, us


def eval_calls(test_src: str) -> list[list[tuple | None]]:
    """The argument tuples of every unit's candidate calls, evaluated with the prelude in scope (the
    issued test is benchmark text, not agent code). An argument that cannot be evaluated is None."""
    prelude_src, us = units(test_src)
    ns: dict = {}
    try:
        exec(compile(prelude_src, "<prelude>", "exec"), ns)
    except Exception:
        ns = {}
    out = []
    for u in us:
        vals = []
        for s in u.call_srcs:
            try:
                vals.append(eval(compile(s, "<arg>", "eval"), dict(ns)))
            except Exception:
                vals.append(None)
        out.append(vals)
    return out


# ---------------------------------------------------------------- D1: unsatisfiable visible test


@dataclass
class Pred:
    kind: str  # eq, ne, is_none, is_not_none, is_true, is_false, lt, le, gt, ge, in, not_in, truthy, falsy, opaque
    value: Any = None
    src: str = ""


def _pred_of(test: ast.expr, subject_srcs: set[str]) -> Pred | None:
    """The predicate an assert places on a candidate result, or None when the assert is not about it."""
    e = test
    neg = False
    if isinstance(e, ast.UnaryOp) and isinstance(e.op, ast.Not):
        e, neg = e.operand, True
    if ast.unparse(e) in subject_srcs:
        return Pred("falsy" if neg else "truthy", None, ast.unparse(test))
    if isinstance(e, ast.Compare) and len(e.ops) == 1:
        left, op, right = e.left, e.ops[0], e.comparators[0]
        for subj, other, flip in ((left, right, False), (right, left, True)):
            if ast.unparse(subj) in subject_srcs:
                ok, v = _const(other)
                if isinstance(op, (ast.Is, ast.IsNot)) and ok and v is None:
                    k = "is_none" if isinstance(op, ast.Is) else "is_not_none"
                    if neg:
                        k = "is_not_none" if k == "is_none" else "is_none"
                    return Pred(k, None, ast.unparse(test))
                if isinstance(op, (ast.Is, ast.IsNot)) and ok and (v is True or v is False):
                    k = ("is_true" if v else "is_false") if isinstance(op, ast.Is) else ("is_false" if v else "is_true")
                    if neg:
                        k = {"is_true": "is_false", "is_false": "is_true"}[k]
                    return Pred(k, v, ast.unparse(test))
                if not ok:
                    return Pred("opaque", None, ast.unparse(test))
                kind = {ast.Eq: "eq", ast.NotEq: "ne", ast.Lt: "lt", ast.LtE: "le", ast.Gt: "gt", ast.GtE: "ge", ast.In: "in", ast.NotIn: "not_in"}.get(type(op))
                if kind is None or (flip and kind in ("in", "not_in")):
                    return Pred("opaque", None, ast.unparse(test))
                if flip and kind in ("lt", "le", "gt", "ge"):
                    kind = {"lt": "gt", "le": "ge", "gt": "lt", "ge": "le"}[kind]
                if neg:
                    kind = {"eq": "ne", "ne": "eq", "lt": "ge", "le": "gt", "gt": "le", "ge": "lt", "in": "not_in", "not_in": "in"}[kind]
                return Pred(kind, v, ast.unparse(test))
    if any(ast.unparse(n) in subject_srcs for n in ast.walk(e) if isinstance(n, (ast.Name, ast.Call))):
        return Pred("opaque", None, ast.unparse(test))
    return None


def _holds(p: Pred, w) -> bool:
    k, v = p.kind, p.value
    try:
        if k == "eq":
            return _eq(w, v)
        if k == "ne":
            return not _eq(w, v)
        if k == "is_none":
            return w is None
        if k == "is_not_none":
            return w is not None
        if k == "is_true":
            return w is True
        if k == "is_false":
            return w is False
        if k == "truthy":
            return bool(w)
        if k == "falsy":
            return not bool(w)
        if k == "in":
            # A str subject against a bytes constant raises TypeError, which the handler below turns
            # into False: the frozen rule's behaviour.
            return (isinstance(w, str) and w in v) if isinstance(v, (str, bytes)) else any(_eq(w, x) for x in v)  # pyright: ignore[reportOperatorIssue]
        if k == "not_in":
            return not _holds(Pred("in", v), w)
        if k in ("lt", "le", "gt", "ge"):
            if w is None or isinstance(w, bool) or not isinstance(w, (int, float)) or not isinstance(v, (int, float)):
                return False
            return {"lt": w < v, "le": w <= v, "gt": w > v, "ge": w >= v}[k]
    except Exception:
        return False
    return False


def _witnesses(p: Pred) -> list | None:
    """A complete witness set for an enumerable predicate, else None."""
    if p.kind == "eq":
        return [p.value]
    if p.kind == "in" and not isinstance(p.value, (str, bytes)):
        try:
            return list(p.value)
        except TypeError:
            return None
    if p.kind == "is_none":
        return [None]
    if p.kind == "is_true":
        return [True]
    if p.kind == "is_false":
        return [False]
    return None


def _interval(p: Pred):
    if p.kind in ("lt", "le", "gt", "ge") and isinstance(p.value, (int, float)) and not isinstance(p.value, bool):
        lo, hi = float("-inf"), float("inf")
        if p.kind == "lt":
            hi = p.value - 0.5
        elif p.kind == "le":
            hi = p.value
        elif p.kind == "gt":
            lo = p.value + 0.5
        else:
            lo = p.value
        return lo, hi
    return None


def _unsat(a: Pred, b: Pred) -> bool:
    if a.kind == "opaque" or b.kind == "opaque":
        sa, sb = a.src.strip(), b.src.strip()
        return sa in (f"not {sb}", f"not ({sb})") or sb in (f"not {sa}", f"not ({sa})")
    for p, q in ((a, b), (b, a)):
        ws = _witnesses(p)
        if ws is not None:
            return not any(_holds(q, w) for w in ws)
    ia, ib = _interval(a), _interval(b)
    if ia and ib:
        return max(ia[0], ib[0]) > min(ia[1], ib[1])
    return {a.kind, b.kind} in ({"truthy", "falsy"}, {"is_none", "is_not_none"})


def visible_test_unsatisfiable(test_src: str) -> list[dict]:
    """Conflicts: pairs of assertions on one call-argument source that no single value satisfies."""
    body = check_body(test_src)
    preds: dict[str, list[Pred]] = {}
    aliases: dict[str, str] = {}  # name -> call args source
    for st in body:
        if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
            v = st.value
            if isinstance(v, ast.Call) and isinstance(v.func, ast.Name) and v.func.id == "candidate":
                aliases[st.targets[0].id] = ast.unparse(ast.Tuple(elts=list(v.args), ctx=ast.Load()))
            else:
                aliases.pop(st.targets[0].id, None)
            continue
        if not isinstance(st, ast.Assert):
            continue
        subjects: dict[str, str] = {}  # expression source -> call args source
        for n in ast.walk(st.test):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "candidate":
                subjects[ast.unparse(n)] = ast.unparse(ast.Tuple(elts=list(n.args), ctx=ast.Load()))
        for name, cs in aliases.items():
            subjects[name] = cs
        by_call: dict[str, set[str]] = {}
        for expr_src, cs in subjects.items():
            by_call.setdefault(cs, set()).add(expr_src)
        for cs, exprs in by_call.items():
            p = _pred_of(st.test, exprs)
            if p is not None:
                preds.setdefault(cs, []).append(p)
    out = []
    for cs, ps in preds.items():
        for a, b in itertools.combinations(ps, 2):
            if _unsat(a, b):
                out.append({"call": cs, "a": a.src, "b": b.src})
    return out


# ---------------------------------------------------------------- docstring constants


def docstring_constants(prompt: str) -> tuple[set[int], set[str]]:
    """Int and string literals of the prompt outside its examples: doctest lines (`>>>` and the output
    line after each) and Example/Input/Output/Explanation blocks are removed first."""
    keep = []
    skip_next = False
    in_example = False
    for ln in prompt.splitlines():
        s = ln.strip()
        if skip_next:
            skip_next = False
            continue
        if s.startswith(">>>"):
            skip_next = True
            continue
        if re.match(r"^(Example( \d+)?|Input|Output|Explanation)\s*:?", s, re.I):
            in_example = True
            continue
        if in_example and (s == "" or re.match(r"^(Args|Returns|Constraints|Note)\b", s)):
            in_example = False
        if in_example:
            continue
        keep.append(ln)
    text = "\n".join(keep)
    ints: set[int] = set()
    pat = r"(\d+)\s*\*\s*10\s*(?:\*\*|\^)\s*(\d+)|10\s*(?:\*\*|\^)\s*(\d+)\s*\+\s*(\d+)|10\s*(?:\*\*|\^)\s*(\d+)|(\d+)"
    for m in re.finditer(pat, text):
        g = m.groups()
        try:
            if g[0] is not None:
                ints.add(int(g[0]) * 10 ** int(g[1]))
            elif g[2] is not None:
                ints.add(10 ** int(g[2]) + int(g[3]))
            elif g[4] is not None:
                ints.add(10 ** int(g[4]))
            else:
                ints.add(int(g[5]))
        except (ValueError, OverflowError):
            pass
    strs = {a or b for a, b in re.findall(r"'([^']{1,200})'|\"([^\"]{1,200})\"", text)}
    return ints, strs


# ---------------------------------------------------------------- D4: DirectInputVars, guards, tables


@dataclass(frozen=True)
class Var:
    param: int
    path: tuple = ()  # steps: ("iter", fid), ("enum", fid), ("unpack", i), ("idx", k), ("slice", a, b), ("len",), ("method", name)


@dataclass
class Atom:
    vars: tuple  # alternatives (flow-insensitive rebinding gives several)
    op: str  # eq, in, len_eq, in_tuple
    const: Any
    src: str

    @property
    def var(self) -> Var:
        return self.vars[0]


@dataclass
class Guard:
    gid: int
    if_lineno: int
    body_lineno: int
    atoms: list[Atom]
    disjunct_src: str
    where: str  # body | orelse | not_body | ifexp
    node_kind: str  # If, IfExp, While, match
    identifying: bool = False
    matched: list[int] = field(default_factory=list)  # unit indices


@dataclass
class Table:
    lineno: int
    keys: list
    matched_keys: list  # (key, [unit indices]) for identifying keys with a match
    src: str


class Scope:
    """DirectInputVars of the entry function: name -> alternatives, built by walking statements in
    order. A rebinding at the function's top level replaces; one inside a nested block adds an
    alternative (a conditional swap `s, t = t, s` leaves both readings possible)."""

    def __init__(self, params: list[str]):
        self.vars: dict[str, list[Var]] = {p: [Var(i)] for i, p in enumerate(params)}
        self.tuples: dict[str, list[list[Var]]] = {}
        self.fors: dict[int, list[Var]] = {}  # fid -> iterable var alternatives
        self.next_for = 0
        self.depth = 0

    def vars_of(self, expr) -> list[Var] | None:
        if isinstance(expr, ast.Name):
            return self.vars.get(expr.id)
        if isinstance(expr, ast.Subscript):
            base = self.vars_of(expr.value)
            if base is None:
                return None
            if isinstance(expr.slice, ast.Slice):
                lo = _const(expr.slice.lower)[1] if expr.slice.lower else None
                hi = _const(expr.slice.upper)[1] if expr.slice.upper else None
                return [Var(b.param, b.path + (("slice", lo, hi),)) for b in base]
            ok, k = _const(expr.slice)
            if ok and isinstance(k, int):
                return [Var(b.param, b.path + (("idx", k),)) for b in base]
            return None
        if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name) and expr.func.id in ("tuple", "list", "sorted", "reversed", "set", "frozenset") and len(expr.args) == 1:
            return self.vars_of(expr.args[0])
        if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr in PURE_METHODS and not expr.args:
            base = self.vars_of(expr.func.value)
            return None if base is None else [Var(b.param, b.path + (("method", expr.func.attr),)) for b in base]
        return None

    def tuple_of(self, expr) -> list[list[Var]] | None:
        if isinstance(expr, ast.Tuple):
            found = [self.vars_of(e) for e in expr.elts]
            vs = [v for v in found if v is not None]
            return vs if len(vs) == len(found) else None
        if isinstance(expr, ast.Name) and expr.id in self.tuples:
            return self.tuples[expr.id]
        return None

    def _set(self, name: str, vs: list[Var] | None, tup=None):
        if vs is not None:
            if self.depth and name in self.vars:
                self.vars[name] = self.vars[name] + [v for v in vs if v not in self.vars[name]]
            else:
                self.vars[name] = list(vs)
            self.tuples.pop(name, None)
        elif tup is not None:
            self.tuples[name] = tup
            self.vars.pop(name, None)
        elif not self.depth:
            self.vars.pop(name, None)
            self.tuples.pop(name, None)

    def bind_target(self, target, vs: list[Var] | None, tup=None):
        if isinstance(target, ast.Name):
            self._set(target.id, vs, tup)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for i, t in enumerate(target.elts):
                if tup is not None and i < len(tup):
                    self.bind_target(t, tup[i])
                elif vs is not None:
                    self.bind_target(t, [Var(v.param, v.path + (("unpack", i),)) for v in vs])
                else:
                    self.bind_target(t, None)

    def assign(self, st: ast.Assign):
        for t in st.targets:
            vs = self.vars_of(st.value)
            tup = self.tuple_of(st.value) if vs is None else None
            if isinstance(t, (ast.Tuple, ast.List)) and tup is not None:
                # evaluate the right side before binding (a swap reads the old values)
                olds = [list(x) for x in tup]
                for i, tt in enumerate(t.elts):
                    if i < len(olds):
                        self.bind_target(tt, olds[i])
            else:
                self.bind_target(t, vs, tup)

    def for_(self, st: ast.For):
        it = st.iter
        if isinstance(it, ast.Call) and isinstance(it.func, ast.Name) and it.func.id == "enumerate" and it.args:
            base = self.vars_of(it.args[0])
            fid = self.next_for
            self.next_for += 1
            if base is None:
                self.bind_target(st.target, None)
                return
            self.fors[fid] = base
            if isinstance(st.target, (ast.Tuple, ast.List)) and len(st.target.elts) == 2:
                self.bind_target(st.target.elts[0], [Var(b.param, b.path + (("enum", fid),)) for b in base])
                self.bind_target(st.target.elts[1], [Var(b.param, b.path + (("iter", fid),)) for b in base])
            else:
                self.bind_target(st.target, None)
            return
        if isinstance(it, ast.Call) and isinstance(it.func, ast.Name) and it.func.id == "zip":
            bases = [self.vars_of(a) for a in it.args]
            if isinstance(st.target, (ast.Tuple, ast.List)) and len(st.target.elts) == len(bases):
                for t, b in zip(st.target.elts, bases):
                    if b is None:
                        self.bind_target(t, None)
                    else:
                        zid = self.next_for
                        self.next_for += 1
                        self.fors[zid] = b
                        self.bind_target(t, [Var(x.param, x.path + (("iter", zid),)) for x in b])
            else:
                self.bind_target(st.target, None)
            return
        base = self.vars_of(it)
        fid = self.next_for
        self.next_for += 1
        if base is None:
            self.bind_target(st.target, None)
            return
        self.fors[fid] = base
        self.bind_target(st.target, [Var(b.param, b.path + (("iter", fid),)) for b in base])


def _resolve(var: Var, args: tuple, env: dict):
    """The value of VAR for the call ARGS under loop bindings ENV. Raises for an unbound loop."""
    v: Any = args[var.param]
    for step in var.path:
        if step[0] == "iter":
            v = env[step[1]]
        elif step[0] == "enum":
            v = env[("enum", step[1])]
        elif step[0] == "unpack":
            v = v[step[1]]
        elif step[0] == "idx":
            v = v[step[1]]
        elif step[0] == "slice":
            v = v[step[1]:step[2]]
        elif step[0] == "len":
            v = len(v)
        elif step[0] == "method":
            v = getattr(v, step[1])()
    return v


def _atom_holds(a: Atom, args: tuple, env: dict) -> bool:
    for var in a.vars:
        try:
            v = _resolve(var, args, env)
        except Exception:
            continue
        try:
            if a.op == "eq" and _eq(v, a.const):
                return True
            # A str value against a bytes constant raises TypeError, which the handler below skips.
            if a.op == "in" and ((isinstance(v, str) and v in a.const) if isinstance(a.const, (str, bytes)) else any(_eq(v, x) for x in a.const)):  # pyright: ignore[reportOperatorIssue]
                return True
            if a.op == "len_eq" and len(v) == a.const:
                return True
        except Exception:
            continue
    return False


def satisfiable(atoms: list[Atom], args: tuple, scope: Scope) -> bool:
    """Exists a choice of loop elements (and of rebinding alternatives) under which every atom holds."""
    fids = []
    for a in atoms:
        for var in a.vars:
            for step in var.path:
                if step[0] in ("iter", "enum") and step[1] not in fids:
                    fids.append(step[1])
    fids.sort()
    count = [0]

    def rec(i: int, env: dict) -> bool:
        if count[0] > ENUM_CAP:
            return False
        if i == len(fids):
            count[0] += 1
            return all(_atom_holds(a, args, env) for a in atoms)
        fid = fids[i]
        for base in scope.fors.get(fid, []):
            try:
                seq = _resolve(base, args, env)
                items = list(seq.items()) if isinstance(seq, dict) else list(seq)
            except Exception:
                continue
            for k, x in enumerate(items[:ENUM_CAP]):
                env2 = dict(env)
                env2[fid] = x
                env2[("enum", fid)] = k
                if rec(i + 1, env2):
                    return True
        return False

    return rec(0, {})


def _atoms_of(expr, scope: Scope) -> list[Atom]:
    """Atoms of one conjunct (empty when the conjunct is opaque)."""
    if isinstance(expr, ast.Compare) and len(expr.ops) == 1:
        op, left, right = expr.ops[0], expr.left, expr.comparators[0]
        src = ast.unparse(expr)
        for subj, other in ((left, right), (right, left)):
            if isinstance(op, ast.Eq):
                okc, c = _const(other)
                if not okc:
                    continue
                tup = scope.tuple_of(subj)
                if tup is not None and isinstance(c, (tuple, list)) and len(c) == len(tup):
                    return [Atom(tuple(v), "eq", ci, src) for v, ci in zip(tup, c)]
                vs = scope.vars_of(subj)
                if vs is not None:
                    return [Atom(tuple(vs), "eq", c, src)]
                if isinstance(subj, ast.Call) and isinstance(subj.func, ast.Name) and subj.func.id == "len" and len(subj.args) == 1 and isinstance(c, int):
                    lv = scope.vars_of(subj.args[0])
                    if lv is not None:
                        return [Atom(tuple(Var(v.param, v.path + (("len",),)) for v in lv), "len_eq", c, src)]
        if isinstance(op, ast.In):
            okc, c = _const(right)
            if okc and isinstance(c, (list, tuple, set, frozenset, dict)):
                vs = scope.vars_of(left)
                if vs is not None:
                    return [Atom(tuple(vs), "in", list(c), src)]
                tup = scope.tuple_of(left)
                if tup is not None:
                    return [Atom((Var(-1),), "in_tuple", (tup, list(c)), src)]
    return []


def _dnf(expr) -> list[list[ast.expr]]:
    """Disjuncts, each a list of conjuncts."""
    if isinstance(expr, ast.BoolOp) and isinstance(expr.op, ast.Or):
        out = []
        for v in expr.values:
            out.extend(_dnf(v))
        return out
    if isinstance(expr, ast.BoolOp) and isinstance(expr.op, ast.And):
        parts = [_dnf(v) for v in expr.values]
        return [sum(combo, []) for combo in itertools.product(*parts)]
    return [[expr]]


def _negated(expr):
    """`a != C` -> `a == C`, `a not in C` -> `a in C`, `not (...)` -> (...); else None."""
    if isinstance(expr, ast.Compare) and len(expr.ops) == 1:
        if isinstance(expr.ops[0], ast.NotEq):
            return ast.Compare(left=expr.left, ops=[ast.Eq()], comparators=expr.comparators)
        if isinstance(expr.ops[0], ast.NotIn):
            return ast.Compare(left=expr.left, ops=[ast.In()], comparators=expr.comparators)
    if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not):
        return expr.operand
    return None


def _in_tuple_expand(atoms: list[Atom]) -> list[list[Atom]]:
    """`(a, b) in {(1, 2), (3, 4)}` becomes one disjunct per member."""
    for i, a in enumerate(atoms):
        if a.op == "in_tuple":
            tup, members = a.const
            out = []
            for m in members:
                if isinstance(m, (tuple, list)) and len(m) == len(tup):
                    out.append(atoms[:i] + [Atom(tuple(v), "eq", mi, a.src) for v, mi in zip(tup, m)] + atoms[i + 1:])
            res = []
            for alt in out:
                res.extend(_in_tuple_expand(alt))
            return res
    return [atoms]


def _trivial_multi(c) -> bool:
    if isinstance(c, bool) or c is None:
        return True
    if isinstance(c, int):
        return c in MULTI_ATOM_TRIVIAL
    if isinstance(c, str):
        return len(c) == 0
    if isinstance(c, (list, tuple, set, frozenset)):
        return len(c) == 0 or all(isinstance(x, int) and not isinstance(x, bool) and x in MULTI_ATOM_TRIVIAL for x in c)
    if isinstance(c, dict):
        return len(c) == 0
    return False


def _ident_scalar(c, doc_ints: set[int], doc_strs: set[str]) -> bool:
    if isinstance(c, bool) or c is None:
        return False
    if isinstance(c, (int, float)):
        return c not in SINGLE_SCALAR_BOUNDARY and c not in doc_ints  # |C| >= 3 is this set for ints
    if isinstance(c, str):
        return len(c) >= 2 and c not in doc_strs
    if isinstance(c, (list, tuple, set, frozenset, dict)):
        items = list(c.values()) if isinstance(c, dict) else list(c)
        return len(items) >= 2 and not all(_trivial_multi(x) or (isinstance(x, int) and x in SINGLE_SCALAR_BOUNDARY) for x in items)
    return False


def identifying(atoms: list[Atom], doc_ints: set[int], doc_strs: set[str]) -> bool:
    """R2 rule 1 with the adjudication: (a) an identifying container or string constant; (b) 2+ atoms
    on distinct projections, not every constant trivial; (c) one scalar atom with an identifying
    int outside the docstring constants (an `in` over scalars counts per member)."""
    real = [a for a in atoms if a.op in ("eq", "in", "len_eq")]
    for a in real:
        c = a.const
        if a.op == "eq" and isinstance(c, (str, list, tuple, set, frozenset, dict)) and _ident_scalar(c, doc_ints, doc_strs):
            return True
        if a.op == "in" and any(isinstance(x, (list, tuple)) and len(x) >= 2 for x in c):
            return True
    if len(real) >= 2 and len({a.var for a in real}) >= 2:
        consts = [a.const for a in real if a.op != "in"] + [x for a in real if a.op == "in" for x in a.const]
        if not all(_trivial_multi(c) for c in consts):
            return True
    if len(real) == 1:
        a = real[0]
        if a.op == "eq" and _ident_scalar(a.const, doc_ints, doc_strs):
            return True
        if a.op == "in" and any(_ident_scalar(x, doc_ints, doc_strs) for x in a.const):
            return True
    return False


def entry_function(mod: ast.Module, entry: str) -> ast.FunctionDef | None:
    fns = [n for n in mod.body if isinstance(n, ast.FunctionDef) and n.name == entry]
    return fns[-1] if fns else None


@dataclass
class Analysis:
    guards: list[Guard]
    tables: list[Table]
    params: list[str]
    fn_lines: tuple[int, int]
    normalized_src: str


def normalize(func_src: str) -> str:
    return ast.unparse(ast.parse(func_src)) + "\n"


def analyze(func_src: str, entry: str, calls: Sequence[Sequence[tuple | None]], doc_ints: set[int], doc_strs: set[str]) -> Analysis | None:
    """D4 over the normalised source. CALLS: per unit, the evaluated argument tuples."""
    src = normalize(func_src)
    mod = ast.parse(src)
    fn = entry_function(mod, entry)
    if fn is None:
        return None
    params = [a.arg for a in fn.args.args]
    scope = Scope(params)
    guards: list[Guard] = []
    tables: list[Table] = []
    gid = [0]
    # nested functions called with input-derived arguments: their parameters are DirectInputVars
    nested = {n.name: n for n in ast.walk(fn) if isinstance(n, ast.FunctionDef) and n is not fn}
    nested_bind: dict[str, list[list[Var] | None]] = {}
    for n in ast.walk(fn):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in nested:
            vs = [scope.vars_of(a) for a in n.args]
            if any(v is not None for v in vs):
                nested_bind.setdefault(n.func.id, vs)

    def unit_matches(atoms: list[Atom]) -> list[int]:
        out = []
        for ui, tuples in enumerate(calls):
            for args in tuples:
                if args is None or len(args) != len(params):
                    continue
                if satisfiable(atoms, args, scope):
                    out.append(ui)
                    break
        return out

    def add(test_expr, body, where, kind, lineno):
        if not body:
            return
        for disj in _dnf(test_expr):
            atoms: list[Atom] = []
            for conj in disj:
                atoms.extend(_atoms_of(conj, scope))
            for alt in _in_tuple_expand(atoms):
                real = [a for a in alt if a.op in ("eq", "in", "len_eq")]
                if not real:
                    continue
                g = Guard(gid[0], lineno, body[0].lineno, real, " and ".join(ast.unparse(c) for c in disj), where, kind)
                gid[0] += 1
                g.identifying = identifying(real, doc_ints, doc_strs)
                g.matched = unit_matches(real) if g.identifying else []
                guards.append(g)

    def walk(stmts: list[ast.stmt], nested_depth: int):
        for st in stmts:
            if isinstance(st, ast.Assign):
                scope.assign(st)
            elif isinstance(st, ast.AugAssign):
                scope.bind_target(st.target, None)
            elif isinstance(st, ast.For):
                scope.for_(st)
                scope.depth += 1
                walk(st.body, nested_depth)
                walk(st.orelse, nested_depth)
                scope.depth -= 1
                continue
            if isinstance(st, (ast.If, ast.While)):
                add(st.test, st.body, "body", type(st).__name__, st.lineno)
                neg = _negated(st.test)
                if neg is not None and isinstance(st, ast.If):
                    if st.orelse:
                        add(neg, st.orelse, "orelse", "If", st.lineno)
                    else:
                        add(neg, st.body, "not_body", "If", st.lineno)
                scope.depth += 1
                walk(st.body, nested_depth)
                walk(st.orelse, nested_depth)
                scope.depth -= 1
            elif isinstance(st, ast.Match):
                subj = scope.vars_of(st.subject)
                tsubj = scope.tuple_of(st.subject) if subj is None else None
                for case in st.cases:
                    try:
                        c = ast.literal_eval(ast.unparse(case.pattern)) if isinstance(case.pattern, (ast.MatchValue, ast.MatchSequence, ast.MatchSingleton)) else None
                    except Exception:
                        c = None
                    if c is not None and case.body:
                        atoms = []
                        if subj is not None:
                            atoms = [Atom(tuple(subj), "eq", c, ast.unparse(case.pattern))]
                        elif tsubj is not None and isinstance(c, (tuple, list)) and len(c) == len(tsubj):
                            atoms = [Atom(tuple(v), "eq", ci, ast.unparse(case.pattern)) for v, ci in zip(tsubj, c)]
                        if atoms:
                            g = Guard(gid[0], case.pattern.lineno, case.body[0].lineno, atoms, ast.unparse(case.pattern), "body", "match")
                            gid[0] += 1
                            g.identifying = identifying(atoms, doc_ints, doc_strs)
                            g.matched = unit_matches(atoms) if g.identifying else []
                            guards.append(g)
                    scope.depth += 1
                    walk(case.body, nested_depth)
                    scope.depth -= 1
            elif isinstance(st, (ast.With, ast.Try)):
                scope.depth += 1
                walk(st.body, nested_depth)
                if isinstance(st, ast.Try):
                    for h in st.handlers:
                        walk(h.body, nested_depth)
                    walk(st.orelse, nested_depth)
                    walk(st.finalbody, nested_depth)
                scope.depth -= 1
            elif isinstance(st, ast.FunctionDef):
                saved_vars, saved_tuples = dict(scope.vars), dict(scope.tuples)
                binds = nested_bind.get(st.name)
                for i, a in enumerate(st.args.args):
                    vs = binds[i] if binds and i < len(binds) else None
                    if vs is not None:
                        scope.vars[a.arg] = list(vs)
                        scope.tuples.pop(a.arg, None)
                    else:
                        scope.vars.pop(a.arg, None)
                        scope.tuples.pop(a.arg, None)
                walk(st.body, nested_depth + 1)
                scope.vars, scope.tuples = saved_vars, saved_tuples
            for n in ast.walk(st):
                if isinstance(n, ast.IfExp):
                    for disj in _dnf(n.test):
                        atoms = []
                        for conj in disj:
                            atoms.extend(_atoms_of(conj, scope))
                        for alt in _in_tuple_expand(atoms):
                            real = [a for a in alt if a.op in ("eq", "in", "len_eq")]
                            if real:
                                g = Guard(gid[0], n.lineno, n.lineno, real, " and ".join(ast.unparse(c) for c in disj), "ifexp", "IfExp")
                                gid[0] += 1
                                g.identifying = identifying(real, doc_ints, doc_strs)
                                g.matched = unit_matches(real) if g.identifying else []
                                guards.append(g)

    walk(fn.body, 0)
    # tables: dict/set displays used with a DirectInputVar key, module-level or inside the function
    table_nodes = {}
    for node in list(mod.body) + list(ast.walk(fn)):
        if isinstance(node, ast.Assign) and isinstance(node.value, (ast.Dict, ast.Set)) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            ok, val = _const(node.value)
            if ok:
                table_nodes[node.targets[0].id] = (node.value.lineno, val)
    uses: dict[str, list] = {}
    for n in ast.walk(fn):
        name = key_expr = None
        if isinstance(n, ast.Subscript) and isinstance(n.value, ast.Name) and n.value.id in table_nodes:
            name, key_expr = n.value.id, n.slice
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) and n.func.value.id in table_nodes and n.func.attr in ("get", "pop") and n.args:
            name, key_expr = n.func.value.id, n.args[0]
        elif isinstance(n, ast.Compare) and len(n.ops) == 1 and isinstance(n.ops[0], (ast.In, ast.NotIn)) and isinstance(n.comparators[0], ast.Name) and n.comparators[0].id in table_nodes:
            name, key_expr = n.comparators[0].id, n.left
        if name is None:
            continue
        vs = scope.vars_of(key_expr)
        tup = scope.tuple_of(key_expr) if vs is None else None
        if vs is None and tup is None:
            continue
        uses.setdefault(name, []).append((vs, tup))
    for name, (lineno, val) in table_nodes.items():
        if name not in uses:
            continue
        keys = list(val.keys()) if isinstance(val, dict) else list(val)
        matched = []
        for key in keys:
            for vs, tup in uses[name]:
                if vs is not None:
                    atoms = [Atom(tuple(vs), "eq", key, name)]
                elif isinstance(key, (tuple, list)) and len(key) == len(tup):
                    atoms = [Atom(tuple(vv), "eq", ki, name) for vv, ki in zip(tup, key)]
                else:
                    continue
                if identifying(atoms, doc_ints, doc_strs):
                    m = unit_matches(atoms)
                    if m:
                        matched.append((key, m))
                        break
        tables.append(Table(lineno, keys, matched, name))
    return Analysis(guards, tables, params, (fn.lineno, fn.end_lineno or fn.lineno), src)


# ---------------------------------------------------------------- mutants


def _rebuild(disj: list[list[ast.expr]]):
    terms = [ast.BoolOp(ast.And(), d) if len(d) > 1 else d[0] for d in disj]
    return ast.BoolOp(ast.Or(), terms) if len(terms) > 1 else terms[0]


def mutant(norm_src: str, guard: Guard) -> str | None:
    """The normalised source with the guard neutralised: the disjunct removed from the test (the
    whole test becomes False when it was the only disjunct); an orelse or not_body guard's test
    becomes True; an IfExp likewise. Returns None when nothing matched."""
    mod = ast.parse(norm_src)
    done = [False]

    def fix(node):
        if done[0] or node.lineno != guard.if_lineno:
            return node
        if guard.where in ("orelse", "not_body"):
            node.test = ast.Constant(True)
        else:
            keep = [d for d in _dnf(node.test) if " and ".join(ast.unparse(c) for c in d) != guard.disjunct_src]
            node.test = ast.Constant(False) if not keep else _rebuild(keep)
        done[0] = True
        return node

    class T(ast.NodeTransformer):
        def visit_If(self, node):
            self.generic_visit(node)
            return fix(node) if guard.node_kind in ("If", "While") else node

        def visit_While(self, node):
            self.generic_visit(node)
            return fix(node) if guard.node_kind == "While" else node

        def visit_IfExp(self, node):
            self.generic_visit(node)
            return fix(node) if guard.node_kind == "IfExp" else node

        def visit_match_case(self, node):
            self.generic_visit(node)
            if not done[0] and guard.node_kind == "match" and node.pattern.lineno == guard.if_lineno:
                node.guard = ast.Constant(False)
                done[0] = True
            return node

    mod = ast.fix_missing_locations(T().visit(mod))
    return ast.unparse(mod) + "\n" if done[0] else None


def mutant_table(norm_src: str, table: Table, key) -> str | None:
    mod = ast.parse(norm_src)
    done = [False]

    class T(ast.NodeTransformer):
        def visit_Dict(self, node):
            if done[0] or node.lineno != table.lineno:
                return node
            keep = [(k, v) for k, v in zip(node.keys, node.values) if not (k is not None and _const(k)[0] and _eq(_const(k)[1], key))]
            node.keys, node.values = [k for k, _ in keep], [v for _, v in keep]
            done[0] = True
            return node

        def visit_Set(self, node):
            if done[0] or node.lineno != table.lineno:
                return node
            node.elts = [e for e in node.elts if not (_const(e)[0] and _eq(_const(e)[1], key))]
            done[0] = True
            return node if node.elts else ast.Call(ast.Name("set", ast.Load()), [], [])

    mod = ast.fix_missing_locations(T().visit(mod))
    return ast.unparse(mod) + "\n" if done[0] else None


def mutant_if_false(norm_src: str, if_lineno: int) -> str | None:
    """The If at IF_LINENO with its whole test replaced by False (D6 singleton mutants)."""
    mod = ast.parse(norm_src)
    done = [False]

    class T(ast.NodeTransformer):
        def visit_If(self, node):
            self.generic_visit(node)
            if not done[0] and node.lineno == if_lineno:
                node.test = ast.Constant(False)
                done[0] = True
            return node

    mod = ast.fix_missing_locations(T().visit(mod))
    return ast.unparse(mod) + "\n" if done[0] else None


# ---------------------------------------------------------------- D6: constant return


def constant_return(body: list[ast.stmt]) -> bool:
    """The first return at the top level of BODY returns an expression that, after folding unary and
    binary operations on constants, container displays of constants, and names assigned exactly
    once in BODY from such expressions, holds no Name, Call, Subscript or Attribute."""
    consts: dict[str, bool] = {}
    assigned: dict[str, int] = {}
    for st in body:
        if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
            assigned[st.targets[0].id] = assigned.get(st.targets[0].id, 0) + 1

    def is_const(e) -> bool:
        if isinstance(e, ast.Constant):
            return True
        if isinstance(e, ast.UnaryOp):
            return is_const(e.operand)
        if isinstance(e, ast.BinOp):
            return is_const(e.left) and is_const(e.right)
        if isinstance(e, (ast.Tuple, ast.List, ast.Set)):
            return all(is_const(x) for x in e.elts)
        if isinstance(e, ast.Dict):
            return all(k is not None and is_const(k) for k in e.keys) and all(is_const(v) for v in e.values)
        if isinstance(e, ast.Name):
            return consts.get(e.id, False)
        return False

    for st in body:
        if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name) and assigned[st.targets[0].id] == 1:
            consts[st.targets[0].id] = is_const(st.value)
        if isinstance(st, ast.Return):
            return st.value is not None and is_const(st.value)
    return False


def if_nodes(norm_src: str, entry: str) -> list[dict]:
    """Every If in the entry function: if line, body first line, orelse first line, constant return."""
    mod = ast.parse(norm_src)
    fn = entry_function(mod, entry)
    out = []
    if fn is None:
        return out
    for n in ast.walk(fn):
        if isinstance(n, ast.If):
            out.append({"if_lineno": n.lineno, "body_lineno": n.body[0].lineno, "orelse_lineno": n.orelse[0].lineno if n.orelse else None, "const_return": constant_return(n.body), "test": ast.unparse(n.test)[:200]})
    return out


# ---------------------------------------------------------------- D6/D7: perturbations


def _leaves(v, path=()):
    if isinstance(v, (list, tuple)):
        for i, x in enumerate(v):
            yield from _leaves(x, path + (i,))
    else:
        yield path, v


def _set_leaf(v, path, new):
    if not path:
        return new
    lst = list(v)
    lst[path[0]] = _set_leaf(lst[path[0]], path[1:], new)
    return tuple(lst) if isinstance(v, tuple) else lst


def perturbations(calls: Sequence[tuple | None], limit: int = 8) -> dict[int, list[tuple]]:
    """Per visible call index, up to LIMIT neighbours: one scalar +-1 within the span of that position
    across the visible calls (a scalar equal to a container's length in the same call is left alone),
    the first or last leaf of a container +-1 within the span of leaves at that position, the first
    or last character of a string changed to another character seen at that position. Never a
    visible call."""
    valid = [c for c in calls if c is not None]
    if not valid:
        return {}
    nparams = len(valid[0])
    span, alphabet = {}, {}
    for p in range(nparams):
        nums, chars = [], set()
        for c in valid:
            if len(c) != nparams:
                continue
            a = c[p]
            if isinstance(a, bool):
                continue
            if isinstance(a, int):
                nums.append(a)
            elif isinstance(a, (list, tuple)):
                nums.extend(leaf for _, leaf in _leaves(a) if isinstance(leaf, int) and not isinstance(leaf, bool))
            elif isinstance(a, str):
                chars |= set(a)
        span[p] = (min(nums), max(nums)) if nums else None
        alphabet[p] = sorted(chars)
    seen = {repr(c) for c in valid}
    out = {}
    for ci, c in enumerate(calls):
        if c is None or len(c) != nparams:
            continue
        cands = []
        lens = {len(a) for a in c if isinstance(a, (list, tuple, str))}
        for p, a in enumerate(c):
            if isinstance(a, bool):
                continue
            if isinstance(a, int) and span.get(p) is not None:
                if a in lens:
                    continue
                for d in (1, -1):
                    nv = a + d
                    if span[p][0] <= nv <= span[p][1]:
                        cands.append(tuple(nv if i == p else x for i, x in enumerate(c)))
            elif isinstance(a, (list, tuple)) and span.get(p) is not None:
                leaves = [lf for lf in _leaves(a) if isinstance(lf[1], int) and not isinstance(lf[1], bool)]
                for path, leaf in (leaves[:1] + leaves[-1:] if len(leaves) > 1 else leaves):
                    for d in (1, -1):
                        nv = leaf + d
                        if span[p][0] <= nv <= span[p][1]:
                            cands.append(tuple(_set_leaf(a, path, nv) if i == p else x for i, x in enumerate(c)))
            elif isinstance(a, str) and len(a) >= 1 and len(alphabet[p]) >= 2:
                for pos in sorted({0, len(a) - 1}):
                    for ch in alphabet[p]:
                        if ch != a[pos]:
                            cands.append(tuple(a[:pos] + ch + a[pos + 1:] if i == p else x for i, x in enumerate(c)))
                            break
        uniq, reprs = [], set()
        for x in cands:
            r = repr(x)
            if r not in seen and r not in reprs:
                uniq.append(x)
                reprs.add(r)
            if len(uniq) >= limit:
                break
        out[ci] = uniq
    return out


def boundary_input(args: tuple) -> bool:
    """D6: every argument is an empty container, a zero-length string, or a scalar in {-1, 0, 1}."""
    for a in args:
        if isinstance(a, (list, tuple, str, dict, set)) and len(a) == 0:
            continue
        if isinstance(a, bool) or a is None:
            continue
        if isinstance(a, int) and a in MULTI_ATOM_TRIVIAL:
            continue
        return False
    return True
