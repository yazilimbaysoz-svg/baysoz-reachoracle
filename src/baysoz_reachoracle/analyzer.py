"""Deterministic AST reachability analysis.

Baysöz Labs <baysozlabs@proton.me> — baysoz-reachoracle.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from .models import Advisory, Evidence, Verdict

_TAINT_ROOTS = frozenset({"request", "ctx", "event"})
_TAINT_CALLS = frozenset(
    {
        "input",
        "builtins.input",
        "os.getenv",
        "os.environ.get",
        "sys.argv",
        "request.get_json",
        "request.get_data",
        "flask.request.get_json",
    }
)
_DYNAMIC_CALLS = frozenset(
    {"eval", "exec", "getattr", "__import__", "importlib.import_module", "builtins.eval"}
)
_GUARD_NAMES = frozenset({"TYPE_CHECKING", "__debug__"})


@dataclass(frozen=True, order=True)
class ReferenceEvent:
    path: str
    line: int
    column: int
    symbol: str
    snippet: str
    kind: str
    guarded: bool
    tainted: bool
    source_line: int = 0


@dataclass(frozen=True, order=True)
class DynamicEvent:
    path: str
    line: int
    column: int
    target: str
    snippet: str
    kind: str
    guarded: bool


@dataclass(frozen=True)
class ScanEvents:
    references: tuple[ReferenceEvent, ...]
    dynamics: tuple[DynamicEvent, ...]


@dataclass(frozen=True)
class SymbolVerdict:
    verdict: Verdict
    symbol: str
    tainted: bool
    message: str
    evidence: tuple[Evidence, ...]


def scan_source(source: str, path: str) -> ScanEvents:
    """Scan one Python source text and return deduplicated, sorted events."""
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        message = f"cannot parse {path}:{exc.lineno}: {exc.msg}"
        raise ValueError(message) from exc
    alias_collector = _collect_aliases()
    alias_collector.visit(tree)
    collector = _EventCollector(
        path=path, lines=source.splitlines(), aliases=alias_collector.aliases
    )
    collector.visit(tree)
    return ScanEvents(
        references=tuple(sorted(set(collector.references))),
        dynamics=tuple(sorted(set(collector.dynamics))),
    )


def scan_paths(paths: tuple[tuple[str, str], ...]) -> ScanEvents:
    """Merge events from (relative_path, source_text) pairs deterministically."""
    references: list[ReferenceEvent] = []
    dynamics: list[DynamicEvent] = []
    for path, source in paths:
        events = scan_source(source, path)
        references.extend(events.references)
        dynamics.extend(events.dynamics)
    return ScanEvents(
        references=tuple(sorted(set(references))),
        dynamics=tuple(sorted(set(dynamics))),
    )


class _collect_aliases(ast.NodeVisitor):
    """Collect every import alias keyed by its local binding name."""

    def __init__(self) -> None:
        self.aliases: dict[str, str] = {}

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            self.aliases[local] = alias.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if not node.module or node.level:
            return
        for alias in node.names:
            if alias.name == "*":
                continue
            local = alias.asname or alias.name
            self.aliases[local] = f"{node.module}.{alias.name}"


class _EventCollector(ast.NodeVisitor):
    """Collect symbol references, taint flows, and dynamic-dispatch events."""

    def __init__(self, *, path: str, lines: list[str], aliases: dict[str, str]) -> None:
        self.path = path
        self.lines = lines
        self.aliases = aliases
        self.references: list[ReferenceEvent] = []
        self.dynamics: list[DynamicEvent] = []
        self.guard_depth = 0
        self.taint_origins: dict[str, int] = {}

    def visit_If(self, node: ast.If) -> None:
        guarded = _is_inactive_test(node.test)
        if guarded:
            self.guard_depth += 1
            self._visit_all(node.body)
            self.guard_depth -= 1
        else:
            self._visit_all(node.body)
        self._visit_all(node.orelse)

    def _visit_all(self, nodes: list[ast.stmt]) -> None:
        for node in nodes:
            self.visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module and any(alias.name == "*" for alias in node.names):
            self._dynamic(node, node.module, "star-import")
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        tainted = self._is_tainted(node.value)
        for target in node.targets:
            self._bind_target(target, tainted, node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
            self._bind_target(node.target, self._is_tainted(node.value), node.value)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        self._bind_target(node.target, self._is_tainted(node.value), node.value)

    def visit_Call(self, node: ast.Call) -> None:
        for argument in node.args:
            self.visit(argument)
        for keyword in node.keywords:
            self.visit(keyword.value)
        resolved = self._resolve(node.func)
        if resolved is None and isinstance(node.func, ast.Name) and node.func.id in _DYNAMIC_CALLS:
            resolved = node.func.id
        if resolved in _DYNAMIC_CALLS:
            target = self._literal_string(node.args[0]) if node.args else ""
            self._dynamic(node, target, "dynamic-call")
        if resolved == "getattr":
            target = self._getattr_target(node)
            self._dynamic(node, target, "dynamic-call")
        if resolved is not None:
            tainted = any(self._is_tainted(argument) for argument in node.args)
            tainted = tainted or any(self._is_tainted(keyword.value) for keyword in node.keywords)
            self._reference(
                node,
                resolved,
                "call",
                tainted=tainted,
            )
        else:
            self.visit(node.func)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        resolved = self._resolve(node)
        if resolved is not None:
            self._reference(node, resolved, "attribute", tainted=self._is_tainted(node))
        else:
            self.visit(node.value)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        base = self._resolve(node.value)
        name = self._literal_string(node.slice)
        if base:
            target = f"{base}.{name}" if name else ""
            self._dynamic(node, target, "dynamic-subscript")
        self.visit(node.value)
        self.visit(node.slice)

    def visit_Name(self, node: ast.Name) -> None:
        resolved = self.aliases.get(node.id)
        if resolved is not None:
            self._reference(node, resolved, "name", tainted=self._is_tainted(node))

    def _resolve(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id)
        if isinstance(node, ast.Attribute):
            base = self._resolve(node.value)
            if base is not None:
                return f"{base}.{node.attr}"
        return None

    def _bind_target(self, target: ast.expr, tainted: bool, value: ast.expr) -> None:
        if isinstance(target, ast.Name):
            resolved = self._resolve(value)
            if resolved is not None:
                self.aliases[target.id] = resolved
            if tainted:
                self.taint_origins[target.id] = getattr(value, "lineno", 0)
            else:
                self.taint_origins.pop(target.id, None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._bind_target(element, tainted, value)

    def _is_tainted(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.taint_origins
        if isinstance(node, ast.Attribute):
            base = self._resolve(node.value)
            return _is_taint_path(base)
        if isinstance(node, ast.Subscript):
            base = self._resolve(node.value)
            return base in {"os.environ", "sys.argv"} or _is_taint_path(base)
        if isinstance(node, ast.Call):
            resolved = self._resolve(node.func)
            return bool(resolved and (resolved in _TAINT_CALLS or _is_taint_path(resolved)))
        if isinstance(node, ast.BoolOp):
            return any(self._is_tainted(value) for value in node.values)
        if isinstance(node, ast.IfExp):
            return self._is_tainted(node.body) or self._is_tainted(node.orelse)
        return False

    def _getattr_target(self, node: ast.Call) -> str:
        if len(node.args) < 2:
            return ""
        base = self._resolve(node.args[0])
        attribute = self._literal_string(node.args[1])
        if base and attribute:
            return f"{base}.{attribute}"
        return ""

    def _literal_string(self, node: ast.AST) -> str:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return ""

    def _snippet(self, node: ast.AST) -> str:
        line = getattr(node, "lineno", 0)
        if 0 < line <= len(self.lines):
            return self.lines[line - 1].strip()
        return ""

    def _reference(
        self,
        node: ast.AST,
        symbol: str,
        kind: str,
        *,
        tainted: bool,
    ) -> None:
        line = getattr(node, "lineno", 0)
        column = getattr(node, "col_offset", 0)
        source_line = 0
        if tainted and isinstance(node, ast.Call):
            candidates = [
                self.taint_origins.get(argument.id, 0)
                for argument in node.args
                if isinstance(argument, ast.Name)
            ]
            source_line = next((value for value in candidates if value), 0)
        self.references.append(
            ReferenceEvent(
                path=self.path,
                line=line,
                column=column,
                symbol=symbol,
                snippet=self._snippet(node),
                kind=kind,
                guarded=self.guard_depth > 0,
                tainted=tainted,
                source_line=source_line,
            )
        )

    def _dynamic(self, node: ast.AST, target: str, kind: str) -> None:
        self.dynamics.append(
            DynamicEvent(
                path=self.path,
                line=getattr(node, "lineno", 0),
                column=getattr(node, "col_offset", 0),
                target=target,
                snippet=self._snippet(node),
                kind=kind,
                guarded=self.guard_depth > 0,
            )
        )


def _is_taint_path(path: str | None) -> bool:
    if not path:
        return False
    root = path.split(".")[0]
    return root in _TAINT_ROOTS or ".request." in f"{path}."


def _is_inactive_test(node: ast.expr) -> bool:
    if isinstance(node, ast.Constant):
        return node.value is False or node.value == 0
    if isinstance(node, ast.Name):
        return node.id in _GUARD_NAMES
    if isinstance(node, ast.Attribute):
        return node.attr == "TYPE_CHECKING"
    return False


def _matches_symbol(symbol: str, advisory: Advisory) -> bool:
    for target in advisory.symbols:
        if symbol == target or symbol.startswith(f"{target}."):
            return True
    return False


def _matches_dynamic(event: DynamicEvent, advisory: Advisory) -> bool:
    if event.target:
        return (
            any(
                event.target == target or event.target.startswith(f"{target}.")
                for target in advisory.symbols
            )
            or event.target in advisory.modules
        )
    return False


def resolve_advisory(
    advisory: Advisory,
    events: ScanEvents,
    version_evidence: Evidence,
) -> SymbolVerdict:
    """Resolve a single advisory against collected events."""
    references = tuple(
        sorted(event for event in events.references if _matches_symbol(event.symbol, advisory))
    )
    dynamics = tuple(
        sorted(event for event in events.dynamics if _matches_dynamic(event, advisory))
    )
    if not references:
        for module in advisory.modules:
            if any(
                event.symbol.startswith(f"{module}.") or event.symbol == module
                for event in events.references
            ):
                targeted_locations = {(event.path, event.line, event.column) for event in dynamics}
                dynamics += tuple(
                    event
                    for event in events.dynamics
                    if not event.target
                    and (event.path, event.line, event.column) not in targeted_locations
                )
                break
    evidence: list[Evidence] = [version_evidence]
    evidence.extend(_reference_evidence(event) for event in references)
    evidence.extend(_dynamic_evidence(event) for event in dynamics)
    unique_evidence = tuple(
        sorted(set(evidence), key=lambda item: (item.path, item.line, item.column, item.kind))
    )
    tainted = any(event.tainted and event.kind == "call" for event in references)
    unguarded_refs = [event for event in references if not event.guarded]
    unguarded_dynamics = [event for event in dynamics if not event.guarded]
    symbol = advisory.symbols[0] if advisory.symbols else advisory.package
    if unguarded_refs:
        verdict = Verdict.REACHED
        location = f"{unguarded_refs[0].path}:{unguarded_refs[0].line}"
        message = f"Vulnerable symbol {symbol} is used at {location}"
        if tainted:
            message += " with attacker-controlled data"
    elif unguarded_dynamics:
        verdict = Verdict.UNRESOLVED
        location = f"{unguarded_dynamics[0].path}:{unguarded_dynamics[0].line}"
        message = f"Dynamic dispatch at {location} prevents proving {symbol} unreachable"
    elif references:
        verdict = Verdict.GUARDED
        message = f"Every use of {symbol} is behind a statically inactive guard"
    elif dynamics:
        verdict = Verdict.UNRESOLVED
        message = f"Dynamic dispatch may resolve to {symbol}; reachability cannot be proven offline"
    else:
        verdict = Verdict.NOT_REACHED
        message = f"No source reference to {symbol}; the vulnerable component is installed only"
    return SymbolVerdict(
        verdict=verdict, symbol=symbol, tainted=tainted, message=message, evidence=unique_evidence
    )


def _reference_evidence(event: ReferenceEvent) -> Evidence:
    snippet = f"{event.kind}: {event.symbol} | {event.snippet}"
    if event.tainted:
        snippet += " | attacker-controlled"
    return Evidence(event.path, event.line, event.column, snippet, event.kind)


def _dynamic_evidence(event: DynamicEvent) -> Evidence:
    target = event.target or "<unknown>"
    return Evidence(
        event.path,
        event.line,
        event.column,
        f"{event.kind}: {target} | {event.snippet}",
        event.kind,
    )
