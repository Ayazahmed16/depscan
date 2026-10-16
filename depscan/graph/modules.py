"""Find a project's Python modules and read their imports with the `ast` module.

Nothing is imported or executed: files are only parsed. This is *import-level* analysis. It knows which module
imports which, not which functions are called.
"""
from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "env", ".env", "node_modules", "__pycache__", "site-packages",
             "build", "dist", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "htmlcov"}
STDLIB = set(sys.stdlib_module_names)

# Django settings whose string values name code that Django loads. Not Python imports, but real ones.
SETTINGS_NAMES = {"INSTALLED_APPS", "MIDDLEWARE", "AUTHENTICATION_BACKENDS", "ROOT_URLCONF",
                  "WSGI_APPLICATION", "ASGI_APPLICATION", "SESSION_ENGINE"}
_DOTTED = re.compile(r"^[A-Za-z_]\w*(\.[A-Za-z_]\w*)*$")


@dataclass
class ImportRef:
    candidates: list[str]          # dotted names, most specific first: `from a.b import c` -> ["a.b.c", "a.b"]
    kind: str                      # import | from | dynamic | settings
    lineno: int
    typing_only: bool = False      # inside `if TYPE_CHECKING:` (never executed at run time)


@dataclass
class PyModule:
    name: str                      # dotted module name, e.g. "accounts.views"
    path: str                      # path relative to the project root, forward slashes
    package: str                   # the package this module sits in (itself, for an __init__.py)
    is_init: bool = False
    parsed: bool = True
    imports: list[ImportRef] = field(default_factory=list)
    table: dict[str, tuple[str, str | None]] = field(default_factory=dict)   # local name -> (module, symbol)
    tree: ast.Module | None = None
    settings: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class ProjectIndex:
    root: Path
    modules: dict[str, PyModule]
    unparsable: list[str]          # relative paths that could not be parsed (syntax errors, odd encodings)


def _is_type_checking(test: ast.expr) -> bool:
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or \
           (isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING")


def _relative_base(package: str, level: int, module: str | None) -> str:
    """Resolve `from ..x import y` (level 2) inside `package`."""
    parts = package.split(".") if package else []
    if level > 1:
        parts = parts[: len(parts) - (level - 1)] if len(parts) >= level - 1 else []
    base = ".".join(parts)
    return ".".join(p for p in (base, module) if p)


class _Visitor(ast.NodeVisitor):
    def __init__(self, mod: PyModule):
        self.mod = mod
        self.typing_depth = 0

    def visit_If(self, node: ast.If) -> None:
        if _is_type_checking(node.test):
            self.typing_depth += 1
            for n in node.body:
                self.visit(n)
            self.typing_depth -= 1
            for n in node.orelse:
                self.visit(n)
        else:
            self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            self.mod.imports.append(ImportRef([a.name], "import", node.lineno, self.typing_depth > 0))
            if a.asname:
                self.mod.table[a.asname] = (a.name, None)
            else:
                top = a.name.split(".")[0]
                self.mod.table.setdefault(top, (top, None))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        base = _relative_base(self.mod.package, node.level, node.module) if node.level else (node.module or "")
        for a in node.names:
            if a.name == "*":
                self.mod.imports.append(ImportRef([base], "from", node.lineno, self.typing_depth > 0))
                continue
            cands = [f"{base}.{a.name}" if base else a.name, base] if base else [a.name]
            self.mod.imports.append(ImportRef(cands, "from", node.lineno, self.typing_depth > 0))
            self.mod.table[a.asname or a.name] = (base, a.name)

    def visit_Call(self, node: ast.Call) -> None:
        # importlib.import_module("x.y") / __import__("x"): only a string literal can be followed
        f = node.func
        name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else None
        if name in ("import_module", "__import__") and node.args and isinstance(node.args[0], ast.Constant) \
                and isinstance(node.args[0].value, str) and not node.args[0].value.startswith("."):
            self.mod.imports.append(ImportRef([node.args[0].value], "dynamic", node.lineno, self.typing_depth > 0))
        self.generic_visit(node)


def _settings_refs(tree: ast.Module) -> dict[str, list[str]]:
    """Dotted strings assigned to Django settings that name code Django will load."""
    out: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, (ast.AugAssign, ast.AnnAssign)) else []
        value = getattr(node, "value", None)
        for t in targets:
            if isinstance(t, ast.Name) and t.id in SETTINGS_NAMES and value is not None:
                strings = [c.value for c in ast.walk(value) if isinstance(c, ast.Constant) and isinstance(c.value, str) and _DOTTED.match(c.value)]
                out.setdefault(t.id, []).extend(strings)
    return out


def discover(root: Path) -> ProjectIndex:
    root = Path(root).resolve()
    # source roots: a `src/` folder holding packages is the import root for what is inside it
    src = root / "src"
    roots = [src] if src.is_dir() and not (root / "manage.py").exists() and any(src.glob("*/__init__.py")) else [root]
    modules: dict[str, PyModule] = {}
    unparsable: list[str] = []
    for base in roots:
        for path in sorted(base.rglob("*.py")):
            rel_parts = path.relative_to(base).parts
            if any(p in SKIP_DIRS or p.endswith(".egg-info") for p in rel_parts[:-1]):
                continue
            parts = list(rel_parts)
            parts[-1] = parts[-1][:-3]
            is_init = parts[-1] == "__init__"
            if is_init:
                parts = parts[:-1]
            if not parts:
                continue
            name = ".".join(parts)
            package = name if is_init else ".".join(parts[:-1])
            mod = PyModule(name=name, path=path.relative_to(root).as_posix(), package=package, is_init=is_init)
            try:
                mod.tree = ast.parse(path.read_text("utf-8-sig"), filename=str(path))
            except (SyntaxError, UnicodeDecodeError, ValueError):
                mod.parsed = False
                unparsable.append(mod.path)
            else:
                _Visitor(mod).visit(mod.tree)
                mod.settings = _settings_refs(mod.tree)
            modules[name] = mod
    return ProjectIndex(root, modules, unparsable)


@dataclass(frozen=True)
class Target:
    kind: str    # module (in this project) | external (a third-party top-level name) | stdlib | unresolved
    name: str


def resolve(index: ProjectIndex, candidates: list[str]) -> Target:
    """Where does an import point? Longest matching project module wins, else the top-level name decides."""
    for cand in candidates:
        parts = cand.split(".")
        for n in range(len(parts), 0, -1):
            prefix = ".".join(parts[:n])
            if prefix in index.modules:
                return Target("module", prefix)
    for cand in candidates:
        top = cand.split(".")[0]
        if not top:
            continue
        if top in STDLIB:
            return Target("stdlib", top)
        if any(m == top or m.startswith(top + ".") for m in index.modules):
            return Target("unresolved", top)   # looks like a project package we did not find a module for
        return Target("external", top)
    return Target("unresolved", "")
