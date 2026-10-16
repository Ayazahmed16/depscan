"""Build the exposure graph and work out how each vulnerable package can be reached.

    entry point  ->  module  ->  module ...  ->  third-party package  ->  package it depends on

Entry points, strongest first (the `level` of a package is the strongest one that reaches it):
    web      a URL route, the root urlconf, or middleware / authentication backends (they run on every request)
    startup  settings, INSTALLED_APPS and the code Django auto-loads from them, wsgi/asgi, manage.py
    command  management commands and background task modules
    test     test modules
    none     the package is imported somewhere, but no entry point reaches that code

LIMITATION below is shown in the UI and the docs next to every use of this graph. It is not fine print.
"""
from __future__ import annotations

import importlib.metadata
import re
from collections import deque
from pathlib import Path

import networkx as nx

from ..models import Dependency
from .django import expand_routes, module_routes
from .modules import ProjectIndex, PyModule, Target, discover, resolve

LIMITATION = (
    "Import-level analysis of a Django project (Python only). It shows which modules import which packages, and which of "
    "them a URL route, middleware, startup code or a command can reach. It does not follow function calls: an imported "
    "package may never actually be used, and code reached through getattr, settings values it cannot read, signals, "
    "templates or plugins can be missed. Package-to-package links (transitive dependencies) are known only from a poetry.lock."
)

LEVELS = ("web", "startup", "command", "test")
AUTOLOAD = ("models", "admin", "apps", "signals")   # submodules Django imports for every installed app

# import name -> PyPI distribution, for the common cases where they differ. The rest is matched by name,
# then through the installed distributions of this machine (importlib.metadata) if they happen to be installed.
IMPORT_ALIASES = {
    "yaml": "pyyaml", "PIL": "pillow", "cv2": "opencv-python", "sklearn": "scikit-learn", "bs4": "beautifulsoup4",
    "dateutil": "python-dateutil", "jwt": "pyjwt", "OpenSSL": "pyopenssl", "Crypto": "pycryptodome", "attr": "attrs",
    "dotenv": "python-dotenv", "magic": "python-magic", "MySQLdb": "mysqlclient", "psycopg2": "psycopg2-binary",
    "rest_framework": "djangorestframework", "corsheaders": "django-cors-headers", "django_filters": "django-filter",
    "jose": "python-jose", "ldap": "python-ldap", "serial": "pyserial", "usb": "pyusb", "zmq": "pyzmq", "nacl": "pynacl",
    "git": "gitpython", "docx": "python-docx", "pptx": "python-pptx", "markdown": "markdown", "gi": "pygobject",
    "skimage": "scikit-image", "cairo": "pycairo", "wx": "wxpython", "Image": "pillow", "pkg_resources": "setuptools",
    "google": "protobuf", "ruamel": "ruamel-yaml", "socks": "pysocks", "sentry_sdk": "sentry-sdk", "debug_toolbar": "django-debug-toolbar",
    "allauth": "django-allauth", "crispy_forms": "django-crispy-forms", "storages": "django-storages", "celery": "celery",
    "jinja2": "jinja2", "markupsafe": "markupsafe", "flask_cors": "flask-cors", "flask_sqlalchemy": "flask-sqlalchemy",
}


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


class ImportMapper:
    """Maps a top-level import name (`yaml`) to a declared dependency (`pyyaml`)."""

    def __init__(self, declared: set[str]):
        self.declared = declared
        try:
            self.installed = {k: [normalize(d) for d in v] for k, v in importlib.metadata.packages_distributions().items()}
        except Exception:  # an unusual environment must not stop the analysis
            self.installed = {}

    def dist(self, top: str) -> str | None:
        guesses = [normalize(IMPORT_ALIASES[top])] if top in IMPORT_ALIASES else []
        guesses.append(normalize(top))
        guesses += self.installed.get(top, [])
        return next((g for g in guesses if g in self.declared), None)


class ProjectAnalysis:
    def __init__(self, index: ProjectIndex, deps: list[Dependency]):
        self.index = index
        self.by_name = {d.name: d for d in deps if d.ecosystem == "PyPI"}
        self.requires_known = any(d.requires is not None for d in self.by_name.values())
        self.mapper = ImportMapper(set(self.by_name))
        self.graph = nx.DiGraph()
        self.labels: dict[str, str] = {}
        self.entry_level: dict[str, str] = {}
        self.unmapped: set[str] = set()
        self.warnings: list[str] = []
        self.django = False
        self._pred_cache: dict[str, dict[str, str | None]] = {}
        self._build()

    # ------------------------------------------------------------------ nodes and edges
    def _node(self, nid: str, label: str) -> str:
        if nid not in self.graph:
            self.graph.add_node(nid)
        self.labels.setdefault(nid, label)
        return nid

    def _entry(self, level: str, key: str, label: str) -> str:
        nid = f"entry:{level}:{key}"
        n = 2
        while nid in self.entry_level:        # two routes with the same text: keep both, tell them apart
            nid = f"entry:{level}:{key}#{n}"
            n += 1
        self.entry_level[nid] = level
        return self._node(nid, label)

    def _target_node(self, t: Target) -> str | None:
        if t.kind == "module":
            return self._node(f"mod:{t.name}", t.name)
        if t.kind == "external":
            dist = self.mapper.dist(t.name)
            if dist:
                return self._node(f"pkg:{dist}", dist)
            self.unmapped.add(t.name)
        return None

    def _edge(self, a: str | None, b: str | None, kind: str) -> None:
        if a and b and a != b:
            self.graph.add_edge(a, b, kind=kind)
            if a.startswith("entry:") and b.startswith("mod:"):
                self._parents(a, b[4:], kind)

    def _parents(self, src: str, module_name: str, kind: str) -> None:
        """Running a.b.c first runs a/__init__.py and a/b/__init__.py, so whatever they import is reached too."""
        parts = module_name.split(".")
        for n in range(1, len(parts)):
            parent = ".".join(parts[:n])
            if parent in self.index.modules and self.index.modules[parent].is_init:
                self.graph.add_edge(src, self._node(f"mod:{parent}", parent), kind=kind)

    # ------------------------------------------------------------------ build
    def _build(self) -> None:
        idx = self.index
        if idx.unparsable:
            self.warnings.append(f"{len(idx.unparsable)} Python file(s) could not be parsed and were skipped: {', '.join(idx.unparsable[:5])}"
                                 + (" ..." if len(idx.unparsable) > 5 else ""))
        # 1. module -> module / package edges from imports
        for mod in idx.modules.values():
            me = self._node(f"mod:{mod.name}", mod.name)
            for ref in mod.imports:
                if ref.typing_only:
                    continue
                t = resolve(idx, ref.candidates)
                self._edge(me, self._target_node(t), "import")
                if t.kind == "module":
                    self._parents(me, t.name, "import")
        # 2. package -> package edges (transitive dependencies) where a lock file told us
        for d in self.by_name.values():
            for req in d.requires or []:
                if req in self.by_name:
                    self._edge(self._node(f"pkg:{d.name}", d.name), self._node(f"pkg:{req}", req), "requires")
        # 3. Django entry points
        settings_mods = [m for m in idx.modules.values() if m.settings]
        root_urlconfs: list[str] = []
        for mod in settings_mods:
            self._settings_entries(mod, root_urlconfs)
        for mod in idx.modules.values():
            self._file_entries(mod)
        if not root_urlconfs:
            root_urlconfs = self._guess_root_urlconfs()
        seen_roots = set()
        for root in root_urlconfs:
            if root in seen_roots or root not in idx.modules:
                continue
            seen_roots.add(root)
            e = self._entry("web", f"urlconf:{root}", f"URL configuration ({root})")
            self._edge(e, self._node(f"mod:{root}", root), "entry")
            for full, route in expand_routes(idx, root):
                self._edge(self._entry("web", full, full), self._target_node(route.target), "route")
        self.django = bool(self.entry_level)
        if not self.django:
            self.warnings.append("no Django entry points were found (no settings, urls.py, manage.py, commands or tests): "
                                 "exposure is unknown, so the exposure factor is left out of the risk score")
        if self.unmapped:
            shown = ", ".join(sorted(self.unmapped)[:8]) + (" ..." if len(self.unmapped) > 8 else "")
            self.warnings.append(f"{len(self.unmapped)} third-party import name(s) could not be matched to a declared dependency: {shown}")

    def _settings_entries(self, mod: PyModule, root_urlconfs: list[str]) -> None:
        idx = self.index
        me = self._node(f"mod:{mod.name}", mod.name)
        self._edge(self._entry("startup", f"settings:{mod.name}", f"settings ({mod.name})"), me, "entry")
        for s in mod.settings.get("INSTALLED_APPS", []):
            t = resolve(idx, [s])
            node = self._target_node(t)
            self._edge(me, node, "settings")
            if t.kind == "module":
                m = idx.modules[t.name]
                app = m.name if m.is_init else m.package
                for sub in AUTOLOAD:                       # Django imports these for every installed app
                    if f"{app}.{sub}" in idx.modules:
                        self._edge(me, self._node(f"mod:{app}.{sub}", f"{app}.{sub}"), "autoload")
        for setting, label in (("MIDDLEWARE", "middleware"), ("AUTHENTICATION_BACKENDS", "login backend"), ("SESSION_ENGINE", "session engine")):
            for s in mod.settings.get(setting, []):        # these run for web requests
                e = self._entry("web", f"{setting}:{s}", f"{label} {s.rsplit('.', 1)[-1]}")
                self._edge(e, self._target_node(resolve(idx, [s])), "entry")
        for s in mod.settings.get("ROOT_URLCONF", []):
            t = resolve(idx, [s])
            if t.kind == "module":
                root_urlconfs.append(t.name)
        for setting in ("WSGI_APPLICATION", "ASGI_APPLICATION"):
            for s in mod.settings.get(setting, []):
                t = resolve(idx, [s])
                if t.kind == "module":
                    self._edge(self._entry("startup", f"{setting}:{t.name}", f"{setting.split('_')[0].lower()} ({t.name})"),
                               self._node(f"mod:{t.name}", t.name), "entry")

    def _file_entries(self, mod: PyModule) -> None:
        leaf = mod.name.rsplit(".", 1)[-1]
        me = lambda: self._node(f"mod:{mod.name}", mod.name)  # noqa: E731  (created only when needed)
        parts = mod.path.lower().split("/")
        if leaf in ("manage", "wsgi", "asgi"):
            self._edge(self._entry("startup", f"file:{mod.name}", f"{leaf} ({mod.name})"), me(), "entry")
        if mod.is_init:
            return   # a package's __init__ is not itself a command, task module or test
        if ".management.commands." in f".{mod.name}.":
            self._edge(self._entry("command", f"command:{mod.name}", f"manage.py {leaf}"), me(), "entry")
        if leaf == "tasks":
            self._edge(self._entry("command", f"tasks:{mod.name}", f"background tasks ({mod.name})"), me(), "entry")
        if any(p in ("tests", "test") for p in parts[:-1]) or leaf.startswith("test_") or leaf.endswith("_test") or leaf == "conftest":
            self._edge(self._entry("test", f"test:{mod.name}", f"tests ({mod.name})"), me(), "entry")

    def _guess_root_urlconfs(self) -> list[str]:
        """No ROOT_URLCONF setting found: the urls modules that no other urls module includes."""
        idx = self.index
        urls = [m.name for m in idx.modules.values() if m.name.rsplit(".", 1)[-1] == "urls"]
        included = {r.target.name for u in urls for r in module_routes(idx, idx.modules[u]) if r.kind == "include" and r.target.kind == "module"}
        return [u for u in urls if u not in included]

    # ------------------------------------------------------------------ exposure
    def _preds(self, level: str) -> dict[str, str | None]:
        """Breadth-first search from every entry point of `level`: node -> the node it was reached from."""
        if level not in self._pred_cache:
            starts = [n for n, lv in self.entry_level.items() if lv == level]
            pred: dict[str, str | None] = dict.fromkeys(starts)
            q = deque(starts)
            while q:
                cur = q.popleft()
                for nxt in self.graph.successors(cur):
                    if nxt not in pred:
                        pred[nxt] = cur
                        q.append(nxt)
            self._pred_cache[level] = pred
        return self._pred_cache[level]

    def _path(self, level: str, node: str) -> list[str] | None:
        pred = self._preds(level)
        if node not in pred:
            return None
        path = [node]
        while pred[path[-1]] is not None:
            path.append(pred[path[-1]])
        return path[::-1]

    def exposure(self, name: str) -> dict | None:
        """How the package `name` can be reached, or None when that cannot be known."""
        dep = self.by_name.get(name)
        if dep is None or not self.entry_level:
            return None
        node = f"pkg:{name}"
        importers = sorted(n[4:] for n in self.graph.predecessors(node) if n.startswith("mod:")) if node in self.graph else []
        for level in LEVELS:
            path = self._path(level, node)
            if path:
                return {"level": level, "exposed": level == "web", "path": path, "path_labels": [self.labels[p] for p in path],
                        "imported_by": importers, "note": self._note(level, path)}
        if importers:
            shown = ", ".join(importers[:3]) + (" ..." if len(importers) > 3 else "")
            note = f"imported by {shown}, but no URL route, middleware, startup code or command reaches that code"
        elif dep.direct:
            note = "no import of this package was found in the project (it may still be loaded dynamically, used as a tool, or needed by another package)"
        elif self.requires_known:
            note = "no entry point reaches it through the known dependency graph"
        else:
            return None   # a transitive dependency and no way to see what depends on it
        return {"level": "none", "exposed": False, "path": [], "path_labels": [], "imported_by": importers, "note": note}

    @staticmethod
    def _note(level: str, path: list[str]) -> str:
        return {
            "web": "reachable from a web request",
            "startup": "loaded when the application starts (settings, installed apps, wsgi/asgi) but no URL route reaches it",
            "command": "only used by management commands or background tasks",
            "test": "only used by tests",
        }[level] + f" (path of {len(path)} steps)"

    # ------------------------------------------------------------------ output
    def render(self, vulnerable: set[str]) -> dict:
        """The graph the UI draws: only the paths to the vulnerable packages, plus the modules that import unreached ones."""
        nodes: dict[str, str] = {}
        links: set[tuple[str, str]] = set()

        def add(nid: str) -> None:
            kind = "entry" if nid.startswith("entry:") else "module" if nid.startswith("mod:") else \
                "vulnerable" if nid[4:] in vulnerable else "package"
            nodes[nid] = kind

        for pkg in sorted(vulnerable):
            exp = self.exposure(pkg)
            if exp is None:
                continue
            path = exp["path"]
            if not path:  # not reached: show what imports it, so "nothing reaches this" can be checked by eye
                node = f"pkg:{pkg}"
                add(node)
                for m in exp["imported_by"]:
                    add(f"mod:{m}")
                    links.add((f"mod:{m}", node))
                continue
            for a in path:
                add(a)
            links.update(zip(path, path[1:], strict=False))
        return {
            "nodes": [{"id": n, "label": self.labels.get(n, n), "kind": k, **({"level": self.entry_level[n]} if n in self.entry_level else {})}
                      for n, k in nodes.items()],
            "links": [{"source": a, "target": b} for a, b in sorted(links)],
            "limitation": LIMITATION,
            "stats": {"modules": len(self.index.modules), "web_entry_points": sum(1 for lv in self.entry_level.values() if lv == "web"),
                      "unparsable_files": len(self.index.unparsable), "unmapped_imports": sorted(self.unmapped)},
        }


def analyze_project(root: Path, deps: list[Dependency]) -> ProjectAnalysis:
    return ProjectAnalysis(discover(root), deps)
