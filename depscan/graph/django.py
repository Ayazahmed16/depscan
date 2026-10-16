"""Django specifics: URL routes (following include() chains and DRF routers) and the setting strings Django loads.

Static reading only. A route we cannot read (a computed pattern, a lambda view, a view built at run time) is
skipped, never guessed. See LIMITATION in analysis.py.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass

from .modules import ProjectIndex, PyModule, Target, resolve

URL_FUNCS = {"path", "re_path", "url"}


@dataclass
class RouteDef:
    kind: str                # "view" or "include"
    route: str               # the pattern as written, e.g. "login/" or "^api/"
    target: Target           # the view's module (or third-party package), or the included urlconf module
    lineno: int


def _clean(route: str, regex: bool) -> str:
    if regex:
        route = route.removeprefix("^").removesuffix("$")
    return route


def _route_text(node: ast.expr | None, regex: bool) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return _clean(node.value, regex)
    return "<computed>"


def _root_name(expr: ast.expr) -> str | None:
    while isinstance(expr, ast.Attribute):
        expr = expr.value
    return expr.id if isinstance(expr, ast.Name) else None


def _target_of(index: ProjectIndex, mod: PyModule, expr: ast.expr) -> Target | None:
    """The module (or third-party package) a view expression comes from."""
    if isinstance(expr, ast.Call):
        f = expr.func
        if isinstance(f, ast.Attribute) and f.attr == "as_view":      # HomeView.as_view()
            return _target_of(index, mod, f.value)
        if expr.args:                                                    # login_required(views.home): look inside the decorator
            return _target_of(index, mod, expr.args[0])
        return None
    root = _root_name(expr)
    if root is None:
        return None
    if root in mod.table:
        base, symbol = mod.table[root]
        cands = [f"{base}.{symbol}", base] if symbol else [base]
        # `views.home`: when the attribute is itself a submodule, prefer it
        if isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name) and symbol is None:
            cands = [f"{base}.{expr.attr}", base]
        return resolve(index, cands)
    if root in _defined_names(mod):
        return Target("module", mod.name)                                # a view defined in the urls module itself
    return None


def _defined_names(mod: PyModule) -> set[str]:
    if mod.tree is None:
        return set()
    return {n.name for n in mod.tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}


def _include_target(index: ProjectIndex, mod: PyModule, call: ast.Call) -> Target | None:
    if not call.args:
        return None
    arg = call.args[0]
    if isinstance(arg, ast.Tuple) and arg.elts:                          # include((patterns, "app_name"))
        arg = arg.elts[0]
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):     # include("accounts.urls")
        return resolve(index, [arg.value])
    return _target_of(index, mod, arg)                                    # include(accounts_urls) / include(accounts.urls)


def _registrations(index: ProjectIndex, mod: PyModule) -> dict[str, list[RouteDef]]:
    """DRF: router.register("users", UserViewSet) -> routes under that router variable."""
    out: dict[str, list[RouteDef]] = {}
    if mod.tree is None:
        return out
    for node in ast.walk(mod.tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "register" \
                and isinstance(node.func.value, ast.Name) and len(node.args) >= 2:
            tgt = _target_of(index, mod, node.args[1])
            if tgt:
                prefix = _route_text(node.args[0], False).strip("/")
                out.setdefault(node.func.value.id, []).append(RouteDef("view", prefix + "/", tgt, node.lineno))
    return out


def _from_list(index: ProjectIndex, mod: PyModule, elts: list[ast.expr], routers: dict[str, list[RouteDef]]) -> list[RouteDef]:
    routes: list[RouteDef] = []
    for el in elts:
        if isinstance(el, ast.Starred):
            continue
        if isinstance(el, ast.Attribute) and el.attr == "urls" and isinstance(el.value, ast.Name):   # router.urls
            routes += routers.get(el.value.id, [])
            continue
        if not (isinstance(el, ast.Call) and isinstance(el.func, (ast.Name, ast.Attribute))):
            continue
        fname = el.func.id if isinstance(el.func, ast.Name) else el.func.attr
        if fname not in URL_FUNCS:
            continue
        regex = fname != "path"
        route = _route_text(el.args[0] if el.args else None, regex)
        view = el.args[1] if len(el.args) > 1 else next((k.value for k in el.keywords if k.arg == "view"), None)
        if view is None:
            continue
        if isinstance(view, ast.Call) and isinstance(view.func, (ast.Name, ast.Attribute)) and \
                (view.func.id if isinstance(view.func, ast.Name) else view.func.attr) == "include":
            inner = view.args[0] if view.args else None
            if isinstance(inner, ast.Attribute) and inner.attr == "urls" and isinstance(inner.value, ast.Name) and inner.value.id in routers:
                for r in routers[inner.value.id]:                       # include(router.urls): expand the registered viewsets here
                    routes.append(RouteDef("view", route + r.route, r.target, r.lineno))
                continue
            tgt = _include_target(index, mod, view)
            if tgt:
                routes.append(RouteDef("include", route, tgt, el.lineno))
        else:
            tgt = _target_of(index, mod, view)
            if tgt:
                routes.append(RouteDef("view", route, tgt, el.lineno))
    return routes


def module_routes(index: ProjectIndex, mod: PyModule) -> list[RouteDef]:
    """The routes one urls module declares, before include() chains are expanded."""
    if mod.tree is None:
        return []
    routers = _registrations(index, mod)
    routes: list[RouteDef] = []
    for node in mod.tree.body:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, (ast.AugAssign, ast.AnnAssign)) else []
        if not any(isinstance(t, ast.Name) and t.id == "urlpatterns" for t in targets):
            continue
        value = getattr(node, "value", None)
        if isinstance(value, (ast.List, ast.Tuple)):
            routes += _from_list(index, mod, value.elts, routers)
        elif isinstance(value, ast.BinOp):                                # urlpatterns = [..] + other
            parts = [value.left, value.right]
            routes += _from_list(index, mod, [e for p in parts if isinstance(p, (ast.List, ast.Tuple)) for e in p.elts], routers)
        elif isinstance(value, ast.Attribute) and value.attr == "urls":   # urlpatterns = router.urls
            routes += _from_list(index, mod, [value], routers)
    return routes


def expand_routes(index: ProjectIndex, root_module: str, *, limit: int = 5000) -> list[tuple[str, RouteDef]]:
    """Follow include() chains from a root urlconf. Returns (full path, route) for every view route.

    Cycles are cut and the total is capped, so a strange project cannot make this run away.
    """
    out: list[tuple[str, RouteDef]] = []

    def walk(name: str, prefix: str, seen: tuple[str, ...]) -> None:
        mod = index.modules.get(name)
        if mod is None or name in seen or len(out) >= limit:
            return
        for r in module_routes(index, mod):
            full = (prefix.rstrip("/") + "/" + r.route.lstrip("/")) if prefix else "/" + r.route.lstrip("/")
            if r.kind == "include":
                if r.target.kind == "module":
                    walk(r.target.name, full, (*seen, name))
            else:
                out.append(("/" + full.lstrip("/"), r))

    walk(root_module, "", ())
    return out
