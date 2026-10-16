"""The dependency graph: which package pulls in which, and why a vulnerable package is in your project at all.

Built from the links a lock file records (package-lock.json, yarn.lock, poetry.lock). It answers a practical question
the advisory data cannot: a vulnerable *transitive* package cannot be fixed by editing your manifest; you have to
update, or replace, the direct dependency that needs it. This module names that dependency.

Read-only and offline. Files that do not record dependency links (requirements.txt, Pipfile.lock, go.mod, go.sum)
give nodes but no edges, and the result says so rather than guessing.
"""
from __future__ import annotations

import networkx as nx

from .models import Dependency

LIMITATION = (
    "Links come from lock files (package-lock.json, yarn.lock, poetry.lock). requirements.txt, Pipfile.lock, go.mod and go.sum do "
    "not record what depends on what, so those packages show no links. The path shown is the shortest; a package can be needed by "
    "several others. It does not check whether a newer release of the parent still needs this version."
)
ROOT = "<project>"
MAX_PARENTS_LISTED = 5


def node_id(eco: str, name: str, version: str | None) -> str:
    return f"{eco}:{name}@{version or '?'}"


def label(name: str, version: str | None) -> str:
    return f"{name}@{version or '?'}"


class DependencyGraph:
    def __init__(self, deps: list[Dependency]):
        self.g: nx.DiGraph = nx.DiGraph()
        self.by_name: dict[tuple[str, str], list[str]] = {}
        self.edges_known = any(d.requires_resolved for d in deps)
        merged: dict[str, dict] = {}
        for d in deps:
            nid = node_id(d.ecosystem, d.name, d.candidate)
            m = merged.setdefault(nid, {"dep": d, "direct": False, "scope": d.scope, "links": set()})
            m["direct"] = m["direct"] or d.direct
            if d.scope == "runtime":
                m["scope"] = "runtime"                       # needed at run time through any route: runtime
            m["links"] |= {node_id(d.ecosystem, n, v) for n, v in (d.requires_resolved or [])}
        for nid, m in merged.items():
            d = m["dep"]
            self.g.add_node(nid, name=d.name, version=d.candidate, ecosystem=d.ecosystem, direct=m["direct"], scope=m["scope"])
            self.by_name.setdefault((d.ecosystem, d.name), []).append(nid)
        for nid, m in merged.items():
            for target in m["links"]:
                if target in self.g and target != nid:
                    self.g.add_edge(nid, target)
        # shortest route from the project: runtime direct dependencies first, so a runtime route is preferred over a dev one
        self.g.add_node(ROOT)
        for nid in sorted((n for n, a in self.g.nodes(data=True) if a.get("direct")), key=lambda n: (self.g.nodes[n]["scope"] != "runtime", n)):
            self.g.add_edge(ROOT, nid)
        self.routes: dict[str, list[str]] = nx.single_source_shortest_path(self.g, ROOT)

    # ------------------------------------------------------------------ lookups
    def find(self, eco: str, name: str, version: str | None) -> str | None:
        exact = node_id(eco, name, version)
        if exact in self.g:
            return exact
        candidates = self.by_name.get((eco, name))
        return candidates[0] if candidates else None

    def _label(self, nid: str) -> str:
        a = self.g.nodes[nid]
        return label(a["name"], a["version"])

    def direct_parents(self, nid: str) -> list[str]:
        """Every direct dependency that (transitively) needs this package, by name."""
        if self.g.nodes[nid].get("direct"):
            return []
        anc = nx.ancestors(self.g, nid) - {ROOT}
        return sorted({self.g.nodes[a]["name"] for a in anc if self.g.nodes[a].get("direct")})

    def path_for(self, finding: dict) -> dict:
        """Why this finding's package is in the project, as the finding's `dependency_path`."""
        nid = self.find(finding["ecosystem"], finding["package"], finding["version"])
        if nid is None:
            return {"known": False, "direct": False, "path": [], "path_labels": [], "direct_parents": [], "note": "Not found in the dependency list."}
        a = self.g.nodes[nid]
        if a.get("direct"):
            return {"known": True, "direct": True, "path": [nid], "path_labels": [self._label(nid)], "direct_parents": [],
                    "note": "A direct dependency: it is declared in your own manifest."}
        route = self.routes.get(nid)
        if not route:
            why = ("The lock file does not link it to any of your direct dependencies." if self.edges_known else
                   "The files given do not say what depends on it: add a package-lock.json, yarn.lock or poetry.lock.")
            return {"known": False, "direct": False, "path": [], "path_labels": [], "direct_parents": [], "note": f"A transitive dependency. {why}"}
        path = route[1:]                                     # drop the project marker
        parents = self.direct_parents(nid)
        more = f" and {len(parents) - MAX_PARENTS_LISTED} more" if len(parents) > MAX_PARENTS_LISTED else ""
        note = (f"A transitive dependency, needed through {', '.join(parents[:MAX_PARENTS_LISTED])}{more}. "
                f"It cannot be fixed by editing your manifest: update or replace {'that dependency' if len(parents) == 1 else 'those dependencies'}, "
                "or use your package manager's override.")
        return {"known": True, "direct": False, "path": path, "path_labels": [self._label(n) for n in path],
                "direct_parents": parents, "note": note}

    # ------------------------------------------------------------------ for the API
    def render(self, findings: list[dict]) -> dict:
        """Nodes and links worth drawing: the direct dependencies, every vulnerable package, and the routes that lead to them."""
        hits: dict[str, dict] = {}
        for f in findings:
            nid = self.find(f["ecosystem"], f["package"], f["version"])
            if nid:
                h = hits.setdefault(nid, {"count": 0, "max_risk": 0.0})
                h["count"] += 1
                h["max_risk"] = max(h["max_risk"], f["risk"]["score"])
        keep: set[str] = {n for n, a in self.g.nodes(data=True) if a.get("direct")}
        links: set[tuple[str, str]] = set()
        for nid in hits:
            route = self.routes.get(nid, [nid])[1:] or [nid]
            keep.update(route)
            links.update(zip(route, route[1:], strict=False))
        nodes = []
        for nid in sorted(keep):
            a = self.g.nodes[nid]
            h = hits.get(nid)
            route = self.routes.get(nid)
            nodes.append({
                "id": nid, "label": self._label(nid), "name": a["name"], "version": a["version"], "scope": a["scope"],
                "kind": "vulnerable" if h else "direct" if a["direct"] else "transitive",
                "depth": (len(route) - 1) if route else None,
                "findings": h["count"] if h else 0, "max_risk": round(h["max_risk"], 1) if h else None,
            })
        real = [n for n in self.g.nodes if n != ROOT]
        transitive = [n for n in real if not self.g.nodes[n]["direct"]]
        unlinked = [n for n in transitive if n not in self.routes]
        return {
            "nodes": nodes,
            "links": [{"source": s, "target": t} for s, t in sorted(links)],
            "stats": {
                "packages": len(real), "direct": len(real) - len(transitive), "transitive": len(transitive),
                "links_known": self.edges_known, "unlinked_transitive": len(unlinked), "vulnerable_packages": len(hits),
                "max_depth": max((len(self.routes[n]) - 1 for n in real if n in self.routes), default=0), "shown": len(nodes),
            },
            "limitation": LIMITATION,
        }


def build_dependency_graph(deps: list[Dependency]) -> DependencyGraph:
    return DependencyGraph(deps)
