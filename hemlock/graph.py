"""Who asked for this package?

Several rules end by telling you to find out which of your direct
dependencies pulled a package in. That is poor advice from a tool that cannot
answer it, so this builds the edges from the manifests it already read.

Resolution is by name rather than by installed path. npm can hold several
copies of one package at different depths, and collapsing them loses which
copy an edge points at. For answering "why is this here", the name is what
people mean, and the alternative is a lot of machinery for a distinction that
rarely changes the answer.
"""

from __future__ import annotations

import json
import os
import tomllib
from collections import deque

from .model import Package

DEP_FIELDS = ("dependencies", "optionalDependencies", "peerDependencies")


class Graph:
    def __init__(self):
        self.edges: dict[tuple[str, str], set[str]] = {}
        self.roots: set[tuple[str, str]] = set()

    def add(self, ecosystem: str, parent: str, child: str) -> None:
        self.edges.setdefault((ecosystem, parent), set()).add(child)

    def children(self, ecosystem: str, name: str) -> set[str]:
        return self.edges.get((ecosystem, name), set())

    def paths_to(self, ecosystem: str, target: str, limit: int = 3) -> list[list[str]]:
        """Shortest routes from a direct dependency down to `target`.

        Breadth-first, so the first route found through any given package is
        the shortest one. Cycles are common in real trees and are cut by the
        visited set rather than by a depth limit.
        """
        starts = [name for eco, name in self.roots if eco == ecosystem]
        if target in starts:
            return [[target]]

        found: list[list[str]] = []
        seen = {target}
        queue = deque([[name] for name in sorted(starts)])

        while queue and len(found) < limit:
            path = queue.popleft()
            if len(path) > 12:
                continue
            for child in sorted(self.children(ecosystem, path[-1])):
                if child == target:
                    found.append([*path, child])
                    if len(found) >= limit:
                        break
                elif child not in path and child not in seen:
                    seen.add(child)
                    queue.append([*path, child])
        return found

    def is_direct(self, ecosystem: str, name: str) -> bool:
        return (ecosystem, name) in self.roots


# --------------------------------------------------------------------------


def build(root: str, packages: list[Package]) -> Graph:
    graph = Graph()
    for pkg in packages:
        if pkg.direct and pkg.kind == "package":
            graph.roots.add((pkg.ecosystem, pkg.name))

    for manifest in sorted({p.origin for p in packages if p.origin}):
        path = os.path.join(root, manifest)
        base = os.path.basename(manifest)
        try:
            if base in ("package-lock.json", "npm-shrinkwrap.json"):
                _npm_lockfile(json.load(open(path, encoding="utf-8")), graph)
            elif base == "poetry.lock":
                _poetry(tomllib.load(open(path, "rb")), graph)
        except (OSError, ValueError, tomllib.TOMLDecodeError):
            continue

    return graph


def _npm_lockfile(doc: dict, graph: Graph) -> None:
    if entries := doc.get("packages"):
        _npm_v3(entries, graph)
    elif tree := doc.get("dependencies"):
        _npm_v1(tree, None, graph)


def _npm_v3(entries: dict, graph: Graph) -> None:
    """Lockfile v2/v3: a flat map keyed by install path.

    An edge follows node's own resolution: look for the dependency beside the
    dependent first, then in each ancestor's node_modules, then at the root.
    """
    for path, entry in entries.items():
        parent = _name_of(path, entry)
        deps: dict[str, str] = {}
        for field in DEP_FIELDS:
            deps.update(entry.get(field) or {})

        for child in deps:
            resolved = _resolve(path, child, entries)
            if resolved is None:
                continue
            if parent is None:
                graph.roots.add(("npm", child))
            else:
                graph.add("npm", parent, child)


def _name_of(path: str, entry: dict) -> str | None:
    if not path:
        return None  # the project itself, so its dependencies are roots
    return entry.get("name") or path.split("node_modules/")[-1]


def _resolve(base: str, name: str, entries: dict) -> str | None:
    prefix = base
    while True:
        candidate = f"{prefix}/node_modules/{name}" if prefix else f"node_modules/{name}"
        if candidate in entries:
            return candidate
        if not prefix:
            return None
        cut = prefix.rfind("/node_modules/")
        prefix = prefix[:cut] if cut != -1 else ""


def _npm_v1(tree: dict, parent: str | None, graph: Graph) -> None:
    for name, entry in (tree or {}).items():
        if parent is None:
            graph.roots.add(("npm", name))
        else:
            graph.add("npm", parent, name)
        for required in entry.get("requires") or {}:
            graph.add("npm", name, required)
        _npm_v1(entry.get("dependencies"), name, graph)


def _poetry(doc: dict, graph: Graph) -> None:
    from .pypi import normalize

    declared = {normalize(p.get("name", "")) for p in doc.get("package", [])}
    for entry in doc.get("package", []):
        parent = normalize(entry.get("name", ""))
        for child in entry.get("dependencies") or {}:
            if normalize(child) in declared:
                graph.add("pypi", parent, normalize(child))

    # Anything nothing else depends on is something the project asked for.
    depended_on = {c for children in graph.edges.values() for c in children}
    for name in declared:
        if name and name not in depended_on:
            graph.roots.add(("pypi", name))
