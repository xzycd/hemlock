"""Reading the npm side of a project.

Handles package-lock.json (all three format versions), yarn.lock, and a bare
package.json when there is no lockfile. Where node_modules is present we also
read the installed package.json, because that is the only place the real
install scripts live. A lockfile only tells you *that* a package has one.
"""

from __future__ import annotations

import json
import os
import re

from .model import Package

MANIFESTS = ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "package.json"]

_YARN_ENTRY = re.compile(r'^"?([^"\s,]+)"?(?:,\s*"?[^"\s,]+"?)*:\s*$')
_YARN_FIELD = re.compile(r'^\s{2,}"?([\w-]+)"?\s+"?([^"\n]+?)"?\s*$')


def find_manifests(root: str) -> list[str]:
    hits = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in MANIFESTS:
            if name in filenames:
                hits.append(os.path.join(dirpath, name))
    return _prefer_lockfiles(hits)


_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox"}


def _prefer_lockfiles(paths: list[str]) -> list[str]:
    """One manifest per directory. A lockfile beats a package.json."""
    by_dir: dict[str, str] = {}
    for p in paths:
        d = os.path.dirname(p)
        current = by_dir.get(d)
        if current is None or MANIFESTS.index(os.path.basename(p)) < MANIFESTS.index(os.path.basename(current)):
            by_dir[d] = p
    return sorted(by_dir.values())


def parse(path: str, root: str) -> list[Package]:
    base = os.path.basename(path)
    rel = os.path.relpath(path, root)
    try:
        raw = open(path, encoding="utf-8").read()
    except OSError:
        return []

    if base == "yarn.lock":
        pkgs = _parse_yarn(raw, rel)
    else:
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError:
            return []
        if base == "package.json":
            pkgs = _parse_package_json(doc, rel)
        else:
            pkgs = _parse_lockfile(doc, rel)

    _attach_installed(pkgs, os.path.dirname(path))
    return pkgs


def _parse_lockfile(doc: dict, rel: str) -> list[Package]:
    out: list[Package] = []
    direct = set(doc.get("packages", {}).get("", {}).get("dependencies", {}))
    direct |= set(doc.get("packages", {}).get("", {}).get("devDependencies", {}))

    # v2/v3: flat map keyed by install path.
    for install_path, entry in doc.get("packages", {}).items():
        if not install_path:
            continue  # the project itself
        name = entry.get("name") or install_path.split("node_modules/")[-1]
        pkg = Package(
            ecosystem="npm",
            name=name,
            version=entry.get("version"),
            resolved=entry.get("resolved"),
            integrity=entry.get("integrity"),
            dev=bool(entry.get("dev")),
            direct=name in direct,
            origin=rel,
        )
        if entry.get("hasInstallScript"):
            pkg.meta["hasInstallScript"] = True
        if entry.get("link"):
            pkg.meta["link"] = True
        out.append(pkg)

    if out:
        return out

    # v1: recursive "dependencies" tree.
    def walk(deps: dict, top: bool):
        for name, entry in (deps or {}).items():
            out.append(
                Package(
                    ecosystem="npm",
                    name=name,
                    version=entry.get("version"),
                    resolved=entry.get("resolved"),
                    integrity=entry.get("integrity"),
                    dev=bool(entry.get("dev")),
                    direct=top,
                    origin=rel,
                )
            )
            walk(entry.get("dependencies"), False)

    walk(doc.get("dependencies"), True)
    return out


def _parse_package_json(doc: dict, rel: str) -> list[Package]:
    out = []
    for field, is_dev in (("dependencies", False), ("devDependencies", True), ("optionalDependencies", False)):
        for name, spec in (doc.get(field) or {}).items():
            out.append(
                Package(
                    ecosystem="npm",
                    name=name,
                    spec=str(spec),
                    version=None if _is_range(spec) else str(spec),
                    direct=True,
                    dev=is_dev,
                    origin=rel,
                )
            )
    return out


def _is_range(spec: str) -> bool:
    return bool(re.search(r"[\^~*><|\s]|latest|^\d+\.x", str(spec)))


def _parse_yarn(raw: str, rel: str) -> list[Package]:
    out: list[Package] = []
    name = spec = None
    fields: dict[str, str] = {}

    def flush():
        if name:
            out.append(
                Package(
                    ecosystem="npm",
                    name=name,
                    version=fields.get("version"),
                    spec=spec,
                    resolved=fields.get("resolved"),
                    integrity=fields.get("integrity"),
                    origin=rel,
                )
            )

    for line in raw.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        m = _YARN_ENTRY.match(line)
        if m:
            flush()
            fields = {}
            descriptor = m.group(1)
            at = descriptor.rfind("@")
            name, spec = (descriptor[:at], descriptor[at + 1:]) if at > 0 else (descriptor, None)
            continue
        f = _YARN_FIELD.match(line)
        if f and name:
            fields[f.group(1)] = f.group(2)
    flush()
    return out


def _attach_installed(pkgs: list[Package], project_dir: str) -> None:
    """Pull real install scripts off disk when node_modules exists."""
    nm = os.path.join(project_dir, "node_modules")
    if not os.path.isdir(nm):
        return
    for pkg in pkgs:
        pdir = os.path.join(nm, *pkg.name.split("/"))
        manifest = os.path.join(pdir, "package.json")
        if not os.path.isfile(manifest):
            continue
        pkg.source_dir = pdir
        try:
            doc = json.load(open(manifest, encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        pkg.scripts = {k: str(v) for k, v in (doc.get("scripts") or {}).items()}
        for key in ("repository", "homepage", "bin"):
            if doc.get(key):
                pkg.meta[key] = doc[key]
