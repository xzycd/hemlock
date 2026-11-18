"""Reading the npm side of a project.

Handles package-lock.json (all three format versions), pnpm-lock.yaml,
yarn.lock, and a bare package.json when there is no lockfile. Where node_modules is present we also
read the installed package.json, because that is the only place the real
install scripts live. A lockfile only tells you *that* a package has one.
"""

from __future__ import annotations

import json
import os
import re

from .model import Package

MANIFESTS = ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "package.json"]

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
    members = {member for p in by_dir.values() for member in _workspace_members(p)}
    return sorted(p for d, p in by_dir.items() if not (d in members and p.endswith("package.json")))


def _workspace_members(lockfile: str) -> set[str]:
    """Directories whose package.json a workspace lockfile already resolves.

    A workspace keeps one lockfile at its root. Reading each member's
    package.json beside it reports every dependency twice, the second time as
    an unpinned range, when the lockfile sitting above it pins all of them.
    """
    base, root = os.path.basename(lockfile), os.path.dirname(lockfile)
    try:
        raw = open(lockfile, encoding="utf-8").read()
        if base == "pnpm-lock.yaml":
            paths = _pnpm_importers(raw)
        elif base in ("package-lock.json", "npm-shrinkwrap.json"):
            paths = [key for key in json.loads(raw).get("packages", {}) if key and "node_modules/" not in key]
        else:
            return set()
    except (OSError, ValueError, AttributeError):
        return set()
    return {os.path.normpath(os.path.join(root, path)) for path in paths if path != "."}


def parse(path: str, root: str) -> list[Package]:
    base = os.path.basename(path)
    rel = os.path.relpath(path, root)
    try:
        raw = open(path, encoding="utf-8").read()
    except OSError:
        return []

    if base == "yarn.lock":
        pkgs = _parse_yarn(raw, rel)
    elif base == "pnpm-lock.yaml":
        pkgs = _parse_pnpm(raw, rel)
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
        if "node_modules/" not in install_path:
            # A workspace member, keyed by its own directory rather than an
            # install path. It is part of this project, so nothing published
            # is expected to match it and HEM507 has to leave it alone.
            pkg.meta["workspace"] = True
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


# pnpm-lock.yaml is YAML, and the standard library has no YAML reader. The
# lockfile is machine-written in one fixed layout, though: two-space indents,
# one key per line, flow mappings only for `resolution`. Reading that layout
# line by line is enough and keeps the dependency count at zero.
_PNPM_KEY = re.compile(r"^( *)(?:'([^']+)'|\"([^\"]+)\"|([^\s:'\"][^:]*)):(?:\s+(.*))?$")
_PNPM_DEP_FIELDS = ("dependencies", "devDependencies", "optionalDependencies")


def _pnpm_lines(raw: str):
    """Yield (indent, key, value) for every `key:` line."""
    for line in raw.splitlines():
        if m := _PNPM_KEY.match(line):
            yield len(m.group(1)), m.group(2) or m.group(3) or m.group(4), (m.group(5) or "").strip()


def _pnpm_importers(raw: str) -> list[str]:
    section, out = "", []
    for indent, key, _ in _pnpm_lines(raw):
        if indent == 0:
            section = key
        elif indent == 2 and section == "importers":
            out.append(key)
    return out


def _pnpm_coord(key: str) -> tuple[str, str | None]:
    """Split a `packages:` key into name and version across lockfile versions.

    v9 writes `name@1.2.3`, v6 `/name@1.2.3(peer@4.5.6)`, v5 `/name/1.2.3_peer`.
    """
    key = key.lstrip("/").split("(", 1)[0]
    at = key.rfind("@", 1)
    if at > 0:
        return key[:at], key[at + 1:] or None
    name, _, version = key.rpartition("/")
    return (name, version.split("_", 1)[0]) if name else (key, None)


def _parse_pnpm(raw: str, rel: str) -> list[Package]:
    out: list[Package] = []
    direct: set[str] = set()
    dev: set[str] = set()
    section = field = ""
    field_indent = -1
    pkg: Package | None = None
    in_resolution = False

    for indent, key, value in _pnpm_lines(raw):
        if indent == 0:
            section, field, pkg = key, "", None
            if key in _PNPM_DEP_FIELDS:  # a single project, before importers existed
                field, field_indent = key, 0
            continue

        if section in ("importers", *_PNPM_DEP_FIELDS):
            if key in _PNPM_DEP_FIELDS and indent == 4:
                field, field_indent = key, indent
            elif field and indent == field_indent + 2:
                direct.add(key)
                if field == "devDependencies":
                    dev.add(key)
            elif indent <= field_indent:
                field = ""
            continue

        if section != "packages":
            continue
        if indent == 2:
            name, version = _pnpm_coord(key)
            pkg = Package(ecosystem="npm", name=name, version=version, origin=rel)
            if version and _PNPM_SOURCE.match(version):
                pkg.version, pkg.resolved = None, version
            out.append(pkg)
            in_resolution = False
        elif pkg is not None and indent == 4:
            in_resolution = key == "resolution"
            if in_resolution:
                _pnpm_resolution(pkg, value)
            elif key == "requiresBuild" and value == "true":
                pkg.meta["hasInstallScript"] = True
            elif key == "dev" and value == "true":
                pkg.dev = True
        elif pkg is not None and indent == 6 and in_resolution:
            _pnpm_resolution(pkg, f"{key}: {value}")

    for pkg in out:
        pkg.direct = pkg.name in direct
        pkg.dev = pkg.dev or (pkg.name in dev)
    return out


_PNPM_SOURCE = re.compile(r"^(git\+|git:|github:|file:|link:|https?://)")
_PNPM_RESOLUTION = re.compile(r"\b(integrity|tarball|repo|commit):\s*'?([^\s,'}]+)")


def _pnpm_resolution(pkg: Package, text: str) -> None:
    found = dict(_PNPM_RESOLUTION.findall(text))
    if found.get("integrity"):
        pkg.integrity = found["integrity"]
    if found.get("tarball"):
        pkg.resolved = found["tarball"]
    elif found.get("repo"):
        pkg.resolved = f"git+{found['repo']}" if not _PNPM_SOURCE.match(found["repo"]) else found["repo"]


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
