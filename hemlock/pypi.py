"""Reading the Python side of a project.

requirements.txt, poetry.lock, Pipfile.lock and pyproject.toml. If a
virtualenv sits in the tree we also point each package at its installed
source so the code-shape rules have something to read.
"""

from __future__ import annotations

import json
import os
import re
import tomllib
import urllib.parse

from .model import Package

MANIFESTS = ["poetry.lock", "Pipfile.lock", "requirements.txt", "pyproject.toml"]
_SKIP_DIRS = {".git", "node_modules", "__pycache__", "dist", "build", ".tox", ".mypy_cache"}

_REQ = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[(?P<extras>[^\]]+)\])?"
    r"\s*(?P<spec>(?:[=<>!~^]=?|===)\s*[^;#\s]+)?"
)
_INDEX = re.compile(r"^(?:--index-url|--extra-index-url|-i)(?:\s+|=)(\S+)")


def normalize(name: str) -> str:
    """PEP 503: case-insensitive, and -, _ and . are interchangeable."""
    return re.sub(r"[-_.]+", "-", name).lower()


def find_manifests(root: str) -> list[str]:
    hits = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.endswith(".egg-info")]
        for name in filenames:
            if name in MANIFESTS or (name.startswith("requirements") and name.endswith(".txt")):
                hits.append(os.path.join(dirpath, name))
    return sorted(hits)


def parse(path: str, root: str) -> list[Package]:
    base = os.path.basename(path)
    rel = os.path.relpath(path, root)
    try:
        raw = open(path, encoding="utf-8").read()
    except OSError:
        return []

    if base == "poetry.lock":
        pkgs = _parse_poetry(raw, rel)
    elif base == "Pipfile.lock":
        pkgs = _parse_pipfile(raw, rel)
    elif base == "pyproject.toml":
        pkgs = _parse_pyproject(raw, rel)
    else:
        pkgs = _parse_requirements(raw, rel)

    _attach_installed(pkgs, root)
    return pkgs


def _parse_requirements(raw: str, rel: str) -> list[Package]:
    out: list[Package] = []
    extra_indexes: list[str] = []

    for line in _logical_lines(raw):
        if match := _INDEX.match(line):
            extra_indexes.append(match.group(1))
            continue
        if line.startswith(("-r", "-c", "--requirement", "--constraint")):
            continue  # walked separately as its own manifest
        if line.startswith(("-e", "--editable")):
            out.append(Package("pypi", line.split(None, 1)[-1], spec="editable", direct=True, origin=rel,
                               meta={"vcs": True}))
            continue
        if re.match(r"^(git|hg|svn|bzr)\+|^https?://", line):
            name = _name_from_url(line)
            out.append(Package("pypi", name, spec=line, resolved=line, direct=True, origin=rel,
                               meta={"vcs": True}))
            continue

        head = line.split(";")[0].split("--hash")[0].strip()
        m = _REQ.match(head)
        if not m:
            continue
        spec = (m.group("spec") or "").replace(" ", "")
        version = spec[2:] if spec.startswith("==") else None
        pkg = Package(
            ecosystem="pypi",
            name=m.group("name"),
            version=version,
            spec=spec or None,
            direct=True,
            origin=rel,
            integrity="sha256" if "--hash" in line else None,
        )
        out.append(pkg)

    if extra_indexes:
        # A configured index is a property of the file, not of any one
        # requirement in it, so it gets reported against the file.
        out.append(
            Package("pypi", os.path.basename(rel), kind="manifest", origin=rel,
                    meta={"extra_indexes": extra_indexes})
        )
    return out


def _logical_lines(raw: str):
    buf = ""
    for line in raw.splitlines():
        line = line.split(" #")[0].rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        buf += line.rstrip("\\")
        if line.endswith("\\"):
            continue
        yield buf.strip()
        buf = ""
    if buf.strip():
        yield buf.strip()


def _name_from_url(url: str) -> str:
    if "#egg=" in url:
        return urllib.parse.unquote(url.split("#egg=")[1].split("&")[0])
    tail = urllib.parse.urlsplit(url).path.rstrip("/").split("/")[-1]
    # Preserve hyphenated repository names. Splitting `my-package.git` on the
    # first hyphen used to report the dependency as just `my`.
    if ".git@" in tail:
        return urllib.parse.unquote(tail.split(".git@", 1)[0])
    if tail.endswith(".git"):
        return urllib.parse.unquote(tail[:-4])
    return re.split(r"[@.\-]", tail)[0] or tail


def _parse_poetry(raw: str, rel: str) -> list[Package]:
    try:
        doc = tomllib.loads(raw)
    except tomllib.TOMLDecodeError:
        return []
    out = []
    for entry in doc.get("package", []):
        files = entry.get("files") or []
        out.append(
            Package(
                ecosystem="pypi",
                name=entry.get("name", ""),
                version=entry.get("version"),
                spec=f"=={entry.get('version')}",
                dev=entry.get("category") == "dev",
                integrity="sha256" if files else None,
                origin=rel,
                meta={"source": entry.get("source", {})},
            )
        )
    return out


def _parse_pipfile(raw: str, rel: str) -> list[Package]:
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError:
        return []
    out = []
    for section, is_dev in (("default", False), ("develop", True)):
        for name, entry in (doc.get(section) or {}).items():
            version = str(entry.get("version", "")).lstrip("=") or None
            out.append(
                Package(
                    ecosystem="pypi",
                    name=name,
                    version=version,
                    spec=entry.get("version"),
                    dev=is_dev,
                    direct=True,
                    integrity="sha256" if entry.get("hashes") else None,
                    origin=rel,
                )
            )
    return out


def _parse_pyproject(raw: str, rel: str) -> list[Package]:
    try:
        doc = tomllib.loads(raw)
    except tomllib.TOMLDecodeError:
        return []
    out = []

    for dep in doc.get("project", {}).get("dependencies", []) or []:
        m = _REQ.match(dep.strip())
        if m:
            spec = (m.group("spec") or "").replace(" ", "")
            out.append(Package("pypi", m.group("name"), spec=spec or None, direct=True, origin=rel,
                               version=spec[2:] if spec.startswith("==") else None))

    poetry = doc.get("tool", {}).get("poetry", {})
    for name, spec in (poetry.get("dependencies") or {}).items():
        if name.lower() == "python":
            continue
        text = spec if isinstance(spec, str) else json.dumps(spec)
        out.append(Package("pypi", name, spec=text, direct=True, origin=rel))
    return out


def _attach_installed(pkgs: list[Package], root: str) -> None:
    site = _find_site_packages(root)
    if not site:
        return
    installed = {normalize(d): d for d in os.listdir(site)}
    for pkg in pkgs:
        key = normalize(pkg.name)
        for candidate in (key, key.replace("-", "_")):
            hit = installed.get(candidate)
            if hit and os.path.isdir(os.path.join(site, hit)):
                pkg.source_dir = os.path.join(site, hit)
                break


def _find_site_packages(root: str) -> str | None:
    for venv in (".venv", "venv", "env"):
        lib = os.path.join(root, venv, "lib")
        if not os.path.isdir(lib):
            continue
        for entry in sorted(os.listdir(lib)):
            sp = os.path.join(lib, entry, "site-packages")
            if os.path.isdir(sp):
                return sp
    return None
