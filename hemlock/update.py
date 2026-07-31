"""Finding out whether a newer hemlock exists, and how this one was installed.

Deliberately does not update anything on its own. A tool whose entire argument
is that installing software is dangerous should not be the thing that quietly
pipes a download into your interpreter. It works out the exact command, shows
it to you, and runs it only if you say so.

The command adapts to where the release actually is. It asks PyPI first and
falls back to the repository's tags, so a copy installed from git before 0.5.0
reached PyPI still upgrades, and one installed from PyPI is told to use pip.
Neither path is hard-coded to a version.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

PACKAGE = "hemlock-scan"
SOURCE = "git+https://github.com/xzycd/hemlock"
PYPI = f"https://pypi.org/pypi/{PACKAGE}/json"
TAGS = "https://api.github.com/repos/xzycd/hemlock/tags"

# 1.2.3, and nothing else. A prerelease is not something to offer somebody
# who typed `hemlock update` expecting a stable one.
RELEASE = re.compile(r"^v?(\d+)\.(\d+)(?:\.(\d+))?$")


def parse_version(text: str) -> tuple[int, int, int] | None:
    m = RELEASE.match(text.strip())
    if not m:
        return None
    return int(m[1]), int(m[2]), int(m[3] or 0)


def newest(versions) -> str | None:
    ranked = sorted(((parse_version(v), v) for v in versions), key=lambda x: x[0] or (-1,))
    ranked = [(p, v) for p, v in ranked if p]
    return ranked[-1][1] if ranked else None


def latest(http) -> tuple[str, str] | None:
    """(version, where it came from), or None if nothing answered."""
    if doc := http.get(PYPI, allow_404=True):
        if version := newest(doc.get("releases", {}) or [doc["info"]["version"]]):
            return version, "pypi"
    if tags := http.get(TAGS, allow_404=True):
        if version := newest(t["name"] for t in tags if isinstance(t, dict) and "name" in t):
            return version, "github"
    return None


def installation(prefix: str | None = None, package_dir: str | None = None) -> str:
    """How this copy got here: 'git', 'pipx' or 'pip'."""
    prefix = prefix or sys.prefix
    root = os.path.dirname(package_dir or os.path.dirname(os.path.abspath(__file__)))
    if os.path.isdir(os.path.join(root, ".git")):
        return "git"
    if f"{os.sep}pipx{os.sep}" in prefix or os.sep + "pipx" in prefix:
        return "pipx"
    return "pip"


def upgrade_command(method: str, on_pypi: bool, root: str | None = None) -> list[str]:
    target = PACKAGE if on_pypi else SOURCE
    if method == "git":
        return ["git", "-C", root or _repo_root(), "pull", "--ff-only"]
    if method == "pipx":
        return (["pipx", "upgrade", PACKAGE] if on_pypi
                else ["pipx", "install", "--force", SOURCE])
    return [sys.executable, "-m", "pip", "install", "--upgrade", target]


def _repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(command: list[str]) -> int:
    # The child inherits this process's stdout and writes to it straight away,
    # while our own prints are still sitting in a buffer whenever stdout is a
    # pipe rather than a terminal. Redirected to a file or read from a CI log,
    # that put the whole of pip's output above the line explaining what was
    # about to run. Flushing here rather than at the call site because this is
    # the one place the file descriptor changes hands.
    sys.stdout.flush()
    sys.stderr.flush()
    try:
        return subprocess.run(command, check=False).returncode
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"hemlock: could not run {command[0]}: {exc}", file=sys.stderr)
        return 1
