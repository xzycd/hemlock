"""The checks.

Each rule gets one package and yields evidence. Yielding nothing means the
rule did not fire. Weights live in the decorator so that tuning the scoring
never means touching detection logic.

A note on weights. Very few of these are damning alone. Plenty of honest
packages run install scripts, and plenty of good libraries have one
maintainer. The weights are calibrated so that a single signal reads as
"worth a glance" and three signals from different angles read as "stop the
build". See score.py for how that stacking works.
"""

from __future__ import annotations

import math
import os
import re
import unicodedata
import urllib.parse
from datetime import UTC, datetime, timedelta
from functools import lru_cache

from .data import AFFIXES, CREDENTIAL_PATHS, HOMOGLYPHS, POPULAR
from .model import RULES, Context, Package, rule
from .provenance import describe
from .pypi import normalize

# --------------------------------------------------------------------------
# naming
# --------------------------------------------------------------------------


def edit_distance(a: str, b: str, cutoff: int = 3) -> int:
    """Damerau-Levenshtein, abandoned early once it passes the cutoff."""
    if abs(len(a) - len(b)) > cutoff:
        return cutoff + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        low = i
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            best = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                best = min(best, prev2[j - 2] + cost)  # transposition
            cur[j] = best
            # Tracking the row minimum here rather than scanning the finished
            # row is worth doing: this loop runs tens of millions of times on
            # a large lockfile.
            if best < low:
                low = best
        if low > cutoff:
            return cutoff + 1
        prev2, prev = prev, cur
    return prev[-1]


def _bare(name: str) -> str:
    """Strip the npm scope so '@acme/react' compares against 'react'."""
    return name.split("/")[-1] if name.startswith("@") else name


# Corpus bucketed by name length, each entry carrying its set of characters.
# Built once per ecosystem, on first use.
_BUCKETS: dict[str, dict[int, list[tuple[str, frozenset]]]] = {}

NEAR = 2  # how many edits still counts as a near miss


def _buckets(ecosystem: str) -> dict[int, list[tuple[str, frozenset]]]:
    if ecosystem not in _BUCKETS:
        by_length: dict[int, list[tuple[str, frozenset]]] = {}
        for target in POPULAR.get(ecosystem, frozenset()):
            by_length.setdefault(len(target), []).append((target, frozenset(target)))
        _BUCKETS[ecosystem] = by_length
    return _BUCKETS[ecosystem]


@lru_cache(maxsize=8192)
def nearest(name: str, ecosystem: str) -> tuple[int, str] | None:
    """The closest popular name within two edits, or nothing.

    Comparing every name against the whole corpus was 93% of the runtime on a
    fifty thousand package lockfile, so two prefilters run first. Both are
    sound rather than heuristic: strings within two edits differ in length by
    at most two, and differ in at most two distinct characters, because each
    character present in one and missing from the other costs an edit of its
    own. What survives both goes to the dynamic programming.

    Ties break on the lower distance and then on the name, so the same
    lockfile always reports the same neighbour.
    """
    chars = frozenset(name)
    by_length = _buckets(ecosystem)
    best: tuple[int, str] | None = None
    for length in range(len(name) - NEAR, len(name) + NEAR + 1):
        for target, target_chars in by_length.get(length, ()):
            if len(chars - target_chars) > NEAR:
                continue
            d = edit_distance(name, target, cutoff=NEAR)
            if d and d <= NEAR and (best is None or (d, target) < best):
                best = (d, target)
    return best


@rule(
    "HEM101",
    title="Name is a near-miss of a popular package",
    category="naming",
    weight=30,
    explain="""
    The package name is one or two keystrokes away from something with
    millions of downloads. Typosquatting works because installs are typed by
    hand and read by nobody: `pip install requsts` fails silently upward into
    a working environment, and the tarball that lands runs with your
    permissions.

    The real cases are unremarkable to look at. `colourama` shipped a
    clipboard-watching crypto stealer to people reaching for `colorama`.
    `crossenv` on npm collected environment variables from anyone who missed
    the hyphen in `cross-env`.

    Check the name character by character against what you meant to install.
    If it is a transitive dependency, find out which of your direct
    dependencies asked for it. Legitimate packages rarely depend on
    near-misses of their own neighbours.
    """,
)
def near_miss(pkg: Package, ctx: Context):
    name = _bare(pkg.name).lower()
    if pkg.ecosystem == "pypi":
        name = normalize(name)
    if name in POPULAR.get(pkg.ecosystem, frozenset()) or len(name) < 4:
        return
    if hit := nearest(name, pkg.ecosystem):
        d, target = hit
        yield f'{d} edit{"s" if d > 1 else ""} away from "{target}"'


@rule(
    "HEM102",
    title="Popular name plus a plausible-looking affix",
    category="naming",
    weight=22,
    explain="""
    The name is a well-known package with a word bolted on that suggests an
    official variant: a `-js` suffix, a `python-` prefix, a `-sdk` tail. No
    typo is required. The victim reads the name, decides it is the Node build
    or the Python binding, and installs it.

    `python3-dateutil` sat on PyPI impersonating `python-dateutil` and pulled
    in a second squatted package that shipped a credential stealer. The name
    was not a mistake by anyone. It was a guess about what people would
    assume existed.

    Confirm the package against the project's own documentation or its
    repository, not against the registry search results.
    """,
)
def affix_impersonation(pkg: Package, ctx: Context):
    name = _bare(pkg.name).lower()
    if pkg.ecosystem == "pypi":
        name = normalize(name)
    if name in POPULAR.get(pkg.ecosystem, frozenset()):
        return
    if hit := wearing_affix(name, pkg.ecosystem):
        stripped, affix = hit
        yield f'"{stripped}" with "{affix}" attached'


# The four ways an affix can be worn, compiled once per ecosystem instead of
# per package. Rebuilding them inside the rule cost two and a half million
# regex cache lookups on a fifty thousand package lockfile.
_AFFIX_FORMS: dict[str, list[tuple[str, tuple]]] = {}


def _affix_forms(ecosystem: str) -> list[tuple[str, tuple]]:
    if ecosystem not in _AFFIX_FORMS:
        _AFFIX_FORMS[ecosystem] = [
            (affix, (re.compile(rf"^{affix}[-_.]"), re.compile(rf"[-_.]{affix}$"),
                     re.compile(rf"^{affix}"), re.compile(rf"{affix}$")))
            for affix in AFFIXES.get(ecosystem, [])
        ]
    return _AFFIX_FORMS[ecosystem]


@lru_cache(maxsize=8192)
def wearing_affix(name: str, ecosystem: str) -> tuple[str, str] | None:
    """A popular name with something bolted on, or nothing."""
    corpus = POPULAR.get(ecosystem, frozenset())
    for affix, forms in _affix_forms(ecosystem):
        for form in forms:
            stripped = form.sub("", name, count=1)
            if stripped != name and stripped in corpus and len(stripped) >= 4:
                return stripped, affix
    return None


@rule(
    "HEM103",
    title="Name contains a look-alike character",
    category="naming",
    weight=55,
    explain="""
    The name carries a character that is not the ASCII letter it renders as: a
    Cyrillic letter where you read an `a`, an en dash where you read a hyphen.
    Two names that are visually identical are two different packages to the
    registry, and only one of them is the one you audited.

    PyPI's `jeIlyfish` used a capital I in place of the two l's in
    `jellyfish` and ran for a year. That one was pure ASCII; with Unicode
    there is no rendering difference at all to catch.

    Nothing legitimate needs this. Treat it as intentional.
    """,
)
def homoglyph_name(pkg: Package, ctx: Context):
    for ch in pkg.name:
        if ch in HOMOGLYPHS:
            try:
                label = unicodedata.name(ch)
            except ValueError:
                label = f"U+{ord(ch):04X}"
            yield f'"{ch}" ({label}) reads as "{HOMOGLYPHS[ch]}"'
        elif ord(ch) > 127:
            yield f"non-ASCII character U+{ord(ch):04X}"


@rule(
    "HEM104",
    title="Unscoped copy of a scoped package name",
    category="naming",
    weight=28,
    explain="""
    An npm scope is an ownership boundary: only the owner of `@types` can
    publish under `@types`. The bare registry namespace has no such boundary,
    so `types-node` is available to anyone, and it looks close enough to
    `@types/node` to survive a code review.

    This is the same shape as dependency confusion, where a public package
    is published under the name of one of your internal private ones and the
    resolver picks the public copy because its version number is higher. Alex
    Birsan used exactly that to reach build systems at dozens of large
    companies in 2021.

    If you meant the scoped package, the `@` is not optional.
    """,
)
def scope_drop(pkg: Package, ctx: Context):
    if pkg.ecosystem != "npm" or pkg.name.startswith("@"):
        return
    for sep in ("-", "_", "."):
        if sep not in pkg.name:
            continue
        head, tail = pkg.name.split(sep, 1)
        if f"@{head}/{tail}" in POPULAR["npm"] or head in {"types", "babel", "angular", "vue", "nestjs"}:
            yield f'resembles the scoped package "@{head}/{tail}"'
            return


# --------------------------------------------------------------------------
# install-time execution
# --------------------------------------------------------------------------

HOOK_KEYS = ("preinstall", "install", "postinstall", "prepare", "prepublish")

_FETCH_RUN = re.compile(
    r"(curl|wget|Invoke-WebRequest|iwr)\b[^\n|;]{0,200}[|;]\s*(sudo\s+)?(ba|z|d|)?sh\b"
    r"|(curl|wget)\b[^\n]{0,200}-o\s*\S+[^\n]{0,80};\s*(chmod|\./|sh\s)"
    r"|node\s+-e\s+[\"'].{0,40}(http|require\()"
    r"|python3?\s+-c\s+[\"'].{0,40}(urllib|requests|socket)",
    re.I,
)

_DECODE_EXEC = re.compile(
    r"(base64\s+(-d|--decode)|atob\s*\(|Buffer\.from\([^)]*base64|"
    r"b64decode|codecs\.decode|fromCharCode)"
    r"[\s\S]{0,300}?(eval|exec|Function\s*\(|child_process|spawn|subprocess|os\.system)"
    r"|(eval|exec)[\s\S]{0,80}(atob|base64|b64decode|fromCharCode)",
    re.I,
)


def _hooks(pkg: Package) -> dict[str, str]:
    return {k: v for k, v in pkg.scripts.items() if k in HOOK_KEYS}


@rule(
    "HEM201",
    title="Runs a script at install time",
    category="install",
    weight=18,
    explain="""
    The package executes a command when it is installed, before any of your
    code imports it and before any test runs. `npm ci` in CI is enough to
    trigger it.

    On its own this is ordinary. Native modules compile, CLIs link binaries,
    and thousands of honest packages do this every day. It matters because it
    is the delivery mechanism every npm worm has used: Shai-Hulud propagated
    entirely through `postinstall`, harvesting cloud credentials and GitHub
    tokens and then republishing itself into whatever other packages the
    stolen account could reach.

    Low weight by design. Look at it when something else about the package is
    already odd. If you want the blanket fix, `npm ci --ignore-scripts` turns
    the whole class off, and you can allow the handful you actually need.
    """,
)
def install_hook(pkg: Package, ctx: Context):
    hooks = _hooks(pkg)
    if hooks:
        yield ", ".join(f"{k}: {_clip(v)}" for k, v in hooks.items())
    elif pkg.meta.get("hasInstallScript"):
        yield "lockfile records an install script (node_modules not present to read it)"


@rule(
    "HEM202",
    title="Install script downloads and executes",
    category="install",
    weight=45,
    explain="""
    An install hook pulls something off the network and runs it. Whatever you
    reviewed in the published tarball is now irrelevant, because the code that
    actually executes lives on a server the author controls and can change
    after the fact, including after a security audit, and including
    selectively based on who is asking.

    Build tooling does sometimes fetch prebuilt binaries this way. The
    difference is that legitimate cases fetch a versioned, checksummed
    artifact from a host tied to the project. Fetch-and-pipe-to-shell is not
    that.

    Read the URL. If you cannot tell what it serves, do not install the
    package.
    """,
)
def hook_fetches_and_runs(pkg: Package, ctx: Context):
    for name, body in _hooks(pkg).items():
        if _FETCH_RUN.search(body):
            yield f"{name}: {_clip(body)}"


@rule(
    "HEM203",
    title="Install script decodes an encoded payload",
    category="install",
    weight=40,
    explain="""
    The hook decodes a blob and hands the result to an interpreter. The blob
    is the actual program; the visible script is a loader. This exists to beat
    anyone reading the package with their eyes and anyone grepping it for
    strings.

    There is no benign version of this. A build step that needs to run a
    program ships the program.
    """,
)
def hook_decodes_payload(pkg: Package, ctx: Context):
    for name, body in _hooks(pkg).items():
        if _DECODE_EXEC.search(body):
            yield f"{name}: {_clip(body)}"


@rule(
    "HEM204",
    title="Install script touches credentials",
    category="install",
    weight=50,
    explain="""
    The hook references a path or variable that holds secrets: SSH keys, AWS
    credentials, an npm token, a `.env` file, the macOS keychain. A package
    being installed has no reason to know these exist.

    This is the payload half of most registry attacks rather than the delivery
    half. The `ctx` package on PyPI, and a forged copy of the `phpass` PHP
    library, both did nothing but read environment variables and post
    everything that looked like an AWS key to a remote endpoint. Shai-Hulud
    went after `GITHUB_TOKEN` and cloud credentials for the same reason:
    stolen tokens let it publish, and publishing let it spread.

    If this fired on something you already installed, the credentials it can
    reach should be considered exposed. Rotate first, investigate after.
    """,
)
def hook_reads_credentials(pkg: Package, ctx: Context):
    for name, body in _hooks(pkg).items():
        hits = [p for p in CREDENTIAL_PATHS if p.lower() in body.lower()]
        if hits:
            yield f"{name} references {', '.join(sorted(set(hits))[:4])}"


def _clip(text: str, width: int = 88) -> str:
    """Evidence is data. It goes into JSON, SARIF and CI logs as well as onto
    a terminal, so the marker is three dots rather than a typographic ellipsis
    that some consumer downstream will have to cope with."""
    text = " ".join(text.split())
    if len(text) <= width:
        return text
    cut = text[: width - 3]
    # Prefer a word boundary, but not if that throws most of the line away.
    space = cut.rfind(" ")
    return (cut[:space] if space > width * 0.6 else cut) + "..."


# --------------------------------------------------------------------------
# code shape
# --------------------------------------------------------------------------

_CODE_EXT = {".js", ".mjs", ".cjs", ".ts", ".py"}
_MAX_FILES = 40
_MAX_BYTES = 2_000_000


def _source_files(pkg: Package):
    if not pkg.source_dir:
        return
    seen = 0
    for dirpath, dirnames, filenames in os.walk(pkg.source_dir):
        dirnames[:] = [d for d in dirnames if d not in {"node_modules", "test", "tests", "__pycache__"}]
        for fn in filenames:
            if os.path.splitext(fn)[1] not in _CODE_EXT:
                continue
            path = os.path.join(dirpath, fn)
            try:
                # A package can contain a symlink to anywhere on the machine.
                # Reading through it adds no evidence about the package bytes
                # and can make a scan open unrelated local files.
                if os.path.islink(path):
                    continue
                if os.path.getsize(path) > _MAX_BYTES:
                    continue
                yield path, open(path, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            seen += 1
            if seen >= _MAX_FILES:
                return


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


@rule(
    "HEM301",
    title="Source looks deliberately unreadable",
    category="code",
    weight=35,
    explain="""
    A file in this package is a wall of hex escapes, a single enormous line,
    or a high-entropy string blob. Minified code looks like this too, which is
    why the check looks at where the file sits: a bundle under `dist/` is
    expected, the same thing sitting next to readable source is not.

    Obfuscation in a dependency is worth a question regardless of intent,
    because it means nobody downstream is reviewing that code, including the
    people who would otherwise have caught a change to it. The compromised
    `chalk` and `debug` releases carried a bundled crypto-address swapper that
    nobody spotted until it was already installed billions of times a week.

    Compare against the package's repository. If the published artifact
    contains code that the repository does not, that gap is the finding.
    """,
)
def obfuscated_source(pkg: Package, ctx: Context):
    for path, text in _source_files(pkg):
        rel = os.path.relpath(path, pkg.source_dir)
        if any(part in ("dist", "build", "bundle", "umd", "esm") for part in rel.split(os.sep)):
            continue
        if rel.endswith((".min.js", ".min.ts")):
            continue

        hex_escapes = text.count("\\x") + text.count("\\u")
        if hex_escapes > 200 and hex_escapes * 4 > len(text) * 0.15:
            yield f"{rel}: {hex_escapes} hex escapes"
            continue

        longest = max((len(line) for line in text.splitlines()), default=0)
        if longest > 5000 and text.count("\n") < 20:
            yield f"{rel}: single line of {longest} characters"
            continue

        for blob in re.findall(r"['\"][A-Za-z0-9+/=_-]{500,}['\"]", text):
            if entropy(blob) > 4.5:
                yield f"{rel}: {len(blob)}-char blob, entropy {entropy(blob):.1f}"
                break


@rule(
    "HEM302",
    title="Builds code at runtime",
    category="code",
    weight=25,
    explain="""
    The package assembles a string and executes it: `eval`, `new Function`,
    `exec` on something constructed rather than literal. Static analysis stops
    at that boundary, which is exactly why it is there when it is malicious.

    There are real uses: template engines, serializers, a few polyfills. Those
    tend to be the package's whole reason for existing, and it will be obvious
    from the name. A logging helper that evaluates strings is not that.
    """,
)
def dynamic_eval(pkg: Package, ctx: Context):
    pattern = re.compile(
        r"\beval\s*\(\s*(?!['\"]?\s*\))|new\s+Function\s*\(|"
        r"\bexec\s*\(\s*(?:[a-z_]\w*\s*[+%]|f['\"])|__import__\s*\(",
        re.I,
    )
    for path, text in _source_files(pkg):
        rel = os.path.relpath(path, pkg.source_dir)
        hits = pattern.findall(text)
        if len(hits) >= 2:
            yield f"{rel}: {len(hits)} dynamic-execution sites"


# --------------------------------------------------------------------------
# pinning and integrity
# --------------------------------------------------------------------------


@rule(
    "HEM401",
    title="Version is not pinned",
    category="lockfile",
    weight=12,
    explain="""
    The requirement accepts versions that do not exist yet. `*`, `latest` and
    an open-ended range all mean the same thing operationally: whatever the
    author publishes next is what you will install, without review.

    Every account-takeover attack depends on this. When `chalk` was hijacked,
    the malicious release was a patch bump, so it reached everyone whose range
    allowed patch updates, which is nearly everyone, within minutes.

    Commit a lockfile and install from it. Pinning in the manifest alone is
    not enough, because it says nothing about transitive dependencies.
    """,
)
def floating_version(pkg: Package, ctx: Context):
    spec = (pkg.spec or "").strip()
    if not spec or pkg.version:
        return
    if spec in ("*", "", "latest", "x") or spec.startswith(("^", "~", ">", "*")):
        yield f'"{pkg.name}" requested as "{spec or "*"}"'


@rule(
    "HEM402",
    title="Lockfile entry has no integrity hash",
    category="lockfile",
    weight=20,
    explain="""
    The lockfile pins a version but records no hash for it. The version number
    then only identifies which artifact to ask for, not which artifact you
    agreed to. If the registry serves different bytes tomorrow, nothing
    notices.

    npm writes an `integrity` field automatically, and pip will enforce hashes
    if you give it any (`--require-hashes`). An entry missing one is usually a
    hand-edit or a package installed from somewhere that does not provide one.
    """,
)
def missing_integrity(pkg: Package, ctx: Context):
    if pkg.version and not pkg.integrity and not pkg.meta.get("link") and pkg.origin.endswith(
        ("package-lock.json", "npm-shrinkwrap.json", "Pipfile.lock")
    ):
        yield f"{pkg.coord} pinned without a hash"


@rule(
    "HEM403",
    title="Resolved over plain HTTP",
    category="lockfile",
    weight=30,
    explain="""
    The artifact is fetched over HTTP. Anyone on the path between the build
    machine and the registry can replace it, and on a shared or cloud network
    that is not a hypothetical.

    No major registry needs this any more. An `http://` URL in a modern
    lockfile is either a mirror that was configured badly or a line somebody
    edited by hand.
    """,
)
def insecure_transport(pkg: Package, ctx: Context):
    if pkg.resolved and pkg.resolved.startswith("http://"):
        yield pkg.resolved


_OFF_REGISTRY = re.compile(r"^(git\+|git:|file:|link:|https?://)")
_REGISTRY_HOSTS = frozenset({"registry.npmjs.org", "files.pythonhosted.org"})


def _is_registry_url(src: str) -> bool:
    try:
        parsed = urllib.parse.urlsplit(src)
        return (
            parsed.scheme in {"http", "https"}
            and parsed.hostname in _REGISTRY_HOSTS
            and parsed.username is None
            and parsed.password is None
        )
    except ValueError:
        return False


def _off_registry(pkg: Package) -> str:
    """Where a package came from, when that is not the registry.

    Two rules need this answered the same way: one reports the source, and one
    has to stay quiet about a name the registry was never going to hold.
    """
    src = str(pkg.resolved or pkg.spec or "")
    if _is_registry_url(src):
        return ""
    return src if (pkg.meta.get("vcs") or _OFF_REGISTRY.match(src)) else ""


@rule(
    "HEM404",
    title="Installed from outside the registry",
    category="lockfile",
    weight=22,
    explain="""
    The dependency comes from a git URL, a tarball URL or a local path rather
    than the registry. That source has no publishing history, no maintainer
    record and no signature, so most of the checks in this tool have nothing
    to work with.

    A git dependency pinned to a branch is the sharpest version of this: the
    contents change whenever someone pushes, and your lockfile still looks
    unchanged. Pin to a commit SHA if you must depend on one.
    """,
)
def off_registry_source(pkg: Package, ctx: Context):
    if source := _off_registry(pkg):
        yield _clip(source, 100)


@rule(
    "HEM405",
    title="An additional package index is configured",
    category="lockfile",
    weight=25,
    explain="""
    The requirements file adds an index beyond the default. With
    `--extra-index-url`, pip queries both and takes the highest version it
    finds. It does not prefer your private one. Anyone who learns the name of
    an internal package can publish a copy to PyPI with a huge version number
    and win the resolution.

    That is dependency confusion, and it is a configuration bug rather than a
    compromise: use `--index-url` to replace the default outright, and mirror
    what you need through your own index.
    """,
)
def alternate_index(pkg: Package, ctx: Context):
    for url in pkg.meta.get("extra_indexes", []):
        if "pypi.org" not in url:
            yield f"resolves against {url} as well as PyPI"


# --------------------------------------------------------------------------
# registry trust (requires --online)
# --------------------------------------------------------------------------


@rule(
    "HEM501",
    title="This version was published very recently",
    category="registry",
    weight=25,
    online=True,
    explain="""
    A brand-new release of an established package, before anyone has had time
    to look at it. This is the shape of a hijack: the account is stolen, a
    patch version goes out, and the window between publication and discovery
    is where all the damage happens. For `chalk` and `debug` that window was
    about two hours, and two billion weekly downloads flowed through it.

    Freshness is not suspicious by itself, because packages get released. It is
    useful as a filter. Combined with a changed publisher or a new install
    script, it is the single most actionable signal here.

    Adjust the window with `--fresh-days`. A cooldown period on your
    dependency updates costs very little and closes most of this.
    """,
)
def fresh_release(pkg: Package, ctx: Context):
    published = pkg.meta.get("published_at")
    if not published:
        return
    age = datetime.now(UTC) - published
    if age < timedelta(days=ctx.fresh_days):
        hours = int(age.total_seconds() // 3600)
        when = f"{hours} hours ago" if hours < 48 else f"{age.days} days ago"
        # A bare name on the command line carries no version of its own, and
        # this read "None published 3 hours ago". The registry says which
        # version it answered with; `pkg.version` stays whatever the manifest
        # pinned, because `floating_version` reads it to mean exactly that.
        which = pkg.version or pkg.meta.get("resolved_version")
        yield f"{which} published {when}" if which else f"published {when}"


@rule(
    "HEM502",
    title="Published by a different account than usual",
    category="registry",
    weight=45,
    online=True,
    explain="""
    npm records which account uploaded each individual version. This version
    came from an account that did not publish the ones before it.

    Sometimes that is a new co-maintainer or a release bot. Sometimes it is
    the entire attack: the `event-stream` backdoor arrived when the original
    author handed the package to a volunteer who had asked politely for it,
    and who then added a dependency that stole Bitcoin wallets. The takeover
    of `ua-parser-js` looked the same from the registry's side.

    The question this raises is answerable in about a minute. Does the new
    publisher appear in the project's repository? Did a maintainer announce
    the handover? If the answer to both is no, do not install it.
    """,
)
def publisher_change(pkg: Package, ctx: Context):
    current = pkg.meta.get("publisher")
    history = pkg.meta.get("prior_publishers") or []
    if not current or not history or current in history:
        return
    others = ", ".join(history[:3]) + (f" and {len(history) - 3} others" if len(history) > 3 else "")
    yield f'published by "{current}", who had not published this package before; earlier releases by {others}'


@rule(
    "HEM503",
    title="Deprecated or withdrawn",
    category="registry",
    weight=25,
    online=True,
    explain="""
    The maintainers or the registry have pulled this version back. Sometimes
    the deprecation message is where a compromise gets announced, so read it
    rather than just noting it.

    A yanked version still sitting in your lockfile means your installs are
    pinned to something its own authors have retracted.
    """,
)
def deprecated_or_yanked(pkg: Package, ctx: Context):
    if pkg.meta.get("deprecated"):
        yield f"deprecated: {_clip(str(pkg.meta['deprecated']))}"
    if pkg.meta.get("yanked"):
        yield f"yanked: {_clip(str(pkg.meta.get('yanked_reason') or 'no reason given'))}"


@rule(
    "HEM504",
    title="Almost nobody installs this",
    category="registry",
    weight=20,
    online=True,
    explain="""
    Very low download numbers. Harmless for a niche library, and meaningful
    the moment it lines up with a name that resembles something popular: a
    typosquat's downloads come from mistakes, so they stay low while the
    package it imitates has millions.

    Worth a second look when the package arrived as a transitive dependency
    you did not choose.
    """,
)
def low_reach(pkg: Package, ctx: Context):
    downloads = pkg.meta.get("downloads")
    if downloads is not None and downloads < 500:
        yield f"{downloads} downloads in the last week"


@rule(
    "HEM505",
    title="No source repository",
    category="registry",
    weight=15,
    online=True,
    explain="""
    The package does not say where its source lives, so there is nothing to
    compare the published artifact against. You cannot review what you cannot
    find, and you cannot tell whether the tarball matches the code.

    Attackers omit this because a repository invites inspection and because
    maintaining a convincing fake one is work.
    """,
)
def repo_missing(pkg: Package, ctx: Context):
    if pkg.meta.get("repo_missing"):
        yield "no repository URL in registry metadata"


@rule(
    "HEM506",
    title="Release size jumped sharply",
    category="registry",
    weight=25,
    online=True,
    explain="""
    This version is several times larger than the one before it. Packages
    grow, but a utility library that triples in size in a patch release has
    gained something, and it is worth knowing what.

    Bundled payloads are heavier than the code they hide in, and the size
    delta shows up in registry metadata before anyone has unpacked the
    tarball.
    """,
)
def size_jump(pkg: Package, ctx: Context):
    now, before = pkg.meta.get("unpacked_size"), pkg.meta.get("prior_unpacked_size")
    if now and before and before > 20_000 and now > before * 3:
        yield f"{_kb(before)} -> {_kb(now)} since the previous release"


def _kb(n: int) -> str:
    return f"{n / 1024:.0f} KB" if n < 1024 * 1024 else f"{n / 1048576:.1f} MB"


@rule(
    "HEM507",
    title="The registry has no package by this name",
    category="registry",
    weight=35,
    online=True,
    explain="""
    The registry answered that it holds nothing under this name. That is not
    a clean result, and it is not something you can install either.

    There are two readings and they want different answers. The first is a
    typo. The spelling is the whole finding, and correcting it ends the
    matter. What you should not do is leave the misspelling sitting in a
    manifest for later: names people get wrong are the names that get
    claimed, and whoever claims one inherits every install that repeats the
    mistake.

    The second reading is dependency confusion. An internal package name is
    absent from the public registry only until somebody else publishes it,
    and a resolver asked for a name that then exists in two places usually
    takes the higher version number rather than the closer index. Alex Birsan
    collected internal names from leaked manifests and public JavaScript in
    2021, published packages under those names, and had code executing inside
    Apple, Microsoft, PayPal and more than thirty other companies. Every one
    of those names looked exactly like this the day before he took it.

    Which reading applies is a question about the name, not about the
    registry. Keep an internal name behind a single index you control, or
    register it in public yourself so that nobody else can.
    """,
)
def not_published(pkg: Package, ctx: Context):
    if not pkg.meta.get("unpublished"):
        return
    # A workspace member, an editable checkout or a git dependency was never
    # going to be on the registry, so its absence there is not a signal.
    # HEM404 already reports where those actually come from.
    if any(pkg.meta.get(k) for k in ("workspace", "link", "vcs")) or _off_registry(pkg):
        return
    yield f"{'npm' if pkg.ecosystem == 'npm' else 'PyPI'} has no package under this name"


# --------------------------------------------------------------------------
# build provenance (requires --online)
# --------------------------------------------------------------------------

# Both registries supported attested publishing well before this date, so a
# release made after it had the option available and did not take it. Older
# releases predate the tooling and are not judged for it.
PROVENANCE_EXPECTED_FROM = datetime(2025, 1, 1, tzinfo=UTC)


@rule(
    "HEM601",
    title="Published without build provenance",
    category="provenance",
    weight=20,
    online=True,
    explain="""
    The registry holds no attestation tying this release to a repository, a
    workflow and a commit. Somebody uploaded a file, and there is no way to
    check that the file matches any source you can read.

    This mattered less when the alternative did not exist. It does now. npm
    began revoking classic publish tokens in December 2025 and finished in
    early 2026, which leaves trusted publishing as the ordinary path, and
    trusted publishing emits provenance automatically. PyPI has carried PEP
    740 attestations since late 2024. A release made after either of those
    landed, with no provenance attached, was published some other way.

    Ordinary reasons exist: an older project, a maintainer releasing from a
    laptop, a registry mirror. Low weight for exactly that reason. What it
    removes is your ability to answer the next question, which is whether the
    tarball matches the tag.
    """,
)
def no_provenance(pkg: Package, ctx: Context):
    if pkg.meta.get("provenance"):
        return
    published = pkg.meta.get("published_at")
    if published and published >= PROVENANCE_EXPECTED_FROM:
        yield f"published {published:%Y-%m-%d} with no attestation on the registry"


@rule(
    "HEM602",
    title="Provenance points at a different repository",
    category="provenance",
    weight=55,
    online=True,
    explain="""
    The package tells you its source lives in one repository. The signed
    attestation says the artifact was built from another. One of those is
    wrong, and the attestation is the one backed by a signature.

    This is the shape of an attack that survives review. You are sent to a
    clean repository, you read clean code, and you install a build made
    somewhere else. Before attestations existed there was no way to notice;
    the published tarball and the tagged source were simply two things nobody
    compared.

    Forks and release automation in a separate repository produce this
    legitimately, so check before you panic. What you want to confirm is that
    the repository named in the attestation is one the maintainers control
    and have said they build from.
    """,
)
def provenance_mismatch(pkg: Package, ctx: Context):
    prov = pkg.meta.get("provenance") or {}
    built = prov.get("repository")
    declared = pkg.meta.get("declared_repo")
    if built and declared and built != declared:
        yield f"declared {declared}, but built from {describe(prov)}"


# --------------------------------------------------------------------------
# public intelligence (requires --online)
# --------------------------------------------------------------------------


@rule(
    "HEM701",
    title="This exact version is reported as malware",
    category="intel",
    weight=100,
    online=True,
    certain=True,
    explain="""
    osv.dev carries a record naming this version as malicious. That is not an
    inference drawn from the signals in this tool; somebody analysed the
    package, wrote it up, and published the finding to a database that npm,
    PyPI and every scanner downstream reads.

    Because it is a report rather than a judgement, it does not get scored
    against anything else. The verdict is 100 and the other rules stop
    mattering.

    The feed is large. An OSV mirror pulled in May 2026 held roughly 226,000
    malicious-package records across npm and PyPI, which is what a registry
    under sustained automated attack looks like. hemlock skips any record OSV
    has withdrawn, because in May 2026 OSV pulled 157 malware reports that an
    automated classifier had raised against trusted packages, and tools that
    had already ingested them kept failing builds over nothing.

    If this fired on something installed: remove it, then rotate every
    credential the install had reach over. Look up the record id on osv.dev
    for what the payload actually did.
    """,
)
def known_malware(pkg: Package, ctx: Context):
    for report in pkg.meta.get("malware", []):
        aliases = f" ({', '.join(report['aliases'][:2])})" if report.get("aliases") else ""
        yield f"{report['id']}{aliases}: {_clip(report['summary'], 70)}"


@rule(
    "HEM702",
    title="Published advisory against this version",
    category="intel",
    weight=30,
    online=True,
    explain="""
    An advisory covers the exact version installed, from osv.dev, which
    aggregates GitHub Security Advisories, PyPA, and the ecosystem databases
    into one place.

    This is the one check here that overlaps with a conventional
    vulnerability scanner, and it is included because a single batched
    request covers the whole dependency list for free. Known vulnerabilities
    are the easy half of the problem; everything else in this tool exists for
    the packages no advisory has caught up with yet.

    Look the ids up at osv.dev/vulnerability/<id>.
    """,
)
def known_advisory(pkg: Package, ctx: Context):
    advisories = pkg.meta.get("advisories") or []
    if not advisories:
        return
    shown = ", ".join(advisories[:4])
    more = f" and {len(advisories) - 4} more" if len(advisories) > 4 else ""
    yield f"{len(advisories)} advisor{'y' if len(advisories) == 1 else 'ies'}: {shown}{more}"


# --------------------------------------------------------------------------
# what to do about it
# --------------------------------------------------------------------------

# One line per rule, imperative, no hedging. These are kept together rather
# than spread through the decorators so the set can be read at once: a report
# where every third entry says "investigate further" is a report nobody acts
# on, and that only shows up when you see them side by side.
REMEDIES = {
    "HEM101": "Compare the name against what you meant to install, then find out which dependency asked for it.",
    "HEM102": "Confirm the package against the project's own documentation, not against registry search results.",
    "HEM103": "Nothing legitimate needs a look-alike character. Remove it.",
    "HEM104": "If you meant the scoped package, the @scope is not optional.",
    "HEM201": "Install with scripts off unless this package needs them: npm ci --ignore-scripts",
    "HEM202": "Read the URL it fetches. If you cannot tell what it serves, do not install this.",
    "HEM203": "There is no benign version of this. Remove it.",
    "HEM204": "Treat every credential it could reach as exposed. Rotate first, investigate after.",
    "HEM301": "Compare the published artifact against the package's own repository.",
    "HEM302": "Check whether building code at runtime is what this package is for. Usually it is not.",
    "HEM401": "Pin the version and commit a lockfile.",
    "HEM402": "Regenerate the lockfile so the entry carries a hash.",
    "HEM403": "Point the resolver at an https registry.",
    "HEM404": "Pin to a commit rather than a branch, or move the dependency to the registry.",
    "HEM405": "Replace the default index with --index-url rather than adding one with --extra-index-url.",
    "HEM501": "Let the release age, or read the diff before taking it.",
    "HEM502": "Check whether the new publisher appears in the project's repository or release notes.",
    "HEM503": "Read the deprecation message, then move to whatever it points at.",
    "HEM504": "Find out which dependency asked for this before trusting it.",
    "HEM505": "Prefer a package whose source you can read.",
    "HEM506": "Find out what the extra weight is before installing it.",
    "HEM507": "Check the spelling first. If the name is one of your own, claim it in public or point the "
              "resolver at a single index you control.",
    "HEM601": "Nothing to fix directly. It costs you the ability to check the tarball against the tag.",
    "HEM602": "Confirm the maintainers control the repository the attestation names.",
    "HEM701": "Remove it, then rotate every credential the install could reach.",
    "HEM702": "Upgrade past the affected range. Every id above resolves at osv.dev.",
}

for _rule_id, _remedy in REMEDIES.items():
    RULES[_rule_id].fix = _remedy
