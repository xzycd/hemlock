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
from datetime import UTC, datetime, timedelta

from .data import AFFIXES, CREDENTIAL_PATHS, HOMOGLYPHS, POPULAR
from .model import Context, Package, rule
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
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + cost)  # transposition
        if min(cur) > cutoff:
            return cutoff + 1
        prev2, prev = prev, cur
    return prev[-1]


def _bare(name: str) -> str:
    """Strip the npm scope so '@acme/react' compares against 'react'."""
    return name.split("/")[-1] if name.startswith("@") else name


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
    corpus = POPULAR.get(pkg.ecosystem, frozenset())
    if name in corpus or len(name) < 4:
        return
    for target in corpus:
        d = edit_distance(name, target, cutoff=2)
        if d and d <= 2 and abs(len(name) - len(target)) <= 2:
            yield f'{d} edit{"s" if d > 1 else ""} away from "{target}"'
            return


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
    corpus = POPULAR.get(pkg.ecosystem, frozenset())
    if name in corpus:
        return
    for affix in AFFIXES.get(pkg.ecosystem, []):
        for stripped in (
            re.sub(rf"^{affix}[-_.]", "", name),
            re.sub(rf"[-_.]{affix}$", "", name),
            re.sub(rf"^{affix}", "", name),
            re.sub(rf"{affix}$", "", name),
        ):
            if stripped != name and stripped in corpus and len(stripped) >= 4:
                yield f'"{stripped}" with "{affix}" attached'
                return


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
    text = " ".join(text.split())
    if len(text) <= width:
        return text
    cut = text[: width - 1]
    # Prefer a word boundary, but not if that throws most of the line away.
    space = cut.rfind(" ")
    return (cut[:space] if space > width * 0.6 else cut) + "…"


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
    src = pkg.resolved or pkg.spec or ""
    if pkg.meta.get("vcs") or re.match(r"^(git\+|git:|file:|link:|https?://(?!registry\.))", str(src)):
        if "registry.npmjs.org" in str(src) or "files.pythonhosted.org" in str(src):
            return
        yield _clip(str(src), 100)


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
        yield f"{pkg.version} published {when}"


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
    if current and history and current not in history:
        yield f'published by "{current}"; previous releases by {", ".join(sorted(set(history))[:3])}'


@rule(
    "HEM503",
    title="Release is unsigned",
    category="registry",
    weight=15,
    online=True,
    explain="""
    The registry has no signature for this artifact. npm signs published
    tarballs and can also carry a provenance attestation linking a release
    back to the CI run and commit that built it.

    Unsigned means older, or published from a laptop. It is not evidence of
    anything. It does mean that if you later need to prove what was in a
    release, there is nothing to check it against.
    """,
)
def unsigned_release(pkg: Package, ctx: Context):
    if pkg.ecosystem == "npm" and pkg.meta.get("signed") is False:
        yield "no registry signature or provenance attestation"


@rule(
    "HEM504",
    title="Deprecated or withdrawn",
    category="registry",
    weight=25,
    online=True,
    explain="""
    The maintainers or the registry have pulled this version back. Sometimes
    the deprecation message is where a compromise gets announced, so read it
    rather than just noting it.

    A yanked version that is still in your lockfile means your installs are
    pinned to something its own authors have retracted.
    """,
)
def deprecated_or_yanked(pkg: Package, ctx: Context):
    if pkg.meta.get("deprecated"):
        yield f"deprecated: {_clip(str(pkg.meta['deprecated']))}"
    if pkg.meta.get("yanked"):
        yield f"yanked: {_clip(str(pkg.meta.get('yanked_reason') or 'no reason given'))}"


@rule(
    "HEM505",
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
    "HEM506",
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
    "HEM507",
    title="Known vulnerability reported for this version",
    category="registry",
    weight=30,
    online=True,
    explain="""
    A published advisory covers the exact version installed. This is the one
    check here that overlaps with a conventional vulnerability scanner, and it
    is included because it is free: PyPI returns advisories inline with
    package metadata.

    Known vulnerabilities are the easy half of the problem. Everything else in
    this tool exists for the packages that no advisory has caught up with yet.
    """,
)
def known_vulnerable(pkg: Package, ctx: Context):
    seen = set()
    for adv in pkg.meta.get("vulnerabilities", []):
        ids = adv.get("aliases") or [adv.get("id", "advisory")]
        # The same advisory often arrives twice under different sources.
        if ids[0] in seen:
            continue
        seen.add(ids[0])
        yield f"{ids[0]}: {_clip(adv.get('summary') or adv.get('details') or '', 66)}"
        if len(seen) == 3:
            return


@rule(
    "HEM508",
    title="Release size jumped sharply",
    category="registry",
    weight=25,
    online=True,
    explain="""
    This version is several times larger than the one before it. Packages grow,
    but a utility library that triples in size in a patch release has gained
    something, and it is worth knowing what.

    Bundled payloads are heavier than the code they hide in. The size delta is
    often visible in registry metadata before anyone has unpacked the tarball.
    """,
)
def size_jump(pkg: Package, ctx: Context):
    now, before = pkg.meta.get("unpacked_size"), pkg.meta.get("prior_unpacked_size")
    if now and before and before > 20_000 and now > before * 3:
        yield f"{_kb(before)} -> {_kb(now)} since the previous release"


def _kb(n: int) -> str:
    return f"{n / 1024:.0f} KB" if n < 1024 * 1024 else f"{n / 1048576:.1f} MB"
