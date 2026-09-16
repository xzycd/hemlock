<div align="center">

<img src="docs/banner.svg" alt="hemlock" width="820">

**Poison hemlock looks like parsley.**

Static supply-chain checks for npm and PyPI packages.

[![ci](https://github.com/xzycd/hemlock/actions/workflows/ci.yml/badge.svg)](https://github.com/xzycd/hemlock/actions/workflows/ci.yml)
[![pypi](https://img.shields.io/pypi/v/hemlock-scan)](https://pypi.org/project/hemlock-scan/)
[![python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![dependencies](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)](#privacy-and-trust)

</div>

Hemlock looks for dependency behavior that deserves a closer look: near-miss
names, install hooks, obfuscated source, weak lockfile entries, unusual
publisher changes, missing build provenance, and versions reported as malware.
It works offline by default and never executes package code.

It also compares your packages against each other, because the compromises
that matter now arrive several packages at a time.

This is not a model or a black-box score. Every result includes the rule,
evidence, remedy, and arithmetic that produced it.

## Install

```bash
pipx install hemlock-scan
```

Python 3.11 or newer is required. A normal pip install works too:

```bash
pip install hemlock-scan
```

Hemlock has no runtime dependencies.

## Use

```bash
hemlock scan .                    # scan a project offline
hemlock scan . --online           # add registry, provenance, and OSV checks
hemlock check chalk@5.6.1         # check a name before installing it
hemlock diff --since origin/main  # inspect only dependency changes
hemlock history . --online        # check versions previously held in git
hemlock why left-pad              # show which dependency brought it in
hemlock baseline .                # accept the current backlog
hemlock explain HEM701            # explain one rule and its remedy
hemlock rules                     # list every rule and weight
hemlock init                      # write config and CI files
hemlock update                    # offer the correct update command
```

Scans and diffs support terminal, Markdown, JSON, and SARIF output. Hemlock
finds npm and Python manifests below the chosen directory, including common
lockfiles and requirements files. If installed source is present under
`node_modules` or a local virtual environment, the static source checks read
it without following file symlinks.

An unprefixed package passed to `check` is treated as npm. Prefix Python
packages with `pypi:` or pass `--ecosystem pypi`:

```bash
hemlock check pypi:requests==2.32.3 --online
```

`hemlock update` does not silently install anything. It detects pip, pipx, or
a git checkout, prints the command, and asks before running it. Use `--check`
to report only or `--yes` to skip the question.

## What it reports

The 29 rules cover seven areas:

| Area | Examples |
|---|---|
| Naming | typosquats, homoglyphs, dropped npm scopes |
| Install behavior | install hooks, downloads followed by execution, credential access |
| Source shape | obfuscation and dynamic execution |
| Lockfiles | floating versions, missing hashes, HTTP downloads, extra indexes |
| Registry trust | fresh or withdrawn releases, new publishers, missing repositories |
| Public records | build provenance, advisories, and exact malware reports |
| Correlated activity | one payload, one endpoint, or one new account across several packages |

Seventeen rules run offline. Online mode adds twelve checks backed by public
npm, PyPI, and OSV endpoints. Run `hemlock rules` for the full list and
`hemlock explain HEMxxx` for the reason behind a rule.

An exact malware record is treated as a fact and settles the verdict. Other
signals are weighted. Repeated findings in one category count less after the
first, while agreement across categories increases the result. The report
prints this calculation under each package.

Severity bands are:

| Score | Severity |
|---:|---|
| 85 to 100 | critical |
| 60 to 84 | high |
| 30 to 59 | medium |
| 1 to 29 | low |

The default failure threshold is high. Change it with
`--fail-on low|medium|high|critical|never` or in `.hemlock.toml`.

## Packages judged together

Every rule below HEM800 judges one package on its own. That is the right unit
for a typosquat and the wrong one for what has been happening to npm.

A modern compromise is not one bad package. It is one payload, pushed into
however many packages a stolen token could reach. Shai-Hulud put the same
`bundle.js` behind a `postinstall` in hundreds of them over a weekend, all
reporting to one webhook. Read one of those on its own and you get a package
that runs a script at install time: a medium, the kind of finding a busy
repository already has forty of. Read six together and you have the incident.

So Hemlock compares packages against each other as well as judging them alone:

- **The same code.** Install-time source is tokenized and everything an
  attacker picks freely is erased — identifiers become `id`, string contents
  and numbers go entirely, comments disappear. What is left is compared by
  winnowed fingerprints. Renaming every variable, re-minifying the file, and
  changing the address it reports to all leave the match intact.
- **The same endpoint.** Hosts reached from install-time code, once
  registries, runtimes, the large CDNs and the package's own declared
  repository are removed.
- **The same new account.** One publisher behind several packages, counted
  only where that account is new to each of them.

Linked packages are reported as one campaign, above the per-package list,
through rules HEM801 to HEM803. The first two read installed code, so run them
against a tree that has been installed, and an accepted campaign stops being
reported like any other baselined finding.

Because correlation is an ordinary rule category, it is weighted, suppressed,
baselined and serialized by the same machinery as everything else, and the
existing "categories that agree count for more" arithmetic does the escalation
without a second scoring system.

On the bundled fixture, four packages that score 18 apiece alone score 100
together:

```
  correlated  packages that arrived together ──────────  1 campaign · 4 packages

  ▌ C1  4 packages sharing one install payload, one endpoint
  ▌
  ▌                              1  2
  ▌   fs-metadata 2.1.4          ●  ●
  ▌   nuxt-icon-set 0.9.2        ●  ●
  ▌   swc-loader-utils 2.1.4     ●  ●
  ▌   dom-serialize-fast 2.1.4   ●  ·
  ▌
  ▌    1  payload 21e21f
  ▌       identical code in 4 packages under 4 separate owners, compared after
  ▌       names and strings are removed (first seen as scripts/setup.js)
  ▌    2  endpoint telemetry-collect.example.invalid
  ▌       reached from the install path of 3 packages
  ▌
  ▌   Read one at a time, 4 of these come back as a low finding and no build
  ▌   stops. They are one finding in several places. Remove them together.
```

Five guards keep this quiet on honest projects, and each exists because
without it something large and innocent lights up:

- Only code an install would actually execute is fingerprinted — files named
  by a hook, declared binaries, declared entry points — rather than every file
  in the tree. A vendored helper under `dist/` is shared by thousands of
  packages and means nothing.
- Packages that share an owner are never linked to each other. A monorepo
  publishing one helper across its own scope is a build system.
- A host or an account shared by more than sixty owners is an idiom, not an
  incident. This cap deliberately does not apply to a shared payload: several
  hundred separate owners shipping identical install code has one explanation.
- A publish burst is never a link on its own. Half a dependency tree moves in
  the same week for dull reasons; timing corroborates a link that already
  exists.
- Code that is one pattern repeated — a barrel of re-exports, a generated
  constants table, forty identical stubs — is not compared at all. These
  normalize to the same short stream however different their contents are, so
  without this every generated file in the tree matches every other one.

Turn it off with `--no-correlate` or `correlate = false` in `.hemlock.toml`.

## Changes and history

A full scan answers what is in the tree now. Two other commands answer more
specific questions.

`hemlock diff` compares the working tree with a valid git revision, or compares
two manifest files. It reports packages that were added, updated, or removed
and scores only the additions and updates.

```bash
hemlock diff --since HEAD~1 --online
hemlock diff old/package-lock.json new/package-lock.json
```

`hemlock history` reads lockfile blobs from the mainline git history. It can
show when a version entered and left the project, which tagged releases held
it, and whether OSV now reports it as malware. The default limit is 200
manifest commits, and the report says when that window was truncated or the
checkout is shallow.

```bash
hemlock history . --online
hemlock history . --package chalk
```

## Existing projects

A baseline lets an established project adopt Hemlock without turning every old
finding into a new CI failure:

```bash
hemlock baseline .
git add .hemlock-baseline.json
```

The baseline fingerprint includes the package version. Updating a dependency
raises its findings again. Pass `--ignore-baseline` to include accepted
findings in the active result.

## CI

`hemlock init` creates `.hemlock.toml` and a GitHub Actions workflow. Pull
requests are checked as diffs. Pushes scan the full tree, and the scheduled job
also checks lockfile history. Generated workflows pin Hemlock and third-party
Actions to exact versions or commits.

A small manual setup looks like this:

```yaml
- run: pip install hemlock-scan
- run: hemlock diff --since origin/${{ github.base_ref }} --online --fail-on high
```

Exit codes are `0` when the threshold is clear, `1` when a finding reaches it,
and `2` when the command cannot run.

## Configuration

Configuration is optional. Put `.hemlock.toml` at the project root:

```toml
fail_on = "high"
fresh_days = 14
correlate = true

[[ignore]]
rule = "HEM201"
package = "esbuild"
reason = "compiles a reviewed native binary during installation"
expires = "2027-01-01"
```

Expired suppressions are reported instead of applied. Invalid configuration is
rejected with a clear error rather than silently falling back to defaults.

## Privacy and trust

Offline scans make no network requests. Online mode talks only to public npm,
PyPI, and OSV services. It needs no account or API key, and sends no telemetry.
Responses are cached for six hours under `~/.cache/hemlock`. HTTP response and
gzip expansion sizes are bounded, and cache entries are replaced atomically.

Releases are built from version-matched tags through PyPI trusted publishing.
The workflow stores no PyPI token and attaches PEP 740 attestations. Its
third-party Actions are pinned to full commit hashes.

Hemlock is also static by design. It reads package metadata and source but does
not execute install hooks or imported code.

## Limits

- Hemlock is not a complete CVE scanner. Use `osv-scanner`, `pip-audit`, or
  `npm audit` for full known-vulnerability coverage.
- It is not a sandbox and cannot prove a package is safe.
- Provenance rules read the registry's verified result. They do not yet verify
  the Sigstore bundle locally.
- Correlation reads code that is installed. A lockfile names versions rather
  than containing them, so HEM801 and HEM802 need `node_modules` or a local
  virtual environment on disk; run them after an install. A scan that had
  nothing to read says so rather than reporting a quiet all-clear.
- The payload and endpoint comparisons are effectively npm-only today. They
  read install hooks and declared entry points, and a wheel has neither.
  HEM803 needs the per-version publisher that npm records and PyPI does not.
- Correlation compares install-time code, so a payload that only runs when the
  package is imported is outside what it reads. It can also link two packages
  that genuinely vendor the same code under different owners, which is a true
  statement that may not be the one you wanted; HEM801 is suppressible like any
  other rule.
- Heuristics can produce false positives. Suppressions and baselines exist for
  reviewed cases.
- Only npm and PyPI are supported.

## Development

```bash
git clone https://github.com/xzycd/hemlock
cd hemlock
pip install -e ".[dev]"
ruff check hemlock tests
pytest -q
```

Tests use local fixtures and stubbed registry responses. The deliberately bad
project under `examples/compromised-app` is inert: payloads are random text and
all remote addresses use `.invalid` domains. See
[examples/README.md](examples/README.md) for the fixture map.

## Releasing

Only a version-matched tag can publish. Update `hemlock/__init__.py` and the
changelog, then create an annotated tag after the release commit reaches the
default branch:

```bash
git tag -s v0.9.0 -m "hemlock v0.9.0"
git push origin v0.9.0
```

The workflow runs lint, tests, and the known-bad fixture before it builds and
publishes the wheel and source archive.

## License

MIT. See [LICENSE](LICENSE).
