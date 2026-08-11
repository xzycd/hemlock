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

The 26 rules cover six areas:

| Area | Examples |
|---|---|
| Naming | typosquats, homoglyphs, dropped npm scopes |
| Install behavior | install hooks, downloads followed by execution, credential access |
| Source shape | obfuscation and dynamic execution |
| Lockfiles | floating versions, missing hashes, HTTP downloads, extra indexes |
| Registry trust | fresh or withdrawn releases, new publishers, missing repositories |
| Public records | build provenance, advisories, and exact malware reports |

Fifteen rules run offline. Online mode adds eleven checks backed by public npm,
PyPI, and OSV endpoints. Run `hemlock rules` for the full list and
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
git tag -s v0.8.1 -m "hemlock v0.8.1"
git push origin v0.8.1
```

The workflow runs lint, tests, and the known-bad fixture before it builds and
publishes the wheel and source archive.

## License

MIT. See [LICENSE](LICENSE).
