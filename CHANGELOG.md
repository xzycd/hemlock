# Changelog

## 0.3.0

The theme is adoption. Version 0.2 could tell you a lot about a codebase and
very little about what to do next, and it could not be introduced to a project
that already had a backlog.

### Added

- **Baselines.** `hemlock baseline` records every current finding as accepted.
  After that a scan reports only what is new, so a project with four hundred
  existing findings can adopt the tool on a Tuesday instead of never. A
  committed baseline applies automatically, because CI should stop failing on
  the backlog without anyone remembering a flag. `--ignore-baseline` shows
  everything again.

  The fingerprint includes the version, so a dependency that moves re-raises
  everything about itself. Accepting a finding in March says nothing about the
  release that landed last night.

- **`hemlock why <package>`.** Several rules ended by telling you to find out
  which dependency pulled a package in, which was poor advice from a tool that
  could not answer it. It can now: `graph.py` builds the edges from lockfiles
  it already read, following npm's own resolution order so a nested copy wins
  over a hoisted one. Transitive findings in the normal scan view gained a
  `via` line showing the route.

- **A remedy on every finding.** One imperative line per rule, kept together in
  `rules.py` rather than spread through the decorators, so the whole set can be
  read at once. A report where every third entry says "investigate further" is
  a report nobody acts on, and that only shows up side by side.

- **`hemlock init`.** Writes a commented `.hemlock.toml` and a GitHub workflow
  that judges pull requests as diffs and everything else as full scans. Neither
  file is overwritten if it already exists.

- **A wordmark.** Five rows of block letters in a purple gradient, from an
  alphabet that knows exactly seven letters. It animates in about 200ms on an
  interactive terminal and stays out of the way everywhere else: never under
  CI, never without colour, never in front of JSON.

- Scans report how long they took.

## 0.2.0

The theme is signals that only became available recently, plus a way to review
a change instead of a whole repository.

### Added

- **`HEM701`, known malware.** Queries osv.dev, which aggregates the OpenSSF
  malicious-packages feed, and reports when a record names the exact version
  installed. Withdrawn records are skipped: OSV pulled 157 false-positive
  malware reports in May 2026, and a scanner that keeps failing builds on a
  retracted record is worse than no scanner.
- **`HEM702`, published advisories**, from the same batched OSV request.
  Replaces the PyPI-only advisory check and now covers npm as well.
- **`HEM601` and `HEM602`, build provenance.** Reads npm SLSA attestations and
  PyPI PEP 740 attestations. `HEM602` fires when the repository that signed the
  build is not the repository the package points you at.
- **`hemlock diff`.** Scores only what a change added or moved, against two
  manifests or any git ref via `--since`. Exits non-zero on the same thresholds
  as `scan`.
- Rules can be marked `certain`, which settles a verdict without scoring it.
  Only `HEM701` is.
- Terminal output gained a malware banner, change markers in the diff view,
  staged progress with a spinner, and a request/cache line in online mode.

### Changed

- **Rule ids were renumbered.** `503→601`, `504→503`, `505→504`, `506→505`,
  `507→702`, `508→506`. Update `.hemlock.toml` if it names any of those. This
  was a pre-release cleanup and ids are stable from here.
- `HEM601` replaces the old "release is unsigned" check. Registry signatures
  are now universal enough to say nothing; provenance is the signal that
  replaced them.
- All online work goes through one cached HTTP layer, so OSV costs one batched
  request for the whole dependency list rather than one per package.

### Fixed

- **`HEM502` false positive on pinned older versions.** Prior publishers were
  taken from the most recent releases rather than the ones preceding the
  version in question, so `express@4.18.2` looked like an account takeover
  because the 5.x line has different maintainers.

## 0.1.0

First release. Twenty-three rules across naming, install-time execution, code
shape, pinning and registry trust. Terminal, JSON and SARIF output, a
transparent scoring model, and `hemlock explain`.
