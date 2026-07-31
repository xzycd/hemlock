# Changelog

## 0.4.0

The theme is the view. Every rule and every score from 0.3 is unchanged; what
changed is how much of it you can take in without reading.

### Added

- **A severity rail and a score gauge on every result.** The coloured edge
  down the left groups a package with its findings, and the bar in front of the
  number lets you rank eight results without reading any of them.

- **Direct colour.** The palette carries a 24-bit value and a 256-palette
  fallback for every entry, chosen from `COLORTERM`, `TERM` and `TERM_PROGRAM`.
  `--color always` now beats `NO_COLOR`, on the grounds that a flag typed just
  now is more specific than a variable exported months ago.

- **Clickable output.** Package names open their registry page and advisory ids
  open osv.dev, over OSC 8. Terminals that do not implement it ignore it; files
  and pipes do not, so links switch off when stdout is not a terminal.

- **`--format markdown`**, for scan and diff. Writes a GitHub callout, a table
  of findings and a folded evidence block, with a hidden marker so
  `gh pr comment --edit-last` replaces its own comment instead of stacking a
  new one on every push. `hemlock init` now writes that workflow.

- **A designed all-clear.** A clean scan says how much was read and, more
  usefully, which checks did not run. Anything else reads as a promise the tool
  cannot make.

- **A box around reported malware**, replacing the loose banner. It is the only
  box in the output, because the one rule that is not a judgement call should
  not look like the ones that are.

- `hemlock why` draws a route as a staircase rather than one line, since depth
  is what you are looking for. `hemlock rules` draws each weight beside its
  number. `hemlock explain` ends with the remedy.

- **A face.** Socrates drank hemlock, so the eyes are crossed out. It sits
  beside the wordmark and arrives a beat after the letters finish drawing.
  Terminals under 88 columns get the wordmark alone, because half a face
  wrapped onto the next line looks broken while no face looks deliberate.

- **Motion during a scan.** The spinner's colour walks up the purple ramp and
  back, over a bar whose leading cell is lit separately from its body. It runs
  on offline scans too, driven by real progress through the package list rather
  than a timer. Nothing is drawn for the first 150ms, so only a project big
  enough to make you wait ever sees it.

- **Repeated findings group.** One rule flagging thirty packages now prints
  once, with all thirty names, instead of thirty times with five lines each.
  Nothing at or above the `--fail-on` threshold is ever grouped, and critical
  and high never are, so whatever failed the build always gets its own block.

- **A scan that exits 1 says why**, and names the packages responsible. A wall
  of low-severity findings with a bare `1` at the end gives you no way to tell
  which line caused it, which is how a failing build becomes a build people
  rerun.

- **A release workflow.** Tagging publishes to PyPI over trusted publishing,
  with no API token in the repository, and attaches PEP 740 attestations. It
  refuses to publish if the tag does not match `__version__`, if the tests
  fail, or if the known-bad fixture has stopped being flagged.

### Fixed

- **The documented install command never worked.** `pip install hemlock-scan`
  and `pipx run hemlock-scan` have been in the README since 0.1 and nothing of
  that name has ever been on PyPI. That instruction was also written into the
  CI workflow `hemlock init` generates, so anyone who ran `init` got a pipeline
  that failed on its first run. Both now install from the repository, and a
  test pins it.

- **The version was written in two places and drifted.** `pyproject.toml` said
  `0.3.0` while the package said `0.4.0`, so the wheel carried the previous
  release number. Hatchling now reads it from `hemlock/__init__.py`.

### Changed

- Drawing primitives moved out of `report.py` into `ui.py`. `report.py` decides
  what goes on a line, `ui.py` decides how it looks.
- The ASCII fallback uses `+` for a finding branch so it stays distinguishable
  from the rail beside it.
- No line carries trailing whitespace.
- Counts of one are no longer pluralised.
- Repository links point at `github.com/xzycd/hemlock`, which is where the
  repository actually is.

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
