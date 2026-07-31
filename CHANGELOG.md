# Changelog

## 0.5.1

The first release that is actually on PyPI. 0.5.0 built a correct wheel and
uploaded nothing, because the trusted publisher had not been registered yet.

### Fixed

- **`hemlock check <name>` no longer calls signed packages unsigned.** PEP 740
  attestations attach to a file, so finding one needs a version. The npm branch
  resolved `latest` before looking and the PyPI branch did not, so a name given
  without a version skipped the lookup entirely and HEM601 fired on everything.
  hemlock's own release was the first thing it accused, which is how this was
  found: `hemlock check hemlock-scan --online` reported no build provenance for
  an artifact whose attestation is on PyPI right now.

- **A fresh release names the version it found.** HEM501 read `None published
  0 hours ago` for a package named without one. The registry now records what
  it resolved, and `pkg.version` still means what the manifest pinned, because
  HEM401 reads it to mean exactly that.

### Changed

- **Install instructions point at PyPI again.** `pipx install hemlock-scan`,
  and the workflow written by `hemlock init` installs the same. They pointed
  at git for three releases because nothing of that name was published. The
  test that guarded it now reads the distribution name out of `pyproject.toml`
  instead of hard-coding a URL, so a rename cannot go out while every
  generated workflow still names the old one.

- `hemlock update` needed no change to switch over. It asks PyPI first and
  falls back to the repository's tags, so a copy installed from git before
  0.5.0 landed still upgrades, and one installed from PyPI is told to use pip.

## 0.5.0

The theme is scale. A tool that is pleasant on a twelve package example and
unusable on a real monorepo has only been tested on the easy case.

### Added

- **`hemlock update`.** Checks PyPI, falls back to the repository's tags,
  works out whether this copy came from pipx, pip or a git checkout, and
  builds the right command. Then it shows you that command and asks. There is
  no silent self-update: a tool whose entire argument is that running somebody
  else's install step is the risk does not get to make an exception for its
  own. `--check` reports only, `--yes` skips the question, and with no
  terminal to answer at it prints the command and stops. `hemlock --update`
  is the same thing.

- **A generated banner**, at `docs/banner.svg`, drawn from the same glyph
  table and palette the terminal uses. A test regenerates it and fails if the
  committed file has drifted, so the README cannot end up advertising a
  version of the brand that no longer exists.

### Changed

- **A 55,000 package lockfile now scans in 1.7 seconds, down from 17.9.**
  Comparing every name against the typosquat corpus was 93% of the runtime.
  Two prefilters run before the dynamic programming now: strings within two
  edits differ in length by at most two, and in at most two distinct
  characters. Both are sound rather than heuristic, and a test checks every
  single-edit mutation of every corpus entry against the brute-force sweep
  they replaced. The affix rule was rebuilding its regexes per package, which
  is two and a half million cache lookups it no longer does.

- **Results group by their whole finding signature**, not by a single rule.
  Those 55,000 packages produced 4,745 findings in nine distinct shapes, so
  the report went from 999 lines to 69. High collapses too now, because
  sixteen byte-identical blocks is one finding and fifteen scrolls, and every
  member of a group carries the same score by construction. Reported malware
  and critical still always stand alone, and a group at or above your
  `--fail-on` threshold lists every name it holds rather than capping.

- **The nearest typosquat match is now the closest one**, and stable. The old
  sweep returned whichever match set iteration happened to reach first, so two
  runs could name different neighbours for the same package.

### Fixed

- **The wordmark shredded on a narrow terminal.** It read the report's width,
  which floors at 60 so report columns cannot collapse, and so never learned
  the terminal was 30 columns wide. There are four sizes now and it steps down
  rather than wrapping, ending at a plain name under about 34 columns.

## 0.4.1

### Added

- **`hemlock check`.** Judge a package by name, with no project around it:
  `hemlock check chalk@5.6.1 --online`. A scan tells you about a decision you
  already made; this answers the question you have a minute earlier, when a
  README has just told you to install something. Offline it is a name check
  and says so on its second line, because there is no source or lockfile
  behind a name typed into a shell. Online it reaches osv.dev, build
  provenance and publisher history, which is where it earns its keep.

- **Status words during a scan.** The line reads `Grazing…`, then something
  else five to ten seconds later. The bar underneath is still real progress
  through a real list; the word and the spinner are time passing and say
  nothing about how far along anything is.

- **The wordmark at the top of an interactive scan**, not only on bare
  `hemlock`. Off under CI, off without a terminal, off when stdout is
  redirected, off with `--no-logo` or `HEMLOCK_NO_LOGO`.

### Changed

- **The palette was a rainbow.** Magenta, orange, yellow, teal and green on
  one screen cannot be ranked at a glance, so the reader falls back on the
  numbers, which is what the colour was there to save them. Severity is now
  one warm ramp that heats up, purple is the brand and never means a severity,
  and low sits close to grey because a wall of low findings is background.

- **The live display moved onto its own thread.** It used to redraw from
  inside the work loop, so a scan blocked on a slow registry sat with a frozen
  spinner, which reads as a hung process.

### Fixed

- **CI had never passed.** The step that writes SARIF scanned the known-bad
  fixture without `--fail-on never`, so hemlock exited 1 by design and the
  step read that as its own failure. The weekly live-registry job had the same
  bug and its assertion was unreachable behind it. A test now fails if any
  step in `ci.yml` captures a report and gates on it.

- **CI ran on pushes to `main`.** The default branch is `master`, so no push
  to it ever ran the suite.

- **Evidence carried a typographic ellipsis.** Clipped evidence goes into
  JSON, SARIF and CI logs as well as onto a terminal, so the marker is three
  dots now. It was also the one non-ASCII character the ASCII fallback leaked.

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
