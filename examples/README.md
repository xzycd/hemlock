# Fixtures

## compromised-app

A project built to be caught. Nothing in it is real and nothing in it runs:
the install scripts `curl` from `.invalid` domains, which do not resolve by
design, and the "payload" files are random characters. Treat it the way you
would treat an EICAR test file — it exists so that a scanner has something
known-bad to prove itself against.

Each dependency is planted to trip a specific rule:

| Package | What it imitates | Rules it should trip |
|---|---|---|
| `colorz` | `colors` | HEM101 near-miss, HEM201 install hook, HEM202 fetch-and-run, HEM204 credential access |
| `сhalk` | `chalk` — the first letter is Cyrillic `с` | HEM103 look-alike character, HEM101 near-miss |
| `types-node` | `@types/node` | HEM104 unscoped copy, HEM403 plain HTTP, HEM402 no integrity |
| `express-js` | `express` | HEM102 affix, HEM402 no integrity |
| `analytics-helper` | nothing — it is just hostile | HEM203 encoded payload, HEM301 obfuscation, HEM302 runtime eval, HEM404 off-registry |
| `express` | itself | none, and that is the point |
| `requsts` | `requests` | HEM101 near-miss |
| `python3-dateutil` | `python-dateutil` | HEM101 near-miss |
| `requirements.txt` | — | HEM405 extra index |

Run it:

```bash
hemlock scan examples/compromised-app
```

The CI `detection` job asserts this fixture still comes back critical, so a
rule that silently stops firing breaks the build rather than the next release.
