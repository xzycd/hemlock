"""Structural fingerprints, for telling "the same code" from "the same text".

A campaign does not copy a file byte for byte. It runs the payload through a
minifier, or renames its variables, or moves the webhook URL into a different
string, and every one of those changes the hash while changing nothing about
what the code does. Comparing digests catches only the laziest version of the
attack, and comparing raw text catches whitespace.

So this compares shape. Source is tokenized, then everything an attacker gets
to choose freely is erased: identifiers become `id`, strings become `str`,
numbers become `num`, comments disappear. What survives is the grammar --
keywords, operators, brackets, and the order they arrive in. Two files that do
the same thing under different names normalize to the same token stream.

The token stream is then reduced to a fingerprint set by winnowing
(Schleimer, Wilkerson and Aiken, 2003). Every k-gram of tokens is hashed, a
window slides over those hashes, and the smallest hash in each window is kept.
The result is a fraction of the hashes, it is stable under insertion and
deletion elsewhere in the file, and it has the property the naive "sample
every nth hash" approach does not: any shared passage longer than the
guarantee threshold is certain to share at least one selected fingerprint.

That last property is what makes the comparison cheap. Fingerprints go into an
inverted index, and only files that already share one are ever compared in
full, so a lockfile with two thousand packages does not turn into two million
comparisons.

Nothing here decides anything. It answers one question -- how much structure
do these two files have in common -- and `campaign.py` decides what that means.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

# A k-gram is a run of K tokens; W of those form a winnowing window. Together
# they guarantee that any shared passage of at least K + W - 1 tokens shares a
# selected fingerprint. At 9 and 6 that is 14 tokens, which is a couple of
# statements: long enough that prose-level coincidence does not reach it, short
# enough that a small injected payload still registers.
K = 9
W = 6

# A Mersenne prime modulus, applied with `%` rather than a bitmask. Masking
# would reduce modulo 2**61, which does not agree with the modular inverse
# used to drop a token off the left of the window, and a rolling hash whose
# two halves disagree is not rolling: the same token run hashes differently
# depending on what preceded it, which quietly destroys the one property
# winnowing is chosen for.
_MOD = (1 << 61) - 1
_BASE = 1_000_003

# Below this a file has no shape worth comparing. A three-line shim is
# identical to every other three-line shim, and clustering on that would
# connect half of npm.
MIN_TOKENS = 120

# And below this a file has no *variety* worth comparing, however long it is.
# A barrel of two hundred re-exports, a generated constants table, a stub file
# of forty identical wrappers: these normalize to one short pattern repeated,
# so every one of them matches every other one of them while having nothing
# whatsoever in common. Length does not separate them from real code, but
# fingerprint count does, and by a wide margin -- a few hundred tokens of
# ordinary source yields scores of distinct fingerprints, and a barrel file
# yields two.
MIN_PRINTS = 12


@dataclass(frozen=True)
class Sketch:
    """One file, reduced to what can be compared across packages."""

    label: str  # short stable id, for printing
    tokens: int  # normalized token count, before winnowing
    prints: frozenset[int] = field(default=frozenset())

    def __bool__(self) -> bool:
        return bool(self.prints)


def similarity(a: Sketch, b: Sketch) -> float:
    """Jaccard overlap of two fingerprint sets, 0.0 to 1.0.

    This is the number worth printing, because it answers "are these the same
    file". It is not on its own the number worth deciding on: a payload
    appended to a large legitimate file is most of one side and a fraction of
    the other, and Jaccard reads that as barely related.
    """
    if not a.prints or not b.prints:
        return 0.0
    shared = len(a.prints & b.prints)
    if not shared:
        return 0.0
    return shared / len(a.prints | b.prints)


def containment(a: Sketch, b: Sketch) -> float:
    """How much of the smaller file appears in the larger one.

    This is what catches a payload injected into an existing file rather than
    shipped as its own. Used alone it would call every small file a part of
    every large one, so `shared_run` guards it with an absolute floor: the
    shared passage has to be big in its own right, not merely big relative to
    a file that was small to begin with.
    """
    if not a.prints or not b.prints:
        return 0.0
    return len(a.prints & b.prints) / min(len(a.prints), len(b.prints))


def shared_run(a: Sketch, b: Sketch) -> int:
    """Fingerprints in common. An absolute measure of how much code is shared."""
    return len(a.prints & b.prints)


# --------------------------------------------------------------------------
# tokenizing
# --------------------------------------------------------------------------

# Words that are structure rather than naming. An attacker can rename every
# identifier in a file; they cannot rename `if`. Both language sets are kept
# in one table because the normalizer only needs to know "is this word load
# bearing", and no word in either set means something else in the other.
_KEYWORDS = frozenset("""
    async await break case catch class const continue debugger default delete do
    else export extends finally for function if import in instanceof let new of
    return static super switch this throw try typeof var void while with yield
    and as assert def del elif except from global is lambda nonlocal not or pass
    raise
    true false null undefined none True False None
""".split())

# After one of these a slash opens a regular expression. After anything else
# -- a name, a number, a closing bracket -- it is division. This is the whole
# of the JavaScript lexer's famous ambiguity, and getting it wrong swallows
# the rest of the file as a string.
_REGEX_OK_AFTER = frozenset([
    "", "(", ",", "=", ":", "[", "!", "&", "|", "?", "{", "}", ";", "+", "-",
    "*", "%", "<", ">", "~", "^", "=>", "===", "!==", "==", "!=", "&&", "||",
    "return", "typeof", "instanceof", "in", "of", "new", "delete", "void",
    "throw", "case", "do", "else", "yield", "await",
])

_IDENT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_NUMBER = re.compile(r"0[xXbBoO][0-9a-fA-F_]+n?|\d[\d_]*(?:\.[\d_]*)?(?:[eE][+-]?\d+)?[njJ]?|\.\d[\d_]*")
# Longest first: `===` must win over `==`, which must win over `=`.
_PUNCT = sorted(
    [">>>=", "...", "===", "!==", "**=", "<<=", ">>=", ">>>", "&&=", "||=", "??=",
     "=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "++", "--", "+=", "-=",
     "*=", "/=", "%=", "&=", "|=", "^=", "**", "<<", ">>", ":=",
     "{", "}", "(", ")", "[", "]", ";", ",", "<", ">", "+", "-", "*", "/", "%",
     "&", "|", "^", "!", "~", "?", ":", "=", ".", "@", "#"],
    key=len, reverse=True,
)

# Punctuators bucketed by first character, longest first inside each bucket.
# Walking the flat list instead cost a `startswith` per entry per character,
# which on a large tree was most of the time this module spent.
_PUNCT_BY_HEAD: dict[str, list[str]] = {}
for _p in _PUNCT:
    _PUNCT_BY_HEAD.setdefault(_p[0], []).append(_p)

_LANG_BY_EXT = {".js": "js", ".mjs": "js", ".cjs": "js", ".ts": "js", ".tsx": "js",
                ".jsx": "js", ".py": "py", ".pyi": "py"}


def language_of(path: str) -> str | None:
    for ext, lang in _LANG_BY_EXT.items():
        if path.endswith(ext):
            return lang
    return None


def normalize(text: str, lang: str = "js") -> list[str]:
    """Reduce source to its structural token stream.

    One scanner covers both languages. They disagree about comment markers and
    about whether a slash can open a regex, and agree about everything the
    fingerprint is actually made of, so the differences are two flags rather
    than two lexers.
    """
    out: list[str] = []
    i, n = 0, len(text)
    last = ""  # last significant token, for the regex-or-division decision
    js = lang == "js"

    while i < n:
        ch = text[i]

        if ch in " \t\r\n\f\v":
            i += 1
            continue

        # comments
        if js and text.startswith("//", i):
            i = _to_eol(text, i)
            continue
        if js and text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        if not js and ch == "#":
            i = _to_eol(text, i)
            continue

        # strings, including python triple quotes and js template literals
        if ch in "\"'`":
            i = _skip_string(text, i, js)
            out.append("str")
            last = "str"
            continue

        if js and ch == "/" and last in _REGEX_OK_AFTER:
            j = _skip_regex(text, i)
            if j > i:
                i = j
                out.append("str")  # a literal is a literal, whatever its syntax
                last = "str"
                continue

        if m := _NUMBER.match(text, i):
            i = m.end()
            out.append("num")
            last = "num"
            continue

        if m := _IDENT.match(text, i):
            word = m.group(0)
            i = m.end()
            # A keyword is structure and is kept verbatim. A name is the
            # attacker's to choose, so it collapses to one token and stops
            # being a way to make the same code look different.
            token = word if word in _KEYWORDS else "id"
            out.append(token)
            last = token
            continue

        matched = ""
        for p in _PUNCT_BY_HEAD.get(ch, ()):
            if text.startswith(p, i):
                matched = p
                break
        if matched:
            i += len(matched)
            out.append(matched)
            last = matched
        else:
            i += 1  # something we do not model; skipping it is not evidence

    return out


def _to_eol(text: str, i: int) -> int:
    end = text.find("\n", i)
    return len(text) if end < 0 else end + 1


def _skip_string(text: str, i: int, js: bool) -> int:
    """Return the index just past the string literal starting at `i`."""
    n = len(text)
    quote = text[i]

    if not js and text.startswith(quote * 3, i):
        end = text.find(quote * 3, i + 3)
        return n if end < 0 else end + 3

    if js and quote == "`":
        # Template literals nest: `${ `${x}` }` is legal, and a scanner that
        # stops at the first closing brace loses the rest of the file.
        i += 1
        depth = 0
        while i < n:
            c = text[i]
            if c == "\\":
                i += 2
                continue
            if depth == 0 and c == "`":
                return i + 1
            if c == "$" and i + 1 < n and text[i + 1] == "{":
                depth += 1
                i += 2
                continue
            if depth and c == "}":
                depth -= 1
            elif depth and c in "\"'`":
                i = _skip_string(text, i, js)
                continue
            i += 1
        return n

    i += 1
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == quote:
            return i + 1
        if c == "\n" and not js:
            return i  # an unterminated single-quoted python string ends at the line
        i += 1
    return n


def _skip_regex(text: str, i: int) -> int:
    """Past a JavaScript regex literal, or `i` if this slash is division."""
    n = len(text)
    j = i + 1
    in_class = False
    while j < n:
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == "\n":
            return i  # regex literals do not span lines, so this was division
        if c == "[":
            in_class = True
        elif c == "]":
            in_class = False
        elif c == "/" and not in_class:
            j += 1
            while j < n and text[j].isalpha():  # flags
                j += 1
            return j
        j += 1
    return i


# --------------------------------------------------------------------------
# winnowing
# --------------------------------------------------------------------------


def _hashes(tokens: list[str]) -> list[int]:
    """Rolling hash of every K-token window, left to right.

    Rabin-Karp rather than a digest per k-gram: a large bundle is hundreds of
    thousands of k-grams, and each one here costs a multiply and an add.
    """
    if len(tokens) < K:
        return []

    cache: dict[str, int] = {}
    values = [cache[t] if t in cache else cache.setdefault(t, hash_token(t)) for t in tokens]
    high = pow(_BASE, K - 1, _MOD)

    h = 0
    for v in values[:K]:
        h = (h * _BASE + v) % _MOD
    out = [h]
    for idx in range(K, len(values)):
        h = ((h - values[idx - K] * high) * _BASE + values[idx]) % _MOD
        out.append(h)
    return out


def hash_token(token: str) -> int:
    """Stable across processes, unlike the builtin, because fingerprints are
    written to JSON and compared against a later run."""
    return int.from_bytes(hashlib.blake2b(token.encode(), digest_size=6).digest(), "big")


def _winnow(hashes: list[int]) -> set[int]:
    """Keep the minimum hash of every W-wide window.

    Ties go to the rightmost occurrence, which is what makes the selection
    stable: the same passage picks the same fingerprint wherever it appears,
    so an edit before it does not shift everything after it.
    """
    if len(hashes) <= W:
        return set(hashes[:1])

    kept: set[int] = set()
    window: list[tuple[int, int]] = []  # (hash, position), increasing by hash
    chosen = -1
    for pos, h in enumerate(hashes):
        while window and window[-1][0] >= h:
            window.pop()
        window.append((h, pos))
        while window[0][1] <= pos - W:
            window.pop(0)
        if pos >= W - 1 and window[0][1] != chosen:
            chosen = window[0][1]
            kept.add(window[0][0])
    return kept


def sketch(text: str, lang: str = "js") -> Sketch:
    """Fingerprint one file. Falsy when there is not enough structure to compare."""
    tokens = normalize(text, lang)
    if len(tokens) < MIN_TOKENS:
        return Sketch(label="", tokens=len(tokens))
    prints = _winnow(_hashes(tokens))
    if len(prints) < MIN_PRINTS:
        return Sketch(label="", tokens=len(tokens))
    return Sketch(label=label_for(prints), tokens=len(tokens), prints=frozenset(prints))


def label_for(prints: set[int] | frozenset[int]) -> str:
    """A short name for a fingerprint set, so a report can say which payload
    it means without printing a thousand integers."""
    if not prints:
        return ""
    digest = hashlib.blake2b(digest_size=3)
    for h in sorted(prints):
        digest.update(h.to_bytes(8, "big"))
    return digest.hexdigest()


def index(sketches: dict[str, Sketch]) -> dict[int, list[str]]:
    """Invert `key -> sketch` into `fingerprint -> keys`.

    Winnowing guarantees that files sharing a long enough passage share a
    fingerprint, so a pair absent from every bucket here cannot be similar and
    never needs comparing.
    """
    out: dict[int, list[str]] = {}
    for key, sk in sketches.items():
        for h in sk.prints:
            out.setdefault(h, []).append(key)
    return out


def candidates(sketches: dict[str, Sketch], max_bucket: int = 64) -> set[tuple[str, str]]:
    """Pairs worth comparing in full.

    A fingerprint shared by hundreds of files is a common idiom rather than a
    copied payload, and pairing everything in that bucket is how this becomes
    quadratic. Those buckets are dropped: anything genuinely copied shares far
    more than one fingerprint and will still be found through another.
    """
    pairs: set[tuple[str, str]] = set()
    for keys in index(sketches).values():
        if len(keys) < 2 or len(keys) > max_bucket:
            continue
        ordered = sorted(keys)
        for a_i, a in enumerate(ordered):
            for b in ordered[a_i + 1:]:
                pairs.add((a, b))
    return pairs
