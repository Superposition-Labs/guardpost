"""Order-free full-name key (Factory v2 ``same-person.ts`` nameToken, registrationNameKey).

A byte-for-byte port: the same Cyrillic table, the same Latin folds in the
same order, the same JavaScript whitespace (``String.prototype.trim`` and
``/\\s+/``, which differ from Python's ``str.strip``/``str.split``: JS trims
U+FEFF and not U+001C..U+001F or U+0085).

"Алина Синичкина" == "Alina Sinichkina" == "Sinichkina Alina" -> "alina sinichkina".
"""

from __future__ import annotations

import re

_CYRILLIC_PLAIN = "абвгдезийклмнопрстуфыэ"
_LATIN_PLAIN = "abvgdeziiklmnoprstufie"

CYRILLIC_TO_LATIN: dict[str, str] = {
    **dict(zip(_CYRILLIC_PLAIN, _LATIN_PLAIN, strict=True)),
    "ё": "e",
    "ж": "zh",
    "х": "h",
    "ц": "ts",
    "ч": "ch",
    "ш": "sh",
    "щ": "sch",
    "ъ": "",
    "ь": "",
    "ю": "iu",
    "я": "ia",
}

# Applied in this order, each to the whole token (JS replaceAll).
FOLDS: tuple[tuple[str, str], ...] = (
    ("kh", "h"),
    ("y", "i"),
    ("j", "i"),
    ("w", "v"),
    ("ph", "f"),
    ("x", "ks"),
)

# ECMAScript WhiteSpace + LineTerminator: the set trim() strips and \s matches.
_JS_WS = "\t\n\v\f\r    -     　﻿"
_JS_SPLIT_RE = re.compile(f"[{_JS_WS}]+")
_JS_TRIM_RE = re.compile(f"^[{_JS_WS}]+|[{_JS_WS}]+$")
_NON_LATIN_RE = re.compile(r"[^a-z]")
_REPEAT_RE = re.compile(r"(.)\1+")


def js_trim(value: str) -> str:
    """``String.prototype.trim``."""
    return _JS_TRIM_RE.sub("", value)


def name_token(token: str) -> str:
    """Fold one name part so Cyrillic and the usual Latin spellings meet."""
    out = "".join(CYRILLIC_TO_LATIN.get(ch, ch) for ch in token.lower())
    for src, dst in FOLDS:
        out = out.replace(src, dst)
    return _REPEAT_RE.sub(r"\1", _NON_LATIN_RE.sub("", out))


def registration_name_key(
    first_name: str | None,
    last_name: str | None,
    display_name: str | None = None,
    email: str | None = None,
) -> str | None:
    """The sorted, folded name tokens, or None.

    None unless two parts of two letters or more remain: a first name alone
    matches strangers. First + last name win over the display name; a display
    name that is just the email's local part is not a name.
    """
    raw = js_trim(" ".join(p for p in (first_name, last_name) if p and js_trim(p)))
    if not raw:
        raw = js_trim(display_name or "")
    if not raw or (email and raw.lower() == email.split("@")[0].lower()):
        return None
    tokens = [name_token(t) for t in _JS_SPLIT_RE.split(raw) if t]
    tokens = [t for t in tokens if len(t) >= 2]
    if len(tokens) < 2:
        return None
    return " ".join(sorted(tokens))
