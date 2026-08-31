"""Unicode tag-character encoding helpers.

Codepoints U+E0000-U+E007F mirror ASCII but render as nothing in virtually every
UI. Text encoded this way is read by a model and invisible to the human reviewing
the same tool list -- which is exactly the asymmetry the smuggling module measures.
"""

from __future__ import annotations

import unicodedata

TAG_BASE = 0xE0000


def to_tags(text: str) -> str:
    """Encode ASCII text as invisible Unicode tag characters."""
    return "".join(chr(TAG_BASE + ord(ch)) for ch in text if ord(ch) < 0x80)


def from_tags(text: str) -> str:
    """Recover the ASCII hidden in tag characters, ignoring everything else."""
    return "".join(
        chr(ord(ch) - TAG_BASE) for ch in text if TAG_BASE <= ord(ch) <= TAG_BASE + 0x7F
    )


def strip_invisible(text: str) -> str:
    """What a human actually sees: format characters and tag characters removed."""
    return "".join(
        ch
        for ch in text
        if unicodedata.category(ch) != "Cf" and not TAG_BASE <= ord(ch) <= 0xE007F
    )
