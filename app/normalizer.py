"""
Amharic Text Normalizer
------------------------
Handles:
- Similar-looking Ge'ez character variants (e.g. ሀ/ሃ/ሐ/ኀ/ኃ/ኸ/ኻ are often used
  interchangeably by casual writers and scammers trying to dodge keyword filters)
- Mixed Amharic/Latin (transliterated) text normalization
- Basic cleanup: extra spaces, repeated punctuation, emoji stripping (optional)
"""

import re
import unicodedata

# Groups of Amharic characters that are commonly confused / interchanged.
# Each group is normalized to its first (canonical) character.
HOMOGLYPH_GROUPS = [
    ["ሀ", "ሃ", "ሐ", "ሓ", "ኀ", "ኃ", "ኸ", "ኻ"],   # "ha" sounds
    ["ሰ", "ሠ"],                                    # "se" sounds
    ["አ", "ዐ"],                                    # "a" sounds
    ["ጸ", "ፀ"],                                    # "tse" sounds
    ["ኡ", "ዑ"],
    ["ኢ", "ዒ"],
    ["ኤ", "ዔ"],
    ["ኦ", "ዖ"],
]

_CANON_MAP = {}
for group in HOMOGLYPH_GROUPS:
    canonical = group[0]
    for ch in group:
        _CANON_MAP[ch] = canonical

# Common transliterated (Latin-script) Amharic scam words -> canonical Amharic
# so the rule engine only needs to check one form.
TRANSLITERATION_MAP = {
    "yikeffet": "ይከፈታል",
    "yitagedal": "ይታገዳል",
    "ansat": "አሸነፉ",
    "wetaj": "ወጣጅ",
    "birr": "ብር",
    "selam": "ሰላም",
}


def normalize_amharic_chars(text: str) -> str:
    """Collapse visually/phonetically similar Amharic characters to one canonical form."""
    return "".join(_CANON_MAP.get(ch, ch) for ch in text)


def normalize_transliteration(text: str) -> str:
    """Replace known Latin-script Amharic words with their canonical Amharic form."""
    lowered = text
    for latin, amharic in TRANSLITERATION_MAP.items():
        lowered = re.sub(rf"\b{re.escape(latin)}\b", amharic, lowered, flags=re.IGNORECASE)
    return lowered


def clean_whitespace_and_punctuation(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = re.sub(r"\s+", " ", text)          # collapse whitespace
    text = re.sub(r"([!?.])\1{1,}", r"\1", text)  # collapse repeated punctuation
    return text.strip()


def detect_script(text: str) -> str:
    """Return 'am' (Amharic/Ge'ez), 'en' (Latin), or 'mixed'."""
    has_geez = bool(re.search(r"[\u1200-\u137F]", text))
    has_latin = bool(re.search(r"[A-Za-z]", text))
    if has_geez and has_latin:
        return "mixed"
    if has_geez:
        return "am"
    if has_latin:
        return "en"
    return "unknown"


def normalize(text: str) -> dict:
    """
    Full normalization pipeline.
    Returns a dict with the cleaned text and detected script,
    so downstream modules (rule engine, ML model) get consistent input.
    """
    original = text
    text = clean_whitespace_and_punctuation(text)
    script = detect_script(text)
    text = normalize_amharic_chars(text)
    text = normalize_transliteration(text)
    return {
        "original": original,
        "normalized": text,
        "script": script,
    }


if __name__ == "__main__":
    samples = [
        "ሰላም! ሂሳብዎ ይታገዳል!!! አሁኑኑ ይህን ሊንክ ይጫኑ",
        "Selam, account'wo yitagedal, click here now",
        "You have won 50000 birr, claim yiketefal now",
    ]
    for s in samples:
        result = normalize(s)
        print(result)
