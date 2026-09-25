"""
entropy.py
Shannon entropy scoring and context analysis, used to catch secrets that don't
match a known vendor format (e.g. a random internal service token) and to help
confirm "generic" regex matches aren't just placeholder text like "changeme123".

Regex alone misses homegrown tokens. Entropy alone is too noisy (UUIDs,
hashes, base64 blobs of non-secret data all score high). Combining them -
"looks like an assignment AND is statistically random" - is what keeps the
false-positive rate usable in a real report.
"""

import math
import re
import string
from collections import Counter

B64_CHARSET = set(string.ascii_letters + string.digits + "+/=")
HEX_CHARSET = set(string.hexdigits)

# candidate token extraction: quoted strings, or bare tokens of length >= 20
TOKEN_RE = re.compile(r"""['"]([A-Za-z0-9+/=_\-]{12,})['"]|(?<![A-Za-z0-9])([A-Za-z0-9+/=_\-]{20,})(?![A-Za-z0-9])""")

COMMON_PLACEHOLDER_WORDS = {
    "changeme", "placeholder", "yourapikeyhere", "example", "xxxxxxxx",
    "todo", "fixme", "dummy", "test", "sample", "insert_key_here",
    "your_api_key", "replace_me", "secret_key_here", "insert_token_here",
    "your_secret_here", "mysecrettoken", "your_password", "admin12345",
}

# Context signals indicating likely credential assignments
POSITIVE_CONTEXT_RE = re.compile(
    r"(?i)\b(api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|"
    r"secret[_-]?key|jwt[_-]?secret|jwt|password|passwd|pwd|private[_-]?key|token|"
    r"bearer|signature|credentials?|db_pass|encryption[_-]?key|session[_-]?secret|secret)\b\s*[:=]"
)

# Context signals indicating documentation, test, mock, or placeholder usage
NEGATIVE_CONTEXT_RE = re.compile(
    r"(?i)(\b(example|sample|mock|fixture|fake|dummy|test|placeholder|demo|stub)\b"
    r"|<[^>]+>|YOUR_[A-Z0-9_]+|INSERT_[A-Z0-9_]+|REPLACE_[A-Z0-9_]+|TODO|FIXME)"
)

# Commit references and SHA pins to ignore
COMMIT_REFERENCE_CONTEXT_RE = re.compile(
    r"(?i)("
    r"uses:\s*\S+@[0-9a-f]{7,40}\b"          # GitHub Actions SHA pin
    r"|\brev:\s*['\"]?[0-9a-f]{7,40}\b"      # pre-commit config revision
    r"|subproject\s+commit\s+[0-9a-f]{40}\b" # git submodule pointer
    r"|\b(commit|sha1?|revision)\s*[:=]\s*['\"]?[0-9a-f]{7,40}\b"
    r")"
)


def is_git_commit_reference(line: str) -> bool:
    return bool(COMMIT_REFERENCE_CONTEXT_RE.search(line))


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def looks_like_placeholder(token: str) -> bool:
    lower = token.lower()
    if lower in COMMON_PLACEHOLDER_WORDS:
        return True
    if len(set(token)) <= 2:  # e.g. "xxxxxxxxxxxxxxxx"
        return True
    if re.fullmatch(r"0+|1+|x+|X+", token):
        return True
    if re.search(r"^(abcde|12345|qwerty|01234)", lower):
        return True
    # Placeholder template indicators like <YOUR_KEY> or ${SECRET}
    return bool(token.startswith("<") and token.endswith(">") or token.startswith("${") and token.endswith("}"))


URL_RE = re.compile(r"https?://\S+")


def extract_candidate_tokens(line: str):
    """
    Pull plausible secret-like substrings out of a line of code.

    URL path/anchor fragments are excluded here: a long hyphenated slug in
    a documentation link scores as high-entropy under the same test as a real
    token, but it's public, non-secret content.
    """
    url_spans = [m.span() for m in URL_RE.finditer(line)]

    def overlaps_url(start, end):
        return any(start >= us and end <= ue for us, ue in url_spans)

    tokens = []
    for match in TOKEN_RE.finditer(line):
        token = match.group(1) or match.group(2)
        if token and not overlaps_url(*match.span()):
            tokens.append(token)
    return tokens


def is_high_entropy_secret(token: str, base64_threshold=4.3, hex_threshold=3.2, min_length=16) -> bool:
    """
    Returns True if a token is statistically likely to be a real secret
    rather than a word, path, or placeholder.
    """
    if len(token) < min_length:
        return False
    if looks_like_placeholder(token):
        return False

    charset = set(token)
    entropy = shannon_entropy(token)

    if charset <= HEX_CHARSET and len(token) >= 32:
        return entropy >= hex_threshold
    if charset <= B64_CHARSET:
        return entropy >= base64_threshold

    # mixed-charset generic string (letters+digits+symbols) - use a higher bar
    return entropy >= 4.6


def evaluate_entropy_context(token: str, line: str, file_path: str = "") -> dict:
    """
    Evaluates an entropy match in the context of its surrounding line and file.
    Returns dictionary with:
      - is_secret: bool
      - confidence: "HIGH" | "MEDIUM" | "LOW"
      - reason: contextual explanation for the score
    """
    if not is_high_entropy_secret(token):
        return {"is_secret": False, "confidence": "LOW", "reason": "Low entropy or placeholder format"}

    has_positive_context = bool(POSITIVE_CONTEXT_RE.search(line))
    has_negative_context = bool(NEGATIVE_CONTEXT_RE.search(line))

    # Auth/config file boost
    is_auth_file = bool(re.search(r"(?i)(\.env|credentials|secrets|auth|config|settings)\b", file_path))

    if has_negative_context:
        return {
            "is_secret": True,
            "confidence": "LOW",
            "reason": "High-entropy token detected, but line contains example/documentation/mock context",
        }

    if has_positive_context and is_auth_file:
        return {
            "is_secret": True,
            "confidence": "HIGH",
            "reason": "High-entropy token with explicit credential assignment in configuration file",
        }

    if has_positive_context:
        return {
            "is_secret": True,
            "confidence": "MEDIUM",
            "reason": "High-entropy token assigned to credential variable",
        }

    # Unstructured high-entropy string
    return {
        "is_secret": True,
        "confidence": "LOW",
        "reason": "High-entropy token without recognizable vendor format or credential variable assignment",
    }
