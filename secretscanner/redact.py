"""
redact.py
Turns a line that matched a detector into a safe-to-display preview where
the SECRET VALUE ITSELF is masked, not just the surrounding line truncated.

This exists because a report that shows the full credential defeats the
point of a security tool - the report becomes a second copy of the leak,
now sitting in a JSON/HTML file that's even easier to grep than the
original git history.
"""


def mask_value(value: str) -> str:
    """Keep a small amount of context (first/last few chars) for the
    reader to recognize which credential this is without exposing enough
    to use it. Fixed-width mask so the output doesn't leak exact length."""
    if len(value) <= 8:
        return "•" * len(value)
    return f"{value[:4]}••••••••{value[-4:]}"


def redact_regex_match(line: str, match, redact_mode: str) -> str:
    """Given the line and the regex Match object that triggered a finding,
    return the line with only the sensitive span replaced."""
    if match is None or redact_mode == "none":
        return line

    if redact_mode == "group":
        try:
            start, end = match.span("secret")
        except IndexError:
            start, end = match.span()  # pattern had no named group; fall back to full match
    else:  # "full"
        start, end = match.span()

    secret_value = line[start:end]
    return line[:start] + mask_value(secret_value) + line[end:]


def redact_token_in_line(line: str, token: str) -> str:
    """Mask a specific token (used for entropy-based findings, which have
    no regex match object) - replaces the first occurrence only."""
    idx = line.find(token)
    if idx == -1:
        return line
    return line[:idx] + mask_value(token) + line[idx + len(token):]
