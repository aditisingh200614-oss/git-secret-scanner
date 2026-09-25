"""
scanner.py
Walks the ENTIRE git history of a repository (every commit, every branch,
including merge commits by default) and inspects every line ever *added*
in a diff for secrets.

Why history and not just the working tree:
Deleting a secret from the current files does NOT remove it from git.
Anyone who clones the repo (or has an old clone) can run `git log -p` and
recover it forever, unless history is rewritten and force-pushed. Tools
that only scan the checked-out files (e.g. a basic grep, or a naive
pre-commit hook that only checks staged files) miss this completely.

Design notes vs. a first-pass version of this tool:
  - Output is streamed line-by-line from `git log`, not buffered into one
    giant string, so this doesn't blow up memory on large real-world repos.
  - Merge commits are included (`git log -p -m`) - by default git hides
    diffs for merge commits, which is a real false-negative source: a
    secret introduced only while resolving a merge conflict would
    otherwise never be seen.
  - Real line numbers are tracked by parsing unified-diff hunk headers
    (`@@ -a,b +c,d @@`), not left as a placeholder.
  - Only the secret VALUE is masked in output, not the whole line - see
    redact.py.
  - Multi-factor risk scoring: each finding carries both Severity (impact)
    and Confidence (likelihood of true secret).
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field

from .entropy import (
    NEGATIVE_CONTEXT_RE,
    evaluate_entropy_context,
    extract_candidate_tokens,
    is_git_commit_reference,
)
from .patterns import (
    CONFIDENCE_ORDER,
    DEFAULT_IGNORE_PATH_PATTERNS,
    PATTERNS,
    SEVERITY_ORDER,
)
from .redact import redact_regex_match, redact_token_in_line

COMMIT_MARKER = "@@COMMIT@@"
FIELD_SEP = "\x1f"
HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
IGNORE_FILE_NAME = ".secretscannerignore"

PRIVATE_KEY_RULE_NAMES = {"Private Key Block", "Generic Private Key Block"}
KEY_BLOCK_TYPE_RE = re.compile(r"BEGIN (\w[\w ]*?) PRIVATE KEY")
KEY_BLOCK_END_RE = re.compile(r"[-]{5}END [\w ]*PRIVATE KEY[-]{5}")
# Safety cap: a malformed diff or a file that never shows an END marker
# (e.g. history was truncated mid-key) shouldn't make the scanner buffer
# an unbounded number of lines waiting for one.
MAX_KEY_BLOCK_LINES = 200


@dataclass
class Finding:
    rule: str
    severity: str
    file_path: str
    commit_hash: str
    commit_short: str
    author: str
    date: str
    line_number: int
    line_preview: str          # already redacted at creation time
    secret_fingerprint: str
    confidence: str = "HIGH"
    still_in_head: bool = False
    detection_method: str = "regex"
    # Multi-line PEM key blocks are fingerprinted on their full body, not
    # just the header, so this is >1 for those findings and reports how
    # many lines were captured without ever printing the key material.
    key_block_lines: int = 0
    # Which branch(es) the introducing commit is reachable from (only
    # populated when scanning --all branches). Lets a team judge blast
    # radius: a secret only reachable from a long-dead feature branch is a
    # lower-priority rotation than one reachable from main.
    branches: list[str] = field(default_factory=list)
    context_reason: str = ""

    def redacted(self) -> str:
        """Preview is already secret-masked; this just bounds display length."""
        s = self.line_preview.strip()
        if len(s) > 160:
            s = s[:160] + "..."
        return s


def _run_git(repo_path: str, args: list[str]) -> str:
    result = subprocess.run(
        ["git", "-C", repo_path] + args,
        capture_output=True, text=True, errors="replace", check=False
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def load_custom_ignore_patterns(repo_path: str) -> list[re.Pattern]:
    """
    Reads a `.secretscannerignore` file from the repo root, one regex per
    line (matched against the file path), '#' comments and blank lines
    skipped. This is how a real team suppresses known false positives
    without editing the tool's source.
    """
    ignore_path = os.path.join(repo_path, IGNORE_FILE_NAME)
    patterns = []
    if os.path.isfile(ignore_path):
        with open(ignore_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    patterns.append(re.compile(line))
                except re.error as e:
                    print(f"[!] Skipping invalid pattern in {IGNORE_FILE_NAME}: {line!r} ({e})",
                          file=sys.stderr)
    return patterns


def is_ignored_path(path: str, ignore_patterns) -> bool:
    return any(p.search(path) for p in ignore_patterns)


def get_head_file_content_cache(repo_path: str):
    """Lazily fetch HEAD content per file, cached, to check if a finding is still live."""
    cache = {}

    def check(file_path: str, secret_line: str) -> bool:
        if file_path not in cache:
            try:
                cache[file_path] = _run_git(repo_path, ["show", f"HEAD:{file_path}"])
            except RuntimeError:
                cache[file_path] = None  # file deleted or never in HEAD
        content = cache[file_path]
        if content is None:
            return False
        return secret_line.strip() in content

    return check


def get_branch_attribution_cache(repo_path: str, all_branches: bool):
    """
    Lazily resolves which branch(es) a commit is reachable from, cached per
    commit hash. Only meaningful (and only pays the `git branch --contains`
    cost) when scanning --all branches; a --current-branch-only scan just
    tags every finding with that one branch.
    """
    cache = {}
    current_branch = None
    if not all_branches:
        try:
            current_branch = _run_git(repo_path, ["rev-parse", "--abbrev-ref", "HEAD"]).strip()
        except RuntimeError:
            current_branch = None

    def resolve(commit_hash: str) -> list[str]:
        if not commit_hash:
            return []
        if not all_branches:
            return [current_branch] if current_branch else []
        if commit_hash not in cache:
            try:
                out = _run_git(repo_path, [
                    "branch", "--all", "--contains", commit_hash,
                    "--format=%(refname:short)",
                ])
                names = set()
                for line in out.splitlines():
                    name = line.strip()
                    if not name or name in ("HEAD",) or "HEAD ->" in name:
                        continue
                    names.add(name.removeprefix("origin/"))
                cache[commit_hash] = sorted(names)
            except RuntimeError:
                cache[commit_hash] = []
        return cache[commit_hash]

    return resolve


def fingerprint(rule: str, file_path: str, secret_text: str) -> str:
    h = hashlib.sha256(f"{rule}:{file_path}:{secret_text}".encode("utf-8", "replace"))
    return h.hexdigest()[:16]


def _iter_git_log_lines(repo_path: str, all_branches: bool, max_commits: int | None,
                         include_merges: bool, verbose: bool):
    """Streams `git log -p` output line by line via Popen instead of
    capturing the whole thing into memory at once - matters on large repos
    where full history diffs can run into hundreds of MB."""
    log_args = [
        "git", "-C", repo_path, "log",
        "-p", "--no-color", "--full-history", "--date=iso-strict",
        f"--pretty=format:{COMMIT_MARKER}%H{FIELD_SEP}%h{FIELD_SEP}%an{FIELD_SEP}%ad{FIELD_SEP}%s",
    ]
    if include_merges:
        log_args.append("-m")  # show diffs for merge commits against each parent
    if all_branches:
        log_args.append("--all")
    if max_commits:
        log_args.extend(["-n", str(max_commits)])

    if verbose:
        print(f"[*] Running: {' '.join(log_args)}", file=sys.stderr)

    proc = subprocess.Popen(log_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, errors="replace")
    assert proc.stdout is not None
    for line in proc.stdout:
        yield line.rstrip("\n")
    proc.stdout.close()
    stderr = ""
    if proc.stderr:
        stderr = proc.stderr.read()
        proc.stderr.close()
    proc.wait()
    if proc.returncode != 0:
        raise RuntimeError(f"git log failed: {stderr.strip()}")


def scan_repository(
    repo_path: str,
    all_branches: bool = True,
    max_commits: int | None = None,
    ignore_paths: bool = True,
    include_merges: bool = True,
    verbose: bool = False,
) -> list[Finding]:
    """
    Streams `git log -p` for the whole repo history and inspects every
    added line against the regex + entropy detectors. Returns de-duplicated
    findings (same secret value in the same file is reported once).
    """
    custom_ignores = load_custom_ignore_patterns(repo_path) if ignore_paths else []
    active_ignore_patterns = (DEFAULT_IGNORE_PATH_PATTERNS + custom_ignores) if ignore_paths else []

    check_still_in_head = get_head_file_content_cache(repo_path)
    resolve_branches = get_branch_attribution_cache(repo_path, all_branches)

    findings: list[Finding] = []
    seen_fingerprints = {}
    pending_key_block = None  # accumulates a multi-line PEM block across diff lines

    commit_hash = commit_short = author = date = ""
    current_file = None
    current_new_line = None
    commits_scanned = 0
    lines_inspected = 0

    def finalize_pending_key_block():
        """
        Turn an accumulated PEM key block into a Finding, fingerprinted on
        the full body (not just the header), then clear it. The key
        material itself is never included in line_preview or anywhere in
        the report - only a line count - since printing it would turn the
        report into a second copy of the leak.
        """
        nonlocal pending_key_block
        if pending_key_block is None:
            return
        kb = pending_key_block
        pending_key_block = None

        block_text = "\n".join(kb["lines"])
        fp = fingerprint(kb["rule"], kb["file_path"], block_text)
        still_live = check_still_in_head(kb["file_path"], kb["lines"][0])
        branches = resolve_branches(kb["commit_hash"])

        if fp in seen_fingerprints:
            existing = seen_fingerprints[fp]
            existing.still_in_head = existing.still_in_head or still_live
            existing.branches = sorted(set(existing.branches) | set(branches))
            return

        key_type = kb["key_type"] or "PRIVATE"
        truncated = len(kb["lines"]) >= MAX_KEY_BLOCK_LINES
        preview = (f"-----BEGIN {key_type} PRIVATE KEY----- "
                   f"[{len(kb['lines'])}-line key block redacted"
                   f"{', END marker not found - truncated at cap' if truncated else ''}]")

        finding = Finding(
            rule=kb["rule"],
            severity=kb["severity"],
            confidence=kb.get("confidence", "HIGH"),
            file_path=kb["file_path"],
            commit_hash=kb["commit_hash"],
            commit_short=kb["commit_short"],
            author=kb["author"],
            date=kb["date"],
            line_number=kb["line_number"],
            line_preview=preview,
            secret_fingerprint=fp,
            still_in_head=still_live,
            detection_method="regex",
            key_block_lines=len(kb["lines"]),
            branches=branches,
            context_reason="Multi-line cryptographic private key block",
        )
        seen_fingerprints[fp] = finding
        findings.append(finding)

    for raw_line in _iter_git_log_lines(repo_path, all_branches, max_commits, include_merges, verbose):
        if raw_line.startswith(COMMIT_MARKER):
            finalize_pending_key_block()  # flush across a commit boundary
            commits_scanned += 1
            _, rest = raw_line.split(COMMIT_MARKER, 1)
            parts = rest.split(FIELD_SEP)
            if len(parts) >= 4:
                commit_hash, commit_short, author, date = parts[0], parts[1], parts[2], parts[3]
            current_file, current_new_line = None, None
            continue

        if raw_line.startswith("+++ b/"):
            finalize_pending_key_block()  # flush across a file boundary
            current_file = raw_line[6:].strip()
            current_new_line = None
            continue
        if raw_line.startswith("+++ /dev/null"):
            finalize_pending_key_block()
            current_file = None
            continue

        hunk_match = HUNK_HEADER_RE.match(raw_line)
        if hunk_match:
            current_new_line = int(hunk_match.group(1))
            continue

        if current_file is None or current_new_line is None:
            continue

        # unified diff line-number bookkeeping: context (' ') and added ('+')
        # lines occupy a line in the NEW file and advance the counter;
        # removed ('-') lines don't exist in the new file.
        if raw_line.startswith("-") and not raw_line.startswith("---"):
            continue  # old-file-only line, no new-line number to assign
        if raw_line.startswith("\\"):  # "\ No newline at end of file"
            continue

        is_added = raw_line.startswith("+") and not raw_line.startswith("+++")
        content_line = raw_line[1:] if (is_added or raw_line.startswith(" ")) else raw_line
        line_no_for_this_line = current_new_line
        current_new_line += 1

        if not is_added:
            continue  # only inspect lines actually introduced by this commit

        lines_inspected += 1

        if pending_key_block is not None:
            # Already inside a PEM block for this file/commit - keep
            # accumulating body lines instead of pattern-matching them
            # (base64 key material can itself look regex/entropy-suspicious,
            # which would otherwise double-report the same key).
            pending_key_block["lines"].append(content_line)
            if KEY_BLOCK_END_RE.search(content_line) or len(pending_key_block["lines"]) >= MAX_KEY_BLOCK_LINES:
                finalize_pending_key_block()
            continue

        if not content_line.strip():
            continue
        if ignore_paths and is_ignored_path(current_file, active_ignore_patterns):
            continue

        matched_rule = matched_severity = matched_confidence = matched_mode = None
        matched_match = None
        method = "regex"
        reason = ""

        for name, severity, confidence, pattern, redact_mode in PATTERNS:
            m = pattern.search(content_line)
            if m:
                matched_rule = name
                matched_severity = severity
                matched_confidence = confidence
                matched_mode = redact_mode
                matched_match = m
                break

        if matched_rule in PRIVATE_KEY_RULE_NAMES:
            # Start capturing the multi-line body instead of emitting a
            # finding for just the header line.
            type_match = KEY_BLOCK_TYPE_RE.search(content_line)
            pending_key_block = {
                "rule": matched_rule,
                "severity": matched_severity,
                "confidence": matched_confidence,
                "file_path": current_file,
                "commit_hash": commit_hash,
                "commit_short": commit_short,
                "author": author,
                "date": date,
                "line_number": line_no_for_this_line,
                "key_type": type_match.group(1).strip() if type_match else "",
                "lines": [content_line],
            }
            continue

        redacted_line = content_line
        secret_for_fingerprint = content_line

        if matched_rule is None and not is_git_commit_reference(content_line):
            for token in extract_candidate_tokens(content_line):
                ctx = evaluate_entropy_context(token, content_line, current_file)
                if ctx["is_secret"]:
                    matched_rule = "High-Entropy Token (unrecognized format)"
                    matched_severity = "LOW"
                    matched_confidence = ctx["confidence"]
                    method = "entropy"
                    secret_for_fingerprint = token
                    redacted_line = redact_token_in_line(content_line, token)
                    reason = ctx["reason"]
                    break

        if matched_rule is None:
            continue

        if method == "regex":
            redacted_line = redact_regex_match(content_line, matched_match, matched_mode)
            if matched_mode == "group":
                try:
                    secret_for_fingerprint = matched_match.group("secret")
                except IndexError:
                    secret_for_fingerprint = matched_match.group(0)
            else:
                secret_for_fingerprint = matched_match.group(0)

            # Context calibration for regex findings
            if NEGATIVE_CONTEXT_RE.search(content_line):
                # If clearly sample/doc context, adjust confidence
                if matched_confidence == "HIGH":
                    matched_confidence = "MEDIUM"
                elif matched_confidence == "MEDIUM":
                    matched_confidence = "LOW"
                reason = "Matched regex signature, but found example/test/documentation keywords"
            else:
                reason = f"Matched {matched_rule} signature with {matched_confidence.lower()} confidence"

        fp = fingerprint(matched_rule, current_file, secret_for_fingerprint)
        still_live = check_still_in_head(current_file, content_line)
        branches = resolve_branches(commit_hash)

        if fp in seen_fingerprints:
            existing = seen_fingerprints[fp]
            existing.still_in_head = existing.still_in_head or still_live
            existing.branches = sorted(set(existing.branches) | set(branches))
            continue

        finding = Finding(
            rule=matched_rule,
            severity=matched_severity,
            confidence=matched_confidence,
            file_path=current_file,
            commit_hash=commit_hash,
            commit_short=commit_short,
            author=author,
            date=date,
            line_number=line_no_for_this_line,
            line_preview=redacted_line,
            secret_fingerprint=fp,
            still_in_head=still_live,
            detection_method=method,
            branches=branches,
            context_reason=reason,
        )
        seen_fingerprints[fp] = finding
        findings.append(finding)

    finalize_pending_key_block()  # flush a block still open at end of history

    if verbose:
        print(f"[*] Commits scanned: {commits_scanned}", file=sys.stderr)
        print(f"[*] Added lines inspected: {lines_inspected}", file=sys.stderr)
        print(f"[*] Findings after dedupe: {len(findings)}", file=sys.stderr)

    findings.sort(key=lambda f: (
        SEVERITY_ORDER.get(f.severity, 9),
        CONFIDENCE_ORDER.get(f.confidence, 9),
        f.date,
    ))
    return findings
