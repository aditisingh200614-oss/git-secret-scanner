"""
patterns.py
Regex signatures for known secret formats, each tagged with severity and default confidence.

Severity model:
  CRITICAL - private keys, cloud provider root/secret credentials (near-certain compromise)
  HIGH     - vendor API tokens with a recognizable, low-false-positive format
  MEDIUM   - generic "key/secret/password = ..." assignments (needs entropy/context to confirm)
  LOW      - weak/contextual signals (still worth a human look)

Confidence model:
  HIGH     - specific signature / checksum / rigid vendor prefix (very unlikely to be false positive)
  MEDIUM   - structured pattern or assignment with entropy support
  LOW      - unstructured high-entropy token or ambiguous keyword assignment
"""

import re

# Each entry: (name, severity, confidence, compiled regex, redact_mode)
# Regexes are written to match on a single added ("+") line of a diff.
#
# redact_mode controls what gets masked in reports (never the whole line -
# variable names and surrounding code are useful context and aren't secret):
#   "full"   - mask the entire regex match (used when the match IS the token)
#   "group"  - mask only the named group `secret` (used when the match also
#              includes a variable name, quotes, or a username/host prefix)
#   "none"   - nothing in the match is sensitive on its own (e.g. a PEM
#              header line - the key material is on following lines we
#              don't individually pattern-match)
PATTERNS = [
    ("AWS Access Key ID", "CRITICAL", "HIGH", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "full"),
    ("AWS Secret Access Key", "CRITICAL", "HIGH", re.compile(
        r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?(?P<secret>[A-Za-z0-9/+=]{40})['\"]?"), "group"),
    ("Private Key Block", "CRITICAL", "HIGH", re.compile(
        r"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED) PRIVATE KEY-----"), "none"),
    ("Generic Private Key Block", "CRITICAL", "HIGH", re.compile(r"-----BEGIN PRIVATE KEY-----"), "none"),

    ("GitHub Personal Access Token", "HIGH", "HIGH", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"), "full"),
    ("GitHub Fine-Grained PAT", "HIGH", "HIGH", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b"), "full"),
    ("Slack Token", "HIGH", "HIGH", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,72}\b"), "full"),
    ("Slack Webhook URL", "HIGH", "HIGH", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}"), "full"),
    ("Stripe Live Secret Key", "CRITICAL", "HIGH", re.compile(r"\bsk_live_[0-9a-zA-Z]{20,247}\b"), "full"),
    ("Stripe Restricted Key", "HIGH", "HIGH", re.compile(r"\brk_live_[0-9a-zA-Z]{20,247}\b"), "full"),
    ("Google API Key", "HIGH", "HIGH", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "full"),
    ("Google OAuth Client Secret", "HIGH", "HIGH", re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{20,}\b"), "full"),
    ("Twilio API Key", "HIGH", "HIGH", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "full"),
    ("Twilio Account SID", "MEDIUM", "MEDIUM", re.compile(r"\bAC[0-9a-fA-F]{32}\b"), "full"),
    ("SendGrid API Key", "HIGH", "HIGH", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"), "full"),
    ("Mailgun API Key", "HIGH", "HIGH", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"), "full"),
    ("Heroku API Key", "HIGH", "HIGH", re.compile(
        r"(?i)heroku[a-z0-9_ ]{0,20}['\"]?\s*[:=]\s*['\"]?(?P<secret>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"), "group"),
    ("NPM Access Token", "HIGH", "HIGH", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "full"),
    ("JSON Web Token (JWT)", "MEDIUM", "MEDIUM", re.compile(
        r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"), "full"),
    ("Database Connection String w/ Credentials", "CRITICAL", "HIGH", re.compile(
        r"(?i)(postgres|postgresql|mysql|mongodb(\+srv)?|redis|amqp)://[^:\s\"']+:(?P<secret>[^@\s\"']+)@[^\s\"']+"), "group"),
    ("Slack/Discord/Generic Bot Token", "HIGH", "MEDIUM", re.compile(
        r"(?i)(discord|bot)[_-]?token['\"]?\s*[:=]\s*['\"]?(?P<secret>[A-Za-z0-9._-]{24,})['\"]?"), "group"),

    # Generic patterns - broad net, relies on entropy check downstream to cut noise
    ("Generic API Key Assignment", "MEDIUM", "MEDIUM", re.compile(
        r"(?i)\b(api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret)\b\s*[:=]\s*['\"](?P<secret>[A-Za-z0-9_\-/+=]{16,64})['\"]"), "group"),
    ("Generic Password Assignment", "MEDIUM", "MEDIUM", re.compile(
        r"(?i)\b(password|passwd|pwd|db_pass)\b\s*[:=]\s*['\"](?P<secret>[^'\"\s]{8,64})['\"]"), "group"),
    ("Generic Secret Assignment", "MEDIUM", "MEDIUM", re.compile(
        r"(?i)\bsecret\b\s*[:=]\s*['\"](?P<secret>[A-Za-z0-9_\-/+=]{12,64})['\"]"), "group"),
]

# File paths / extensions that generate high false-positive noise and are
# excluded by default (override with --no-default-ignore).
DEFAULT_IGNORE_PATH_PATTERNS = [
    re.compile(r"(^|/)\.git/"),
    re.compile(r"(^|/)(test|tests|__tests__|spec|fixtures?|mocks?)/", re.IGNORECASE),
    re.compile(r"\.(lock|min\.js|map|svg|png|jpg|jpeg|gif|ico|woff2?|ttf|eot)$", re.IGNORECASE),
    re.compile(r"(^|/)(package-lock\.json|yarn\.lock|poetry\.lock)$"),
    re.compile(r"\.env\.example$", re.IGNORECASE),
    re.compile(r"(^|/)node_modules/"),
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
CONFIDENCE_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
