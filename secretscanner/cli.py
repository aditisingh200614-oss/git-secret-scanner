import argparse
import sys

from . import __version__
from .baseline import filter_baseline_findings, load_baseline, write_baseline
from .patterns import CONFIDENCE_ORDER, SEVERITY_ORDER
from .report import print_console_report, write_html_report, write_json_report
from .sarif import write_sarif_report
from .scanner import scan_repository


def main():
    parser = argparse.ArgumentParser(
        prog="secretscanner",
        description="Scan a git repository's FULL commit history for leaked credentials "
                    "(API keys, private keys, passwords, tokens) - not just current files.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("repo", help="Path to a local git repository")
    parser.add_argument("--json", metavar="PATH", help="Write a JSON report to PATH")
    parser.add_argument("--html", metavar="PATH", help="Write an HTML report to PATH")
    parser.add_argument("--sarif", metavar="PATH", help="Write a SARIF 2.1.0 report to PATH")
    parser.add_argument("--baseline", metavar="PATH",
                        help="Path to baseline file containing known findings. Only NEW findings will be reported/failed.")
    parser.add_argument("--generate-baseline", metavar="PATH",
                        help="Generate a baseline JSON file containing all findings from this scan")
    parser.add_argument("--current-branch-only", action="store_true",
                        help="Only scan the current branch's history (default: all branches)")
    parser.add_argument("--max-commits", type=int, default=None,
                        help="Limit scan to the N most recent commits (default: entire history)")
    parser.add_argument("--min-severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "critical", "high", "medium", "low"],
                        default="LOW", help="Only report findings at or above this severity")
    parser.add_argument("--min-confidence", choices=["HIGH", "MEDIUM", "LOW", "high", "medium", "low"],
                        default="LOW", help="Only report findings at or above this confidence level")
    parser.add_argument("--no-default-ignore", action="store_true",
                        help="Don't skip default noisy paths (tests/, lockfiles, node_modules, etc.) "
                             "or a repo-local .secretscannerignore file")
    parser.add_argument("--no-merges", action="store_true",
                        help="Skip diffs for merge commits (faster, but can miss secrets introduced "
                             "only while resolving a merge conflict). Included by default.")
    parser.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "critical", "high", "medium", "low", "none", "NONE"],
                        default="none",
                        help="Exit with code 1 if any active finding at/above this severity is found "
                             "(useful in a CI pipeline as a merge gate)")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    min_severity_str = args.min_severity.upper()
    min_confidence_str = args.min_confidence.upper()
    fail_on_str = args.fail_on.upper()

    try:
        findings = scan_repository(
            repo_path=args.repo,
            all_branches=not args.current_branch_only,
            max_commits=args.max_commits,
            ignore_paths=not args.no_default_ignore,
            include_merges=not args.no_merges,
            verbose=args.verbose,
        )
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)

    # If requested, generate baseline from complete scan before filtering
    if args.generate_baseline:
        try:
            write_baseline(findings, args.repo, args.generate_baseline)
            print(f"[+] Baseline containing {len(findings)} finding(s) written to {args.generate_baseline}")
        except (ValueError, OSError, TypeError) as e:
            print(f"error generating baseline: {e}", file=sys.stderr)
            sys.exit(2)

    # Baseline filtering
    baseline_suppressed = 0
    if args.baseline:
        try:
            baseline_fps = load_baseline(args.baseline)
            findings, baseline_matched = filter_baseline_findings(findings, baseline_fps)
            baseline_suppressed = len(baseline_matched)
        except (ValueError, FileNotFoundError, OSError, TypeError) as e:
            print(f"error loading baseline: {e}", file=sys.stderr)
            sys.exit(2)

    min_sev_rank = SEVERITY_ORDER[min_severity_str]
    min_conf_rank = CONFIDENCE_ORDER[min_confidence_str]

    findings = [
        f for f in findings
        if SEVERITY_ORDER[f.severity] <= min_sev_rank and CONFIDENCE_ORDER.get(getattr(f, "confidence", "HIGH"), 9) <= min_conf_rank
    ]

    print_console_report(findings, args.repo, baseline_suppressed=baseline_suppressed)

    if args.json:
        write_json_report(findings, args.repo, args.json, baseline_suppressed=baseline_suppressed)
        print(f"[+] JSON report written to {args.json}")
    if args.html:
        write_html_report(findings, args.repo, args.html, baseline_suppressed=baseline_suppressed)
        print(f"[+] HTML report written to {args.html}")
    if args.sarif:
        write_sarif_report(findings, args.repo, args.sarif)
        print(f"[+] SARIF report written to {args.sarif}")

    if fail_on_str != "NONE":
        threshold = SEVERITY_ORDER[fail_on_str]
        if any(SEVERITY_ORDER[f.severity] <= threshold for f in findings):
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
