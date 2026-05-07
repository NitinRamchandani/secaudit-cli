#!/usr/bin/env python3
"""
SecAudit CLI
------------
Repeatable security checks for AWS environments.
Outputs structured JSON findings for ticketing workflow integration.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from checks import iam, s3, cloudtrail, security_groups

CHECKS = {
    "iam":             iam.run,
    "s3":              s3.run,
    "cloudtrail":      cloudtrail.run,
    "security-groups": security_groups.run,
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def parse_args():
    parser = argparse.ArgumentParser(
        prog="secaudit",
        description="Run repeatable AWS security checks and output structured JSON findings."
    )
    parser.add_argument(
        "--checks",
        nargs="+",
        choices=list(CHECKS.keys()) + ["all"],
        default=["all"],
        help="Checks to run (default: all)"
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="AWS profile to use (default: environment credentials)"
    )
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region (default: us-east-1)"
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Write JSON findings to file instead of stdout"
    )
    parser.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default=None,
        help="Filter findings at or above this severity"
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print a human-readable summary after JSON output"
    )
    return parser.parse_args()


def run_checks(selected, profile, region):
    targets = list(CHECKS.keys()) if "all" in selected else selected
    all_findings = []

    for name in targets:
        print(f"[*] Running check: {name}", file=sys.stderr)
        try:
            findings = CHECKS[name](profile=profile, region=region)
            all_findings.extend(findings)
        except Exception as e:
            all_findings.append({
                "check": name,
                "severity": "INFO",
                "title": f"Check failed: {name}",
                "detail": str(e),
                "resource": "N/A",
                "region": region,
                "remediation": "Check AWS credentials and permissions."
            })

    return all_findings


def filter_by_severity(findings, min_severity):
    if not min_severity:
        return findings
    threshold = SEVERITY_ORDER[min_severity]
    return [f for f in findings if SEVERITY_ORDER.get(f.get("severity", "INFO"), 4) <= threshold]


def build_report(findings, region, profile):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "aws_region": region,
        "aws_profile": profile or "default",
        "total_findings": len(findings),
        "severity_summary": counts,
        "findings": sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 4))
    }


def print_summary(report):
    print("\n" + "=" * 60, file=sys.stderr)
    print("  SecAudit Summary", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print(f"  Region   : {report['aws_region']}", file=sys.stderr)
    print(f"  Profile  : {report['aws_profile']}", file=sys.stderr)
    print(f"  Total    : {report['total_findings']} findings", file=sys.stderr)
    for sev, count in report["severity_summary"].items():
        if count > 0:
            print(f"  {sev:<10}: {count}", file=sys.stderr)
    print("=" * 60 + "\n", file=sys.stderr)


def main():
    args = parse_args()
    findings = run_checks(args.checks, args.profile, args.region)
    findings = filter_by_severity(findings, args.severity)
    report = build_report(findings, args.region, args.profile)

    output_json = json.dumps(report, indent=2)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output_json)
        print(f"[+] Findings written to {args.output}", file=sys.stderr)
    else:
        print(output_json)

    if args.summary:
        print_summary(report)

    # Exit with non-zero if critical or high findings exist
    if report["severity_summary"].get("CRITICAL", 0) > 0 or report["severity_summary"].get("HIGH", 0) > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
