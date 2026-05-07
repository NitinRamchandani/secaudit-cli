# SecAudit CLI

A lightweight command-line tool for running repeatable security checks against AWS environments. Outputs structured JSON findings that plug into existing ticketing and reporting workflows.

Built to replace a collection of manual one-off checks I kept running across different engagements.

---

## Checks Included

| Module           | What it checks                                                                 |
|------------------|--------------------------------------------------------------------------------|
| `iam`            | Root MFA, users without MFA, stale access keys, inline policies                |
| `s3`             | Public access block, encryption, versioning, access logging                    |
| `cloudtrail`     | Trail existence, logging status, log validation, multi-region, CloudWatch      |
| `security-groups`| Open SSH/RDP/DB ports, unrestricted inbound, default SG with rules             |

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/secaudit-cli.git
cd secaudit-cli
pip install -r requirements.txt
```

Requires Python 3.8+ and valid AWS credentials (environment variables, `~/.aws/credentials`, or an IAM role).

---

## Usage

```bash
# Run all checks, print JSON to stdout
python secaudit.py

# Run specific checks
python secaudit.py --checks iam s3

# Use a named AWS profile
python secaudit.py --profile staging

# Target a specific region
python secaudit.py --region us-west-2

# Write findings to a file
python secaudit.py --output findings.json

# Only show HIGH and above
python secaudit.py --severity HIGH

# Print a human-readable summary after JSON
python secaudit.py --summary
```

---

## Output Format

```json
{
  "generated_at": "2026-05-06T10:00:00+00:00",
  "aws_region": "us-east-1",
  "aws_profile": "default",
  "total_findings": 3,
  "severity_summary": {
    "CRITICAL": 1,
    "HIGH": 1,
    "MEDIUM": 1,
    "LOW": 0,
    "INFO": 0
  },
  "findings": [
    {
      "check": "iam",
      "severity": "CRITICAL",
      "title": "Root account does not have MFA enabled",
      "detail": "The AWS root account has no MFA device associated.",
      "resource": "arn:aws:iam::root",
      "region": "global",
      "remediation": "Enable MFA on the root account via IAM > Security credentials."
    }
  ]
}
```

Each finding includes a `remediation` field, making it straightforward to pipe results into Jira, ServiceNow, or any ticketing system that accepts JSON.

---

## Exit Codes

| Code | Meaning                          |
|------|----------------------------------|
| `0`  | No CRITICAL or HIGH findings     |
| `1`  | One or more CRITICAL/HIGH findings |

This makes it easy to fail CI/CD pipelines on serious findings.

---

## Required IAM Permissions

The identity running secaudit needs read-only access to the services being checked:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountSummary",
        "iam:GetAccountAuthorizationDetails",
        "iam:GetLoginProfile",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:ListUserPolicies",
        "s3:ListAllMyBuckets",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketEncryption",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "ec2:DescribeSecurityGroups"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Adding New Checks

Each check is a Python module in the `checks/` directory that exports a single `run(profile, region)` function returning a list of finding dicts. Register it in `CHECKS` inside `secaudit.py`.

---

## License

MIT
