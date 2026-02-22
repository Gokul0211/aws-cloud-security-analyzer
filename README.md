# CloudGuard ULTRA

**AWS Security Posture Scanner — v4.0**

Automated cloud security auditing tool that identifies misconfigurations, verifies they are actually exploitable, maps how far a compromise would spread, estimates when each finding will be breached, and fixes the ones it can.

---

## What makes this different from Prowler, ScoutSuite, and CloudSploit

Every open-source CSPM tool does the same thing: find misconfigurations, map them to compliance frameworks, generate a report. CloudGuard does all of that, plus things none of them do.

```
                          Prowler   ScoutSuite   CloudGuard ULTRA
─────────────────────────────────────────────────────────────────
Misconfiguration detection    ✓         ✓              ✓
CIS / NIST / PCI mapping      ✓         ✓              ✓
Attack path analysis          ✗         ✗              ✓
Live exploit verification     ✗         ✗              ✓
Simulation scoring (0-100)    ✗         ✗              ✓
Time-to-Breach estimation     ✗         ✗              ✓
Graph centrality scoring      ✗         ✗              ✓
Risk propagation engine       ✗         ✗              ✓
Blast radius mapping          ✗         ✗              ✓
Canary token injection        ✗         ✗              ✓
Auto-remediation engine       ✗        partial         ✓
Scan diff engine              ✗         ✗              ✓
Cross-account pivot mapping   ✗         ✗              ✓
Multi-region parallel scan    ✗         ✗              ✓
Full paginator coverage       ✗         ✗              ✓
Executive breach report       ✗         ✗              ✓
Predictive trend forecasting  ✗         ✗              ✓
```

---

## Installation

```bash
pip install boto3 networkx
```

Python 3.9+. No other required dependencies. `networkx` is optional — blast radius and pivot map degrade gracefully if absent.

Configure AWS credentials the standard way:

```bash
export AWS_PROFILE=your-profile
# or
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
```

---

## Quick Start

```bash
# Basic scan — JSON + HTML report, us-east-1
python scanner_ultra.py

# Scan all enabled regions in parallel
python scanner_ultra.py --all-regions

# Full analysis stack
python scanner_ultra.py \
  --simulate-attacks \
  --blast-radius \
  --time-to-breach \
  --executive-report
```

---

## Features

### Core Scanner

Scans 10 AWS services across 35+ security checks with full paginator coverage on every `list` / `describe` call — handles accounts with 10,000+ resources without truncation. Parallel `ThreadPoolExecutor` per service. Every finding gets a composite risk score, TTB estimate, and compliance cross-references.

Services: S3 · IAM · EC2 · RDS · CloudTrail · VPC · Lambda · SNS · SQS · KMS

Frameworks: CIS AWS Foundations v1.5 · NIST CSF · PCI-DSS v3.2 · MITRE ATT&CK

---

### Live Attack Path Simulator (`--simulate-attacks`)

Makes real read-only boto3 calls to confirm whether each finding is actually exploitable — not just theoretically misconfigured. Returns a proof-of-concept command per confirmed finding and a quantified simulation score.

```
[CRITICAL ] S3          arn:aws:s3:::prod-data
  Evidence    : Bucket 'prod-data' is publicly listable without credentials
  Sim Score   : 100/100  [██████████]
  PoC         : aws s3 ls s3://prod-data --no-sign-request

[HIGH     ] EC2         sg-0abc123def456789a
  Evidence    : Port 22-22 open to 0.0.0.0/0 in sg-0abc123def456789a
  Sim Score   :  90/100  [█████████░]
  PoC         : nmap -p 22-22 <instance-public-ip>
```

**Simulation Score (0–100):**

```
SimScore = verifier_confidence + severity_base + exposure_bonus

verifier_confidence  confirmed=50, disproven=0, no-verifier=20
severity_base        CRITICAL=30, HIGH=20, MEDIUM=10, LOW=5
exposure_bonus       +20 if publicly reachable
```

Verifiers implemented for: public S3 buckets, open SG ports, IMDSv1 instances, public EBS snapshots, public RDS endpoints, IAM admin policies, wildcard action policies, Lambda secret env vars.

---

### Blast Radius Calculator (`--blast-radius`)

Builds a directed compromise graph. Starting from every critical/high finding, maps every other resource reachable via pivoting. v4.0 adds two major capabilities:

**Graph Centrality Scoring** runs betweenness centrality and eigenvector centrality across the full resource graph. Betweenness identifies chokepoint nodes that sit on the most attack paths — taking these out breaks the most chains. Eigenvector identifies hubs connected to other high-value nodes.

```
Chokepoints (by betweenness centrality):
  - arn:aws:iam::123:role/SharedDeployRole    (BC: 0.4821)
  - i-0abc123def456789a                        (BC: 0.2103)
```

**Risk Propagation Engine** flows risk downstream through the graph:

```
NodeRisk(v) = BaseRisk(v) + sum_u_in_parents [ NodeRisk(u) * EdgeWeight * DecayFactor ]
```

Edge weights: `CREDENTIAL_THEFT=0.95`, `TRUST_ASSUMPTION=0.90`, `DATA_EXFIL=0.80`, `LATERAL_MOVEMENT=0.75`, `NETWORK_PIVOT=0.70`. Risk attenuates 15% per hop. Runs iterative relaxation until convergence.

```
  Blast radius          : 72.3% of environment reachable
  Max propagated risk   : 9.8/10.0
  Crown jewels:
    - [RDS] arn:aws:rds:us-east-1:123:db:prod-postgres  (propagated risk: 9.6)
    - [S3 ] arn:aws:s3:::customer-data                   (propagated risk: 9.1)
```

---

### Time-to-Breach Estimator

Every finding gets a `ttb_days` estimate — how many days until an attacker is likely to discover and exploit it.

```
TTB = base_days * complexity_factor * exposure_factor * age_factor * cvss_nudge * ttb_multiplier

base_days        CRITICAL=2d, HIGH=7d, MEDIUM=30d, LOW=120d
complexity_f     LOW=0.5, MEDIUM=1.0, HIGH=3.0
exposure_f       0.4 if publicly reachable, else 1.0
age_f            max(0.5, 1.0 - age_days/365 * 0.4)
cvss_nudge       max(0.3, (10 - CVSS) / 10)
ttb_multiplier   per-check constant from threat intel
                 ec2_rdp_open=0.15  (RDP scanners are aggressive)
                 s3_public_acl=0.30 (automated S3 scanners are common)
                 iam_root_no_mfa=0.20
```

Urgency tiers: `IMMEDIATE < 1d`, `CRITICAL < 3d`, `HIGH < 7d`, `MEDIUM < 30d`, `LOW >= 30d`.

---

### Executive Breach Report (`--executive-report`)

Generates a plain-English summary for non-technical stakeholders — CISO, board, or customer. Includes security grade, financial exposure estimate, regulatory flags, attack path summary, blast radius data, top 5 prioritised immediate actions sorted by TTB, and CIS compliance gaps.

```
  Security Grade  : D -- At Risk
  Compliance Score: 54%

ESTIMATED BUSINESS IMPACT
  Financial Exposure Range: $240,000 -- $1,750,000
  Regulatory Risk:
    GDPR Art. 32 (unauthorized data access risk)
    PCI-DSS Req. 3.4 (data-at-rest encryption)

TOP 5 RECOMMENDED IMMEDIATE ACTIONS
  1. [S3] S3 Public Acl
     Time-to-Breach: 0.2d  (IMMEDIATE)
     Auto-fix: fix_s3_public_acl
```

Saved to `reports/executive_report_TIMESTAMP.txt`.

---

### Multi-Region Parallel Scan (`--all-regions`)

Discovers all enabled AWS regions via `ec2:DescribeRegions`, then fans out with `ThreadPoolExecutor` capped at 5 concurrent regions. Produces one JSON + HTML report per region.

```bash
python scanner_ultra.py --all-regions
python scanner_ultra.py --all-regions --simulate-attacks --blast-radius
```

---

### Canary Token Injector (`--inject-canaries`)

Plants honeytokens inside misconfigured resources. When an attacker accesses them, CloudTrail logs their identity and IP. Dry-run by default.

S3 canaries upload files with realistic bait names (`credentials.txt`, `.env`, `secrets.env`, `config/secrets.yml`) containing fake-but-realistic IAM keys in `[default]` profile format — matching the `AKIA` + 16 char format so attackers attempt to use them.

IAM canaries create a `cloudguard-honeypot-<id>` console user. Any login attempt means an attacker has enumerated IAM users and is attempting access.

```bash
python scanner_ultra.py --inject-canaries               # preview
python scanner_ultra.py --inject-canaries --no-dry-run  # plant them
python scanner_ultra.py --check-canaries                # poll CloudTrail for triggers
```

---

### Auto-Remediation Engine (`--remediate`)

19 automated fixes. Dry-run by default. Each fix is classified `SAFE`, `DISRUPTIVE`, or `MANUAL_REQUIRED`.

```bash
python scanner_ultra.py --remediate                              # dry-run
python scanner_ultra.py --remediate --no-dry-run                 # safe fixes only, LIVE
python scanner_ultra.py --remediate --remediate-all --no-dry-run # include disruptive, LIVE
```

Safe fixes include: block public S3 access, enable AES-256 encryption, enable versioning, revoke 0.0.0.0/0 SG ingress rules, enforce IMDSv2, disable public RDS access, enable CloudTrail log file validation, enable KMS key rotation.

Disruptive fixes (require `--remediate-all`): delete IAM console login profile for stale users, deactivate access keys older than 90 days.

---

### Low-Noise Scan Mode (`--low-noise`)

Adds inter-request jitter delays (0.3–2.8s) and exponential backoff retry config to reduce API call density. Intended for production environments where you want to minimise scan footprint. This does not attempt to evade any AWS security service.

`--stealth` is a backwards-compatible alias for `--low-noise`.

---

### Scan Diff Engine (`--diff`)

Git-style comparison between any two scan JSON reports. Shows new findings, fixed findings, severity regressions, per-service deltas, and score trend.

```
Compliance Score: 67% -> 74%  (+7.0)  IMPROVING
+ 2 NEW findings
- 5 FIXED findings
~ 3 CHANGED findings  (1 regression / 2 improvements)
= 18 persistent findings
```

---

### Cross-Account Pivot Mapper (`--pivot-map`)

Maps IAM role trust policies and S3 bucket policies across every account in your AWS Organization. Builds a directed account-level graph answering: if account A is compromised, which other accounts can be reached via existing trust relationships?

---

### Predictive Trend Forecasting

Linear regression over SQLite scan history predicts your compliance score 30 days out. Runs automatically after every scan when 3+ historical scans exist.

```
Score trend: 74% -> predicted 61% in 30 days (REGRESSING)
ALERT: Score predicted to breach 50% threshold!
```

---

## Usage Reference

```bash
# Core
python scanner_ultra.py
python scanner_ultra.py --profile prod --region eu-west-1
python scanner_ultra.py --services s3 iam ec2 rds
python scanner_ultra.py --output json html csv --output-dir ./reports

# Multi-region
python scanner_ultra.py --all-regions

# Low-noise (reduced API footprint)
python scanner_ultra.py --low-noise

# Live verification + simulation scoring
python scanner_ultra.py --simulate-attacks

# Blast radius: centrality + risk propagation
python scanner_ultra.py --blast-radius

# Time-to-Breach breakdown per finding
python scanner_ultra.py --time-to-breach

# Executive business-language report
python scanner_ultra.py --executive-report

# Canary tokens
python scanner_ultra.py --inject-canaries
python scanner_ultra.py --inject-canaries --no-dry-run
python scanner_ultra.py --check-canaries

# Auto-remediation
python scanner_ultra.py --remediate
python scanner_ultra.py --remediate --no-dry-run
python scanner_ultra.py --remediate --remediate-all --no-dry-run

# Scan diff
python scanner_ultra.py --diff reports/scan_20250101_020000.json

# Cross-account org scanning
python scanner_ultra.py --multi-account
python scanner_ultra.py --multi-account --pivot-map --role MySecurityRole

# Trend prediction
python scanner_ultra.py --predict-trend

# Full stack
python scanner_ultra.py \
  --all-regions \
  --simulate-attacks \
  --blast-radius \
  --time-to-breach \
  --executive-report \
  --remediate \
  --inject-canaries \
  --predict-trend

# Web dashboard
python dashboard.py
python dashboard.py --port 8080
```

---

## AWS Permissions

Minimum read-only permissions for a full scan:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudGuardReadOnly",
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketAcl", "s3:GetBucketPolicy", "s3:GetBucketVersioning",
        "s3:GetBucketEncryption", "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketLogging", "s3:ListAllMyBuckets", "s3:ListObjectsV2",
        "iam:GetAccountSummary", "iam:GetAccountPasswordPolicy",
        "iam:ListUsers", "iam:ListAccessKeys", "iam:GetLoginProfile",
        "iam:ListMFADevices", "iam:ListAttachedUserPolicies",
        "iam:ListRoles", "iam:GetRole", "iam:ListPolicies",
        "iam:GetPolicyVersion", "iam:ListPolicyVersions",
        "iam:ListAttachedRolePolicies",
        "ec2:DescribeSecurityGroups", "ec2:DescribeInstances",
        "ec2:DescribeVolumes", "ec2:DescribeSnapshots",
        "ec2:DescribeSnapshotAttribute", "ec2:DescribeVpcs",
        "ec2:DescribeFlowLogs", "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeRegions",
        "rds:DescribeDBInstances",
        "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus",
        "cloudtrail:LookupEvents",
        "lambda:ListFunctions", "lambda:GetFunctionConfiguration",
        "lambda:GetFunctionUrlConfig",
        "sns:ListTopics", "sns:GetTopicAttributes",
        "sqs:ListQueues", "sqs:GetQueueAttributes",
        "kms:ListKeys", "kms:DescribeKey", "kms:GetKeyRotationStatus",
        "kms:GetKeyPolicy",
        "organizations:ListAccounts", "organizations:DescribeOrganization",
        "sts:GetCallerIdentity", "sts:AssumeRole"
      ],
      "Resource": "*"
    }
  ]
}
```

Additional permissions for `--remediate --no-dry-run` and `--inject-canaries --no-dry-run` are documented in the project spec.

---

## Output Files

```
reports/
  scan_TIMESTAMP.json              Full structured report (SIEM-ready)
  scan_TIMESTAMP.html              Self-contained interactive D3.js report
  scan_TIMESTAMP.csv               Flat findings export
  executive_report_TIMESTAMP.txt   Business-language summary
  diff_TIMESTAMP.json              Scan delta (--diff)
  pivot_map_TIMESTAMP.json         Cross-account trust graph (--pivot-map)

cloudguard.db                      SQLite: scans, findings, canaries, remediations
```

---

## Architecture

```
scanner_ultra.py  (4,200+ lines)
|
+-- TimeToBreach               Multi-factor TTB model
+-- BlastRadiusCalculator      NetworkX: centrality + risk propagation
+-- AttackPathSimulator        Live boto3 verifiers + simulation scoring (0-100)
+-- CanaryInjector             S3 + IAM honeytoken planting and monitoring
+-- AutoRemediator             19 fix functions, 3-tier risk classification
+-- ScanDiffEngine             Git-style scan-to-scan delta
+-- CrossAccountPivotMapper    Org-wide IAM trust + S3 policy graph
+-- ScanHistoryDB              SQLite persistence
+-- SecurityScanner            Core scan orchestrator
|   +-- run()                  Single-region parallel scan
|   +-- scan_region()          Thread-safe classmethod
|   +-- run_all_regions()      Multi-region parallel fan-out
+-- MultiAccountScanner        STS assume-role org-wide scanning
+-- predict_trend()            Linear regression forecasting
+-- generate_executive_report() Business-language impact summary
```

---

## Requirements

```
boto3>=1.26.0
networkx>=3.1     # optional: --blast-radius and --pivot-map
```
