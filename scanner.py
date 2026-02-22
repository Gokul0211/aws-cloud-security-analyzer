#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║              CloudGuard ULTRA — AWS Security Posture Scanner                ║
║                              v4.0  💀                                        ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Services  : S3, IAM, EC2, RDS, VPC, CloudTrail, Lambda, SNS, SQS, KMS     ║
║  Frameworks: CIS v1.5 · NIST CSF · PCI-DSS v3.2 · SOC2                     ║
║  Analysis  : MITRE ATT&CK · Graph Centrality · Risk Propagation             ║
║              Blast Radius · Time-To-Breach · Attack Simulation Scoring      ║
║              Canary Tokens · Auto-Remediation · Scan Diff                   ║
║              Cross-Account Pivot · Multi-Region Parallel · Executive Report ║
╚══════════════════════════════════════════════════════════════════════════════╝

NEW IN v4.0 (senior-engineer upgrades):
  📐 Graph Centrality Scoring     — Betweenness + Eigenvector centrality per node
  🌊 Risk Propagation Engine      — NodeRisk = Base + Σ(ParentRisk × EdgeWeight × Decay)
  🌍 Multi-Region Parallel Scan   — ThreadPoolExecutor across all enabled AWS regions
  📄 Full Pagination               — Every list/describe uses paginators; handles 10k+ resources
  🎯 Simulation Scoring           — Quantified exploitability score (0-100) per finding
  📋 Executive Breach Report      — Business-language PDF-ready impact summary
  🔇 Low-Noise Scan Mode          — Reduced-footprint scanning for production environments

Usage:
  python scanner_ultra.py                                    # basic scan
  python scanner_ultra.py --low-noise                        # reduced-footprint scan
  python scanner_ultra.py --all-regions                      # scan all enabled regions
  python scanner_ultra.py --simulate-attacks                 # verify + score exploitability
  python scanner_ultra.py --blast-radius                     # map + propagate risk
  python scanner_ultra.py --time-to-breach                   # estimate days until breach
  python scanner_ultra.py --executive-report                 # business-language summary
  python scanner_ultra.py --inject-canaries                  # plant honeytokens
  python scanner_ultra.py --remediate --dry-run              # preview auto-fixes
  python scanner_ultra.py --remediate                        # actually fix things
  python scanner_ultra.py --diff scan_old.json               # compare vs previous scan
  python scanner_ultra.py --pivot-map                        # cross-account trust graph
  python scanner_ultra.py --multi-account                    # scan entire AWS org
"""

import boto3
import json
import csv
import argparse
import sys
import os
import re
import time
import sqlite3
import hashlib
import random
import string
import threading
import ipaddress
import math
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError, NoCredentialsError
from botocore.config import Config as BotocoreConfig
from typing import List, Dict, Optional, Tuple, Set, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict, deque

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

DB_PATH = os.environ.get("CLOUDGUARD_DB", "cloudguard.db")

# ══════════════════════════════════════════════════════════════════════════════
#  COMPLIANCE + MITRE ATT&CK MAPPINGS  (expanded)
# ══════════════════════════════════════════════════════════════════════════════

CONTROLS: Dict[str, Dict] = {
    # ── S3 ──────────────────────────────────────────────────────────────────
    "s3_public_acl": {
        "cis": "2.1.5",  "nist": "PR.AC-3",  "pci": "1.3.6",
        "mitre": "T1530", "mitre_name": "Data from Cloud Storage",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "exploit_complexity": "LOW",
        "remediation_fn": "fix_s3_public_acl",
        "ttb_multiplier": 0.3,   # very fast to exploit
    },
    "s3_public_policy": {
        "cis": "2.1.5",  "nist": "PR.AC-3",  "pci": "1.3.6",
        "mitre": "T1530", "mitre_name": "Data from Cloud Storage",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "exploit_complexity": "LOW",
        "remediation_fn": "fix_s3_public_policy",
        "ttb_multiplier": 0.3,
    },
    "s3_no_encryption": {
        "cis": "2.1.1",  "nist": "PR.DS-1",  "pci": "3.4",
        "mitre": "T1565", "mitre_name": "Data Manipulation",
        "severity": "HIGH",
        "cvss": 7.5,
        "exploit_complexity": "MEDIUM",
        "remediation_fn": "fix_s3_encryption",
        "ttb_multiplier": 0.6,
    },
    "s3_no_versioning": {
        "cis": "2.1.3",  "nist": "PR.IP-4",  "pci": "10.5.5",
        "mitre": "T1485", "mitre_name": "Data Destruction",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "exploit_complexity": "MEDIUM",
        "remediation_fn": "fix_s3_versioning",
        "ttb_multiplier": 0.8,
    },
    "s3_no_logging": {
        "cis": "2.1.4",  "nist": "DE.CM-7",  "pci": "10.2",
        "mitre": "T1562.008", "mitre_name": "Disable Cloud Logs",
        "severity": "LOW",
        "cvss": 3.1,
        "exploit_complexity": "HIGH",
        "remediation_fn": "fix_s3_logging",
        "ttb_multiplier": 1.2,
    },
    "s3_no_mfa_delete": {
        "cis": "2.1.3",  "nist": "PR.IP-4",  "pci": "10.5.5",
        "mitre": "T1485", "mitre_name": "Data Destruction",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "exploit_complexity": "MEDIUM",
        "remediation_fn": "fix_s3_mfa_delete",
        "ttb_multiplier": 0.9,
    },
    # ── IAM ─────────────────────────────────────────────────────────────────
    "iam_root_no_mfa": {
        "cis": "1.5",    "nist": "PR.AC-1",  "pci": "8.3.1",
        "mitre": "T1078.004", "mitre_name": "Valid Cloud Accounts",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "exploit_complexity": "LOW",
        "remediation_fn": None,   # cannot programmatically fix root MFA
        "ttb_multiplier": 0.2,
    },
    "iam_root_access_keys": {
        "cis": "1.4",    "nist": "PR.AC-4",  "pci": "7.1",
        "mitre": "T1552.005", "mitre_name": "Cloud Instance Metadata API",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "exploit_complexity": "LOW",
        "remediation_fn": None,
        "ttb_multiplier": 0.15,
    },
    "iam_user_no_mfa": {
        "cis": "1.10",   "nist": "PR.AC-1",  "pci": "8.3.1",
        "mitre": "T1078.004", "mitre_name": "Valid Cloud Accounts",
        "severity": "HIGH",
        "cvss": 8.1,
        "exploit_complexity": "LOW",
        "remediation_fn": None,
        "ttb_multiplier": 0.4,
    },
    "iam_stale_credentials": {
        "cis": "1.12",   "nist": "PR.AC-1",  "pci": "8.1.4",
        "mitre": "T1078", "mitre_name": "Valid Accounts",
        "severity": "MEDIUM",
        "cvss": 6.5,
        "exploit_complexity": "MEDIUM",
        "remediation_fn": "fix_iam_stale_credentials",
        "ttb_multiplier": 0.7,
    },
    "iam_weak_password_policy": {
        "cis": "1.8",    "nist": "PR.AC-1",  "pci": "8.2.3",
        "mitre": "T1110", "mitre_name": "Brute Force",
        "severity": "MEDIUM",
        "cvss": 6.8,
        "exploit_complexity": "MEDIUM",
        "remediation_fn": "fix_iam_password_policy",
        "ttb_multiplier": 0.75,
    },
    "iam_admin_policy": {
        "cis": "1.16",   "nist": "PR.AC-4",  "pci": "7.1",
        "mitre": "T1078.004", "mitre_name": "Valid Cloud Accounts",
        "severity": "HIGH",
        "cvss": 8.8,
        "exploit_complexity": "LOW",
        "remediation_fn": "fix_iam_admin_policy",
        "ttb_multiplier": 0.35,
    },
    "iam_pass_role_escalation": {
        "cis": "1.16",   "nist": "PR.AC-4",  "pci": "7.1",
        "mitre": "T1548", "mitre_name": "Abuse Elevation Control Mechanism",
        "severity": "HIGH",
        "cvss": 8.8,
        "exploit_complexity": "LOW",
        "remediation_fn": None,
        "ttb_multiplier": 0.4,
    },
    "iam_stale_access_key": {
        "cis": "1.13",   "nist": "PR.AC-1",  "pci": "8.1.4",
        "mitre": "T1552.004", "mitre_name": "Private Keys",
        "severity": "MEDIUM",
        "cvss": 6.5,
        "exploit_complexity": "MEDIUM",
        "remediation_fn": "fix_iam_stale_access_key",
        "ttb_multiplier": 0.65,
    },
    "iam_wildcard_action_policy": {
        "cis": "1.16",   "nist": "PR.AC-4",  "pci": "7.1",
        "mitre": "T1078.004", "mitre_name": "Valid Cloud Accounts",
        "severity": "HIGH",
        "cvss": 8.5,
        "exploit_complexity": "LOW",
        "remediation_fn": None,
        "ttb_multiplier": 0.4,
    },
    "iam_inline_policy_escalation": {
        "cis": "1.16",   "nist": "PR.AC-4",  "pci": "7.1",
        "mitre": "T1548.005", "mitre_name": "Temporary Elevated Cloud Access",
        "severity": "HIGH",
        "cvss": 8.8,
        "exploit_complexity": "LOW",
        "remediation_fn": None,
        "ttb_multiplier": 0.4,
    },
    # ── EC2 ─────────────────────────────────────────────────────────────────
    "ec2_ssh_open": {
        "cis": "5.2",    "nist": "PR.AC-3",  "pci": "1.3",
        "mitre": "T1021.004", "mitre_name": "Remote Services: SSH",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "exploit_complexity": "LOW",
        "remediation_fn": "fix_ec2_sg_port",
        "ttb_multiplier": 0.2,
    },
    "ec2_rdp_open": {
        "cis": "5.3",    "nist": "PR.AC-3",  "pci": "1.3",
        "mitre": "T1021.001", "mitre_name": "Remote Services: RDP",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "exploit_complexity": "LOW",
        "remediation_fn": "fix_ec2_sg_port",
        "ttb_multiplier": 0.15,  # RDP scanners are aggressive
    },
    "ec2_db_port_open": {
        "cis": "5.4",    "nist": "PR.AC-3",  "pci": "1.3",
        "mitre": "T1190", "mitre_name": "Exploit Public-Facing Application",
        "severity": "HIGH",
        "cvss": 8.6,
        "exploit_complexity": "LOW",
        "remediation_fn": "fix_ec2_sg_port",
        "ttb_multiplier": 0.3,
    },
    "ec2_imdsv1_enabled": {
        "cis": "5.6",    "nist": "PR.AC-3",  "pci": "6.5",
        "mitre": "T1552.005", "mitre_name": "Cloud Instance Metadata API",
        "severity": "HIGH",
        "cvss": 8.8,
        "exploit_complexity": "LOW",
        "remediation_fn": "fix_ec2_imdsv2",
        "ttb_multiplier": 0.4,
    },
    "ec2_ebs_snapshot_public": {
        "cis": "2.2.1",  "nist": "PR.AC-3",  "pci": "1.3.6",
        "mitre": "T1530", "mitre_name": "Data from Cloud Storage",
        "severity": "CRITICAL",
        "cvss": 9.1,
        "exploit_complexity": "LOW",
        "remediation_fn": "fix_ec2_snapshot_visibility",
        "ttb_multiplier": 0.25,
    },
    "ec2_ebs_no_encryption": {
        "cis": "2.2.2",  "nist": "PR.DS-1",  "pci": "3.4",
        "mitre": "T1565", "mitre_name": "Data Manipulation",
        "severity": "HIGH",
        "cvss": 7.5,
        "exploit_complexity": "MEDIUM",
        "remediation_fn": None,
        "ttb_multiplier": 0.6,
    },
    "ec2_all_ports_open": {
        "cis": "5.1",    "nist": "PR.AC-3",  "pci": "1.3",
        "mitre": "T1190", "mitre_name": "Exploit Public-Facing Application",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "exploit_complexity": "LOW",
        "remediation_fn": "fix_ec2_sg_port",
        "ttb_multiplier": 0.1,
    },
    "ec2_default_sg_in_use": {
        "cis": "5.4",    "nist": "PR.AC-3",  "pci": "1.2",
        "mitre": "T1562.007", "mitre_name": "Disable or Modify Cloud Firewall",
        "severity": "MEDIUM",
        "cvss": 5.4,
        "exploit_complexity": "MEDIUM",
        "remediation_fn": None,
        "ttb_multiplier": 0.9,
    },
    # ── RDS ─────────────────────────────────────────────────────────────────
    "rds_publicly_accessible": {
        "cis": "2.3.2",  "nist": "PR.AC-3",  "pci": "1.3.7",
        "mitre": "T1190", "mitre_name": "Exploit Public-Facing Application",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "exploit_complexity": "LOW",
        "remediation_fn": "fix_rds_public_access",
        "ttb_multiplier": 0.25,
    },
    "rds_no_encryption": {
        "cis": "2.3.1",  "nist": "PR.DS-1",  "pci": "3.4",
        "mitre": "T1565", "mitre_name": "Data Manipulation",
        "severity": "HIGH",
        "cvss": 7.5,
        "exploit_complexity": "MEDIUM",
        "remediation_fn": None,
        "ttb_multiplier": 0.6,
    },
    "rds_no_backup": {
        "cis": "2.3.3",  "nist": "PR.IP-4",  "pci": "12.10",
        "mitre": "T1485", "mitre_name": "Data Destruction",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "exploit_complexity": "MEDIUM",
        "remediation_fn": "fix_rds_backup",
        "ttb_multiplier": 0.9,
    },
    "rds_no_deletion_protection": {
        "cis": "2.3.5",  "nist": "PR.IP-4",  "pci": "12.10",
        "mitre": "T1485", "mitre_name": "Data Destruction",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "exploit_complexity": "MEDIUM",
        "remediation_fn": "fix_rds_deletion_protection",
        "ttb_multiplier": 0.9,
    },
    # ── CloudTrail ───────────────────────────────────────────────────────────
    "cloudtrail_disabled": {
        "cis": "3.1",    "nist": "DE.CM-3",  "pci": "10.1",
        "mitre": "T1562.008", "mitre_name": "Disable Cloud Logs",
        "severity": "CRITICAL",
        "cvss": 8.2,
        "exploit_complexity": "LOW",
        "remediation_fn": "fix_cloudtrail_enable",
        "ttb_multiplier": 0.3,
    },
    "cloudtrail_no_log_validation": {
        "cis": "3.2",    "nist": "DE.CM-3",  "pci": "10.5.2",
        "mitre": "T1565.001", "mitre_name": "Stored Data Manipulation",
        "severity": "HIGH",
        "cvss": 7.4,
        "exploit_complexity": "MEDIUM",
        "remediation_fn": "fix_cloudtrail_validation",
        "ttb_multiplier": 0.6,
    },
    "cloudtrail_not_multiregion": {
        "cis": "3.3",    "nist": "DE.CM-3",  "pci": "10.1",
        "mitre": "T1562.008", "mitre_name": "Disable Cloud Logs",
        "severity": "MEDIUM",
        "cvss": 5.4,
        "exploit_complexity": "MEDIUM",
        "remediation_fn": None,
        "ttb_multiplier": 0.8,
    },
    # ── Lambda ───────────────────────────────────────────────────────────────
    "lambda_public_url": {
        "cis": "—",      "nist": "PR.AC-3",  "pci": "1.3",
        "mitre": "T1190", "mitre_name": "Exploit Public-Facing Application",
        "severity": "HIGH",
        "cvss": 8.6,
        "exploit_complexity": "LOW",
        "remediation_fn": None,
        "ttb_multiplier": 0.3,
    },
    "lambda_env_secrets": {
        "cis": "—",      "nist": "PR.DS-1",  "pci": "3.4",
        "mitre": "T1552.001", "mitre_name": "Credentials In Files",
        "severity": "CRITICAL",
        "cvss": 9.1,
        "exploit_complexity": "LOW",
        "remediation_fn": None,
        "ttb_multiplier": 0.2,
    },
    "lambda_excessive_permissions": {
        "cis": "—",      "nist": "PR.AC-4",  "pci": "7.1",
        "mitre": "T1078.004", "mitre_name": "Valid Cloud Accounts",
        "severity": "HIGH",
        "cvss": 8.1,
        "exploit_complexity": "LOW",
        "remediation_fn": None,
        "ttb_multiplier": 0.4,
    },
    # ── SNS / SQS ────────────────────────────────────────────────────────────
    "sns_public_topic": {
        "cis": "—",      "nist": "PR.AC-3",  "pci": "1.3",
        "mitre": "T1078.004", "mitre_name": "Valid Cloud Accounts",
        "severity": "HIGH",
        "cvss": 7.5,
        "exploit_complexity": "LOW",
        "remediation_fn": None,
        "ttb_multiplier": 0.5,
    },
    "sqs_public_queue": {
        "cis": "—",      "nist": "PR.AC-3",  "pci": "1.3",
        "mitre": "T1078.004", "mitre_name": "Valid Cloud Accounts",
        "severity": "HIGH",
        "cvss": 7.5,
        "exploit_complexity": "LOW",
        "remediation_fn": None,
        "ttb_multiplier": 0.5,
    },
    # ── KMS ──────────────────────────────────────────────────────────────────
    "kms_key_rotation_disabled": {
        "cis": "3.7",    "nist": "PR.DS-1",  "pci": "3.6",
        "mitre": "T1552", "mitre_name": "Unsecured Credentials",
        "severity": "MEDIUM",
        "cvss": 6.3,
        "exploit_complexity": "MEDIUM",
        "remediation_fn": "fix_kms_rotation",
        "ttb_multiplier": 0.9,
    },
    "kms_public_key_policy": {
        "cis": "—",      "nist": "PR.AC-3",  "pci": "3.6",
        "mitre": "T1552", "mitre_name": "Unsecured Credentials",
        "severity": "CRITICAL",
        "cvss": 9.1,
        "exploit_complexity": "LOW",
        "remediation_fn": None,
        "ttb_multiplier": 0.25,
    },
}

# ── Attacker speed benchmarks (requests-per-day from threat intel)
# Used by Time-To-Breach estimator
ATTACKER_BENCHMARKS = {
    "LOW":      {"requests_per_day": 500,   "automation": False},
    "MEDIUM":   {"requests_per_day": 5000,  "automation": True},
    "HIGH":     {"requests_per_day": 50000, "automation": True},
    "CRITICAL": {"requests_per_day": 500000,"automation": True},
}

# ── Canary token templates
CANARY_SERVICES = ["s3", "iam", "lambda"]

# ── Remediation risk levels (how safe is auto-fix?)
REMEDIATION_RISK = {
    "fix_s3_public_acl":            "SAFE",
    "fix_s3_public_policy":         "SAFE",
    "fix_s3_encryption":            "SAFE",
    "fix_s3_versioning":            "SAFE",
    "fix_s3_logging":               "SAFE",
    "fix_s3_mfa_delete":            "DISRUPTIVE",
    "fix_iam_password_policy":      "SAFE",
    "fix_iam_stale_credentials":    "DISRUPTIVE",
    "fix_iam_stale_access_key":     "DISRUPTIVE",
    "fix_iam_admin_policy":         "DISRUPTIVE",
    "fix_ec2_sg_port":              "SAFE",
    "fix_ec2_imdsv2":               "SAFE",
    "fix_ec2_snapshot_visibility":  "SAFE",
    "fix_rds_public_access":        "SAFE",
    "fix_rds_backup":               "SAFE",
    "fix_rds_deletion_protection":  "SAFE",
    "fix_cloudtrail_enable":        "SAFE",
    "fix_cloudtrail_validation":    "SAFE",
    "fix_kms_rotation":             "SAFE",
}

# ══════════════════════════════════════════════════════════════════════════════
#  LOW-NOISE SCAN CONFIG  🔇
#  Reduced-footprint scanning for production environments.
#  Adds inter-request delays and rate limiting to minimize API call density.
#  Note: This does not attempt to evade any AWS security service.
# ══════════════════════════════════════════════════════════════════════════════

LOW_NOISE_USER_AGENTS = [
    "aws-cli/2.15.30 Python/3.11.8 Linux/6.7.6 botocore/2.6.30",
    "Boto3/1.34.69 Python/3.12.2 Linux/6.7.6 Botocore/1.34.69",
    "aws-sdk-go/1.51.6 (go1.22.1; linux; amd64)",
    "aws-sdk-java/2.25.16 Linux/6.7.6 OpenJDK_64-Bit_Server_VM/21.0.2",
]

# Jitter ranges for low-noise mode (seconds)
LOW_NOISE_JITTER_MIN = 0.3
LOW_NOISE_JITTER_MAX = 2.8

# Boto3 retry config — exponential backoff on throttling
BOTO_RETRY_CONFIG = BotocoreConfig(
    retries={"max_attempts": 5, "mode": "adaptive"},
    max_pool_connections=20,
)

# ── Kept for backwards compatibility with --stealth flag
STEALTH_USER_AGENTS  = LOW_NOISE_USER_AGENTS
STEALTH_JITTER_MIN   = LOW_NOISE_JITTER_MIN
STEALTH_JITTER_MAX   = LOW_NOISE_JITTER_MAX
STEALTH_READ_PATTERN = ["Describe", "List", "Get", "Scan", "Query"]


# ══════════════════════════════════════════════════════════════════════════════
#  UTILS
# ══════════════════════════════════════════════════════════════════════════════

def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()

def _rand_id(n=8) -> str:
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

def _stealth_sleep(stealth: bool):
    if stealth:
        time.sleep(random.uniform(LOW_NOISE_JITTER_MIN, LOW_NOISE_JITTER_MAX))

# Alias — --low-noise and --stealth both call this
_low_noise_sleep = _stealth_sleep


def _paginate(client, method: str, result_key: str, **kwargs) -> List[Dict]:
    """
    Universal paginator helper — works for any boto3 list/describe call.
    Falls back gracefully if the method doesn't support pagination.

    Usage:
        buckets = _paginate(s3, "list_buckets", "Buckets")
        users   = _paginate(iam, "list_users", "Users", MaxItems=1000)
    """
    try:
        paginator = client.get_paginator(method)
        results   = []
        for page in paginator.paginate(**kwargs):
            results.extend(page.get(result_key, []))
        return results
    except client.exceptions.from_code("OperationNotPageable") if hasattr(client, "exceptions") else Exception:
        # Method doesn't support pagination — call directly
        fn = getattr(client, method)
        return fn(**kwargs).get(result_key, [])
    except Exception:
        fn = getattr(client, method, None)
        if fn:
            try:
                return fn(**kwargs).get(result_key, [])
            except Exception:
                return []
        return []

def _color(text: str, code: str) -> str:
    """ANSI color helper."""
    return f"\033[{code}m{text}\033[0m"

def red(t):    return _color(t, "91")
def yellow(t): return _color(t, "93")
def green(t):  return _color(t, "92")
def cyan(t):   return _color(t, "96")
def bold(t):   return _color(t, "1")

def sev_color(sev: str, text: str) -> str:
    m = {"CRITICAL": red, "HIGH": yellow, "MEDIUM": cyan, "LOW": green}
    return m.get(sev, lambda x: x)(text)

def _risk_score(severity: str, cvss: float, public_exposure: bool, age_days: int) -> float:
    """Composite risk = CVSS base + exposure bonus + age decay."""
    base = cvss
    if public_exposure:
        base = min(10.0, base + 1.5)
    age_bonus = min(2.0, age_days / 180)   # older = higher risk
    sev_bonus = {"CRITICAL": 1.0, "HIGH": 0.5, "MEDIUM": 0.0, "LOW": -0.5}.get(severity, 0)
    return round(min(10.0, base + age_bonus + sev_bonus), 1)


# ══════════════════════════════════════════════════════════════════════════════
#  SCAN HISTORY DB  (SQLite)
# ══════════════════════════════════════════════════════════════════════════════

class ScanHistoryDB:
    def __init__(self, path: str = DB_PATH):
        self.path = path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_time   TEXT NOT NULL,
                    account_id  TEXT,
                    region      TEXT,
                    total       INTEGER,
                    critical    INTEGER,
                    high        INTEGER,
                    medium      INTEGER,
                    low         INTEGER,
                    score       REAL,
                    attack_paths INTEGER,
                    report_json TEXT
                );
                CREATE TABLE IF NOT EXISTS findings (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id     INTEGER REFERENCES scans(id),
                    check_id    TEXT,
                    service     TEXT,
                    severity    TEXT,
                    resource    TEXT,
                    risk_score  REAL
                );
                CREATE TABLE IF NOT EXISTS canaries (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at  TEXT,
                    token_id    TEXT UNIQUE,
                    service     TEXT,
                    resource    TEXT,
                    triggered   INTEGER DEFAULT 0,
                    triggered_at TEXT
                );
                CREATE TABLE IF NOT EXISTS remediations (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    applied_at  TEXT,
                    check_id    TEXT,
                    resource    TEXT,
                    action      TEXT,
                    status      TEXT
                );
            """)

    def save(self, report: Dict) -> int:
        s   = report.get("summary", {})
        sev = s.get("severity_breakdown", {})
        with sqlite3.connect(self.path) as conn:
            cur = conn.execute("""
                INSERT INTO scans
                  (scan_time, account_id, region, total, critical, high, medium, low, score, attack_paths, report_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """, (
                report.get("scan_time", _ts()),
                report.get("account_id", ""),
                report.get("region", ""),
                s.get("total_findings", 0),
                sev.get("CRITICAL", 0),
                sev.get("HIGH", 0),
                sev.get("MEDIUM", 0),
                sev.get("LOW", 0),
                s.get("compliance_score", 0),
                s.get("attack_paths_found", 0),
                json.dumps(report, default=str),
            ))
            scan_id = cur.lastrowid
            for f in report.get("findings", []):
                conn.execute("""
                    INSERT INTO findings (scan_id, check_id, service, severity, resource, risk_score)
                    VALUES (?,?,?,?,?,?)
                """, (scan_id, f.get("check_id",""), f.get("service",""),
                      f.get("severity",""), f.get("resource",""), f.get("risk_score",0)))
        return scan_id

    def get_trends(self, limit: int = 50) -> List[Dict]:
        with sqlite3.connect(self.path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY scan_time ASC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_latest_report(self) -> Optional[Dict]:
        with sqlite3.connect(self.path) as conn:
            row = conn.execute(
                "SELECT report_json FROM scans ORDER BY id DESC LIMIT 1"
            ).fetchone()
        return json.loads(row[0]) if row else None

    def log_canary(self, token_id: str, service: str, resource: str):
        with sqlite3.connect(self.path) as conn:
            conn.execute("""
                INSERT OR IGNORE INTO canaries (created_at, token_id, service, resource)
                VALUES (?,?,?,?)
            """, (_ts(), token_id, service, resource))

    def trigger_canary(self, token_id: str):
        with sqlite3.connect(self.path) as conn:
            conn.execute("""
                UPDATE canaries SET triggered=1, triggered_at=? WHERE token_id=?
            """, (_ts(), token_id))

    def get_canaries(self) -> List[Dict]:
        with sqlite3.connect(self.path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM canaries ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

    def log_remediation(self, check_id: str, resource: str, action: str, status: str):
        with sqlite3.connect(self.path) as conn:
            conn.execute("""
                INSERT INTO remediations (applied_at, check_id, resource, action, status)
                VALUES (?,?,?,?,?)
            """, (_ts(), check_id, resource, action, status))


# ══════════════════════════════════════════════════════════════════════════════
#  ⏱️  TIME-TO-BREACH ESTIMATOR
#  Uses exposure + exploit complexity + attacker speed benchmarks
#  to produce a "days until exploitation" estimate per finding
# ══════════════════════════════════════════════════════════════════════════════

class TimeToBreach:
    """
    Estimates how many days remain before a given vulnerability is likely
    to be discovered and exploited by an attacker.

    Model:
      TTB = base_days × exploit_complexity_factor × exposure_factor × age_factor

    - base_days       : derived from severity and CVE data (how fast attackers scan)
    - complexity_factor: LOW complexity = faster exploitation
    - exposure_factor  : publicly exposed resources get hit much faster
    - age_factor       : older findings are more likely already known to attackers
    """

    BASE_DAYS = {
        "CRITICAL": 2.0,
        "HIGH":     7.0,
        "MEDIUM":   30.0,
        "LOW":      120.0,
    }

    COMPLEXITY_FACTOR = {
        "LOW":    0.5,
        "MEDIUM": 1.0,
        "HIGH":   3.0,
    }

    def estimate(self, finding: Dict) -> Dict:
        check_id   = finding.get("check_id", "")
        ctrl       = CONTROLS.get(check_id, {})
        severity   = finding.get("severity", "MEDIUM")
        cvss       = ctrl.get("cvss", 5.0)
        complexity = ctrl.get("exploit_complexity", "MEDIUM")
        ttb_mult   = ctrl.get("ttb_multiplier", 1.0)
        public     = self._is_public(finding)
        age_days   = finding.get("age_days", 0)

        base        = self.BASE_DAYS.get(severity, 30.0)
        comp_factor = self.COMPLEXITY_FACTOR.get(complexity, 1.0)
        exp_factor  = 0.4 if public else 1.0
        age_factor  = max(0.5, 1.0 - (age_days / 365) * 0.4)

        ttb = base * comp_factor * exp_factor * age_factor * ttb_mult

        # CVSS score nudge: higher CVSS = shorter TTB
        cvss_nudge = max(0.3, (10.0 - cvss) / 10.0)
        ttb *= cvss_nudge

        ttb = max(0.1, ttb)

        urgency = "IMMEDIATE"  if ttb < 1   else \
                  "CRITICAL"   if ttb < 3   else \
                  "HIGH"       if ttb < 7   else \
                  "MEDIUM"     if ttb < 30  else "LOW"

        return {
            "estimated_days":    round(ttb, 1),
            "urgency":           urgency,
            "public_exposure":   public,
            "exploit_complexity": complexity,
            "model_factors": {
                "base_days":    base,
                "complexity_f": comp_factor,
                "exposure_f":   exp_factor,
                "age_f":        age_factor,
                "ttb_mult":     ttb_mult,
                "cvss_nudge":   cvss_nudge,
            }
        }

    def _is_public(self, finding: Dict) -> bool:
        msg = finding.get("message", "").lower()
        return any(k in msg for k in ["public", "0.0.0.0", "::/0", "open to internet"])


# ══════════════════════════════════════════════════════════════════════════════
#  🧬 BLAST RADIUS CALCULATOR
#  Given a compromised resource, recursively maps every other resource
#  that becomes compromisable as a consequence.
# ══════════════════════════════════════════════════════════════════════════════

class BlastRadiusCalculator:
    """
    Builds a directed compromise graph: nodes = AWS resources, edges = pivot paths.

    v4.0 additions:
      1. Full IAM pagination (handles 1000+ roles)
      2. Graph Centrality Scoring:
           - Betweenness centrality: nodes that sit on the most attack paths
           - Eigenvector centrality: nodes connected to other high-value nodes
      3. Risk Propagation Engine:
           NodeRisk = BaseRisk + Σ(ParentRisk × EdgeWeight × DecayFactor)
         Risk flows downstream through the graph like water — a compromised
         high-risk node amplifies the risk of everything it can reach.

    Edge types:
      TRUST_ASSUMPTION   — X can assume IAM role Y (weight: 0.9)
      NETWORK_PIVOT      — X in same VPC as Y → lateral movement (weight: 0.7)
      DATA_EXFIL         — Compromised IAM X can read data from Y (weight: 0.8)
      CREDENTIAL_THEFT   — X exposes credentials that unlock Y (weight: 0.95)
    """

    # Edge weights for risk propagation (how much risk flows across each edge type)
    EDGE_WEIGHTS: Dict[str, float] = {
        "TRUST_ASSUMPTION":  0.90,
        "CREDENTIAL_THEFT":  0.95,
        "DATA_EXFIL":        0.80,
        "NETWORK_PIVOT":     0.70,
        "LATERAL_MOVEMENT":  0.75,
    }

    # Service value multipliers for crown jewel scoring
    SERVICE_VALUE: Dict[str, float] = {
        "RDS": 5.0, "S3": 4.5, "IAM": 4.0, "KMS": 4.5,
        "Lambda": 3.0, "EC2": 2.5, "SNS": 2.0, "SQS": 2.0,
    }

    # Risk decay per hop — risk attenuates as it flows further downstream
    DECAY_PER_HOP = 0.85

    def __init__(self, session: boto3.Session, region: str, findings: List[Dict]):
        self.session  = session
        self.region   = region
        self.findings = findings
        self.graph    = nx.DiGraph() if HAS_NETWORKX else None
        self._node_base_risk: Dict[str, float] = {}

    def build_graph(self, low_noise: bool = False) -> Dict:
        """Construct the full resource relationship graph with centrality + propagation."""
        print(f"\n  🧬 Building blast radius graph (v4.0 — centrality + risk propagation)...")

        nodes: List[Dict] = []
        edges: List[Dict] = []
        node_set: Set[str] = set()

        def _add_node(nid: str, service: str, severity: str = "LOW",
                      compromised: bool = False, base_risk: float = 0.0):
            if nid and nid not in node_set:
                node_set.add(nid)
                nodes.append({
                    "id": nid, "service": service,
                    "severity": severity, "compromised": compromised,
                    "base_risk": base_risk,
                })
                self._node_base_risk[nid] = base_risk
                if self.graph is not None:
                    self.graph.add_node(nid, service=service,
                                        severity=severity, base_risk=base_risk)

        def _add_edge(src: str, dst: str, edge_type: str, description: str = ""):
            if src and dst and src != dst:
                weight = self.EDGE_WEIGHTS.get(edge_type, 0.5)
                edges.append({"source": src, "target": dst,
                               "edge_type": edge_type, "description": description,
                               "weight": weight})
                if self.graph is not None:
                    self.graph.add_edge(src, dst, edge_type=edge_type, weight=weight)

        # ── Seed nodes from findings ─────────────────────────────────────────
        sev_risk = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}
        for f in self.findings:
            sev = f.get("severity", "LOW")
            _add_node(
                f.get("resource", ""), f.get("service", ""), sev,
                compromised=sev in ("CRITICAL", "HIGH"),
                base_risk=f.get("risk_score") or sev_risk.get(sev, 2.5),
            )

        # ── IAM role trust relationships (PAGINATED) ─────────────────────────
        try:
            iam   = self.session.client("iam", config=BOTO_RETRY_CONFIG)
            _low_noise_sleep(low_noise)
            roles = _paginate(iam, "list_roles", "Roles")
            for role in roles:
                role_arn  = role["Arn"]
                role_name = role["RoleName"]
                doc       = role.get("AssumeRolePolicyDocument", {})
                for stmt in doc.get("Statement", []):
                    if stmt.get("Effect") != "Allow":
                        continue
                    principal = stmt.get("Principal", {})
                    aws_ps = principal if isinstance(principal, list) else \
                             ([principal] if isinstance(principal, str) else
                              principal.get("AWS", []))
                    if isinstance(aws_ps, str):
                        aws_ps = [aws_ps]
                    for p in aws_ps:
                        for nid in list(node_set):
                            if nid in p or p in nid:
                                _add_node(role_arn, "IAM", "HIGH", base_risk=7.0)
                                _add_edge(nid, role_arn, "TRUST_ASSUMPTION",
                                          f"Can assume role {role_name}")
        except ClientError:
            pass

        # ── EC2 VPC lateral movement (PAGINATED) ─────────────────────────────
        try:
            ec2 = self.session.client("ec2", region_name=self.region,
                                      config=BOTO_RETRY_CONFIG)
            _low_noise_sleep(low_noise)
            reservations = _paginate(ec2, "describe_instances", "Reservations")
            vpc_instances: Dict[str, List[str]] = defaultdict(list)
            for res in reservations:
                for inst in res.get("Instances", []):
                    iid = inst.get("InstanceId", "")
                    vpc = inst.get("VpcId", "")
                    if iid and vpc:
                        vpc_instances[vpc].append(iid)
                        _add_node(iid, "EC2", "LOW", base_risk=2.5)

            for vpc, instances in vpc_instances.items():
                for i, src in enumerate(instances):
                    src_f = next((f for f in self.findings
                                  if src in f.get("resource", "")), None)
                    if src_f and src_f.get("severity") in ("CRITICAL", "HIGH"):
                        for dst in instances[i+1:]:
                            _add_edge(src, dst, "NETWORK_PIVOT",
                                      f"Same VPC ({vpc}) lateral movement")
        except ClientError:
            pass

        # ── S3 data exfil from compromised IAM ───────────────────────────────
        iam_compromised = [f for f in self.findings
                           if f.get("service") == "IAM"
                           and f.get("severity") in ("CRITICAL", "HIGH")]
        s3_nodes = [n for n in nodes if n.get("service") == "S3"]
        for iam_f in iam_compromised:
            for s3n in s3_nodes:
                _add_edge(iam_f.get("resource", ""), s3n["id"], "DATA_EXFIL",
                          "Compromised IAM credential can access S3 data")

        # ── Lambda credential theft ───────────────────────────────────────────
        lambda_secret = [f for f in self.findings
                         if f.get("check_id") == "lambda_env_secrets"]
        for lf in lambda_secret:
            for iam_node in [n for n in nodes if n.get("service") == "IAM"]:
                _add_edge(lf.get("resource", ""), iam_node["id"],
                          "CREDENTIAL_THEFT",
                          "Lambda secret env vars may expose IAM credentials")

        # ── 1. GRAPH CENTRALITY SCORING ──────────────────────────────────────
        centrality: Dict[str, Dict[str, float]] = {}
        if HAS_NETWORKX and self.graph and len(self.graph.nodes()) > 1:
            try:
                bc = nx.betweenness_centrality(self.graph, normalized=True, weight="weight")
            except Exception:
                bc = {n: 0.0 for n in self.graph.nodes()}
            try:
                # eigenvector_centrality can fail on disconnected graphs
                ec_scores = nx.eigenvector_centrality(
                    self.graph, max_iter=500, weight="weight"
                )
            except Exception:
                ec_scores = {n: 0.0 for n in self.graph.nodes()}

            for nid in self.graph.nodes():
                centrality[nid] = {
                    "betweenness":  round(bc.get(nid, 0.0), 4),
                    "eigenvector":  round(ec_scores.get(nid, 0.0), 4),
                    # Combined: betweenness finds bottlenecks, eigenvector finds hubs
                    "combined":     round(bc.get(nid, 0.0) * 0.6 +
                                         ec_scores.get(nid, 0.0) * 0.4, 4),
                }

            # Annotate nodes with centrality
            for node in nodes:
                nid = node["id"]
                node["centrality"] = centrality.get(nid, {"betweenness": 0.0,
                                                           "eigenvector": 0.0,
                                                           "combined": 0.0})
            print(f"     → Centrality computed: {len(centrality)} nodes scored")

        # ── 2. RISK PROPAGATION ENGINE ────────────────────────────────────────
        # NodeRisk(v) = BaseRisk(v) + Σ_u∈parents(u→v) [ NodeRisk(u) × edge_weight × decay^hop ]
        # We run iterative relaxation (similar to PageRank) until convergence.
        propagated_risk: Dict[str, float] = {n["id"]: n["base_risk"] for n in nodes}
        if HAS_NETWORKX and self.graph and len(self.graph.nodes()) > 1:
            try:
                # Topological sort for correct propagation order
                topo_order = list(nx.topological_sort(self.graph))
            except nx.NetworkXUnfeasible:
                # Graph has cycles — use iterative approximation instead
                topo_order = list(self.graph.nodes())

            MAX_ITERATIONS = 10
            for _ in range(MAX_ITERATIONS):
                prev = dict(propagated_risk)
                for nid in topo_order:
                    if not self.graph.has_node(nid):
                        continue
                    parent_contribution = 0.0
                    for parent in self.graph.predecessors(nid):
                        edge_data   = self.graph.get_edge_data(parent, nid, {})
                        ew          = edge_data.get("weight", 0.5)
                        parent_risk = prev.get(parent, 0.0)
                        # Risk decays with each hop; cap contribution at 3.0
                        parent_contribution += min(3.0, parent_risk * ew * self.DECAY_PER_HOP)
                    propagated_risk[nid] = min(10.0, prev.get(nid, 0.0) + parent_contribution)

                # Check convergence
                delta = sum(abs(propagated_risk[k] - prev.get(k, 0.0))
                            for k in propagated_risk)
                if delta < 0.01:
                    break

            # Annotate nodes with propagated risk
            for node in nodes:
                nid = node["id"]
                node["propagated_risk"] = round(propagated_risk.get(nid, node["base_risk"]), 2)
            print(f"     → Risk propagation complete: max propagated risk = "
                  f"{max(propagated_risk.values(), default=0):.1f}")

        # ── Blast radius ──────────────────────────────────────────────────────
        compromised_count = len([n for n in nodes if n.get("compromised")])
        total_reachable   = self._count_reachable(nodes, edges)
        blast_pct         = round(total_reachable / max(len(nodes), 1) * 100, 1)

        crown_jewels = self._find_crown_jewels(nodes, edges, centrality, propagated_risk)
        chains       = self._find_chains(nodes, edges)

        result = {
            "nodes":                    nodes,
            "edges":                    edges,
            "total_resources":          len(nodes),
            "compromised_entry_points": compromised_count,
            "total_reachable":          total_reachable,
            "blast_radius_pct":         blast_pct,
            "highest_value_targets":    crown_jewels,
            "attack_chains":            chains,
            "centrality_leaders":       self._top_by_centrality(centrality),
            "max_propagated_risk":      round(max(propagated_risk.values(), default=0), 2),
        }

        print(f"     → {len(nodes)} resources mapped, {len(edges)} pivot paths found")
        print(f"     → Blast radius: {blast_pct}% of environment reachable")
        return result

    def _count_reachable(self, nodes: List[Dict], edges: List[Dict]) -> int:
        compromised = {n["id"] for n in nodes if n.get("compromised")}
        adj: Dict[str, Set[str]] = defaultdict(set)
        for e in edges:
            adj[e["source"]].add(e["target"])
        visited = set(compromised)
        queue   = deque(compromised)
        while queue:
            curr = queue.popleft()
            for neighbor in adj.get(curr, set()):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)
        return len(visited) - len(compromised)

    def _find_crown_jewels(self, nodes: List[Dict], edges: List[Dict],
                           centrality: Dict, propagated_risk: Dict) -> List[Dict]:
        """
        Crown jewel score = inbound_edges × service_value
                          + centrality_combined × 5
                          + propagated_risk × 0.5
        """
        inbound: Dict[str, int] = defaultdict(int)
        for e in edges:
            inbound[e["target"]] += 1

        crown_jewels = []
        for node in nodes:
            nid   = node["id"]
            svc   = node.get("service", "")
            sval  = self.SERVICE_VALUE.get(svc, 1.0)
            cent  = centrality.get(nid, {}).get("combined", 0.0)
            prop  = propagated_risk.get(nid, 0.0)
            score = (inbound.get(nid, 0) * sval) + (cent * 5) + (prop * 0.5)
            if score > 0:
                crown_jewels.append({
                    **node,
                    "target_value_score": round(score, 2),
                    "propagated_risk":    round(prop, 2),
                    "centrality_combined": round(cent, 4),
                })

        return sorted(crown_jewels, key=lambda x: x["target_value_score"], reverse=True)[:8]

    def _top_by_centrality(self, centrality: Dict) -> List[Dict]:
        """Top 5 nodes by betweenness centrality — these are chokepoints."""
        if not centrality:
            return []
        ranked = sorted(centrality.items(), key=lambda x: x[1].get("betweenness", 0), reverse=True)
        return [{"node": nid, **scores} for nid, scores in ranked[:5]]

    def _find_chains(self, nodes: List[Dict], edges: List[Dict]) -> List[List[str]]:
        if not HAS_NETWORKX or not self.graph:
            return []
        compromised = [n["id"] for n in nodes if n.get("compromised")]
        chains = []
        for src in compromised:
            if src in self.graph:
                for dst in self.graph.nodes():
                    if dst != src:
                        try:
                            path = nx.shortest_path(self.graph, src, dst)
                            if len(path) > 2:
                                chains.append(path)
                        except (nx.NetworkXNoPath, nx.NodeNotFound):
                            pass
        return sorted(chains, key=len, reverse=True)[:5]


# ══════════════════════════════════════════════════════════════════════════════
#  🔴 LIVE ATTACK PATH SIMULATOR
#  Actually walks each hop using real boto3 read-only calls to verify
#  whether the attack path is truly exploitable, not just theoretical.
# ══════════════════════════════════════════════════════════════════════════════

class AttackPathSimulator:
    """
    For each attack path finding, attempts real boto3 calls (read-only)
    to confirm that the misconfiguration is genuinely exploitable.

    Verification steps by check:
      s3_public_acl/policy  → list_objects on the bucket without auth
      ec2_ssh_open          → confirm port 22 CIDR is 0.0.0.0/0 in SG rules
      ec2_imdsv1_enabled    → verify IMDSv2 is not enforced on instance
      rds_publicly_accessible → DNS resolve the endpoint and confirm TCP open
      iam_admin_policy      → list attached policies and verify AdministratorAccess
      lambda_env_secrets    → regex scan env var names for secret patterns
    """

    SECRET_ENV_PATTERNS = re.compile(
        r'(?i)(password|passwd|pwd|secret|token|api_?key|access_?key|private_?key'
        r'|db_?pass|database_?url|connection_?string|auth|credential|cert|private)',
        re.IGNORECASE
    )

    def __init__(self, session: boto3.Session, region: str):
        self.session = session
        self.region  = region
        self._results: List[Dict] = []

    def simulate(self, findings: List[Dict], stealth: bool = False) -> List[Dict]:
        print(f"\n  🔴 Running live attack simulation on {len(findings)} findings...")
        results = []
        with ThreadPoolExecutor(max_workers=3 if stealth else 8) as ex:
            futures = {ex.submit(self._verify, f, stealth): f for f in findings}
            for fut in as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception:
                    results.append({**futures[fut], "simulated": False, "sim_error": "exception"})

        verified_count = sum(1 for r in results if r.get("verified_exploitable"))
        print(f"     → {verified_count}/{len(results)} findings confirmed exploitable by live test")
        return results

    def _verify(self, finding: Dict, stealth: bool) -> Dict:
        _stealth_sleep(stealth)
        check = finding.get("check_id", "")
        resource = finding.get("resource", "")

        handler = {
            "s3_public_acl":          self._verify_s3_public,
            "s3_public_policy":       self._verify_s3_public,
            "ec2_ssh_open":           self._verify_ec2_open_port,
            "ec2_rdp_open":           self._verify_ec2_open_port,
            "ec2_all_ports_open":     self._verify_ec2_open_port,
            "ec2_db_port_open":       self._verify_ec2_open_port,
            "ec2_imdsv1_enabled":     self._verify_imdsv1,
            "ec2_ebs_snapshot_public":self._verify_snapshot_public,
            "rds_publicly_accessible":self._verify_rds_public,
            "iam_admin_policy":       self._verify_iam_admin,
            "iam_wildcard_action_policy": self._verify_iam_wildcard,
            "lambda_env_secrets":     self._verify_lambda_secrets,
        }.get(check)

        if handler:
            verified, evidence, attack_cmd = handler(finding)
        else:
            verified, evidence, attack_cmd = None, "No live verifier for this check", ""

        # Simulation Score (0–100): quantified exploitability confidence
        # Components: verifier confidence + severity weight + exposure bonus
        sim_score = self._compute_sim_score(finding, verified)

        return {
            **finding,
            "simulated":            True,
            "verified_exploitable": verified,
            "sim_evidence":         evidence,
            "proof_of_concept":     attack_cmd,
            "sim_score":            sim_score,   # 0-100 exploitability confidence
        }

    def _compute_sim_score(self, finding: Dict, verified: Optional[bool]) -> int:
        """
        Simulation Score = verifier_confidence + severity_base + exposure_bonus

        verifier_confidence:
          True  → 50 (confirmed)
          False → 0  (disproven)
          None  → 20 (no verifier / indeterminate)

        severity_base:
          CRITICAL → 30, HIGH → 20, MEDIUM → 10, LOW → 5

        exposure_bonus:
          +20 if publicly exposed
        """
        vc = 50 if verified is True else (0 if verified is False else 20)
        sb = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5}.get(
            finding.get("severity", "LOW"), 5)
        msg = finding.get("message", "").lower()
        eb  = 20 if any(k in msg for k in ["public", "0.0.0.0", "::/0", "internet"]) else 0
        return min(100, vc + sb + eb)

    def _verify_s3_public(self, finding: Dict) -> Tuple[Optional[bool], str, str]:
        bucket = finding.get("resource", "").replace("arn:aws:s3:::", "").split("/")[0]
        try:
            # Try unauthenticated list — use a fresh no-credential session
            import botocore
            anon_s3 = boto3.client(
                "s3",
                config=botocore.config.Config(signature_version=botocore.UNSIGNED),
            )
            anon_s3.list_objects_v2(Bucket=bucket, MaxKeys=1)
            attack_cmd = f"aws s3 ls s3://{bucket} --no-sign-request"
            return True, f"Bucket '{bucket}' is publicly listable without credentials", attack_cmd
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDenied", "AllAccessDisabled"):
                return False, f"Bucket '{bucket}' denied unauthenticated access ({code})", ""
            return None, f"Could not verify: {code}", ""

    def _verify_ec2_open_port(self, finding: Dict) -> Tuple[Optional[bool], str, str]:
        sg_id = finding.get("resource", "")
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            sgs = ec2.describe_security_groups(GroupIds=[sg_id]).get("SecurityGroups", [])
            for sg in sgs:
                for rule in sg.get("IpPermissions", []):
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            from_port = rule.get("FromPort", 0)
                            to_port   = rule.get("ToPort", 65535)
                            cmd = f"nmap -p {from_port}-{to_port} <instance-public-ip>"
                            return True, f"Port {from_port}-{to_port} open to 0.0.0.0/0 in {sg_id}", cmd
                    for ip_range in rule.get("Ipv6Ranges", []):
                        if ip_range.get("CidrIpv6") == "::/0":
                            from_port = rule.get("FromPort", 0)
                            cmd = f"nmap -6 -p {from_port} <instance-ipv6>"
                            return True, f"Port {from_port} open to ::/0 (IPv6) in {sg_id}", cmd
        except ClientError:
            pass
        return None, "Could not retrieve security group details", ""

    def _verify_imdsv1(self, finding: Dict) -> Tuple[Optional[bool], str, str]:
        instance_id = finding.get("resource", "")
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            resp = ec2.describe_instances(InstanceIds=[instance_id])
            for res in resp.get("Reservations", []):
                for inst in res.get("Instances", []):
                    opts = inst.get("MetadataOptions", {})
                    if opts.get("HttpTokens") != "required":
                        cmd = ("curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ "
                               "  # run from inside the instance or via SSRF")
                        return True, f"IMDSv1 accessible: HttpTokens={opts.get('HttpTokens','optional')}", cmd
                    else:
                        return False, "IMDSv2 enforced (HttpTokens=required)", ""
        except ClientError:
            pass
        return None, "Could not verify IMDS configuration", ""

    def _verify_snapshot_public(self, finding: Dict) -> Tuple[Optional[bool], str, str]:
        snap_id = finding.get("resource", "")
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            attrs = ec2.describe_snapshot_attribute(
                SnapshotId=snap_id, Attribute="createVolumePermission"
            )
            perms = attrs.get("CreateVolumePermissions", [])
            if any(p.get("Group") == "all" for p in perms):
                cmd = (f"aws ec2 create-volume --snapshot-id {snap_id} "
                       f"--availability-zone us-east-1a --no-sign-request")
                return True, f"Snapshot {snap_id} is publicly shared (Group=all)", cmd
        except ClientError:
            pass
        return None, "Could not verify snapshot permissions", ""

    def _verify_rds_public(self, finding: Dict) -> Tuple[Optional[bool], str, str]:
        db_id = finding.get("resource", "").split(":")[-1]
        try:
            rds = self.session.client("rds", region_name=self.region)
            dbs = rds.describe_db_instances(DBInstanceIdentifier=db_id).get("DBInstances", [])
            for db in dbs:
                if db.get("PubliclyAccessible"):
                    endpoint = db.get("Endpoint", {}).get("Address", "")
                    port     = db.get("Endpoint", {}).get("Port", 5432)
                    engine   = db.get("Engine", "unknown")
                    cmd = f"nmap -p {port} {endpoint}  # then: {engine} -h {endpoint} -P {port}"
                    return True, f"RDS instance {db_id} is publicly accessible at {endpoint}:{port}", cmd
        except ClientError:
            pass
        return None, "Could not verify RDS public accessibility", ""

    def _verify_iam_admin(self, finding: Dict) -> Tuple[Optional[bool], str, str]:
        entity = finding.get("resource", "")
        try:
            iam = self.session.client("iam")
            entity_name = entity.split("/")[-1]

            # Check user attached policies
            try:
                attached = iam.list_attached_user_policies(UserName=entity_name).get("AttachedPolicies", [])
            except ClientError:
                try:
                    attached = iam.list_attached_role_policies(RoleName=entity_name).get("AttachedPolicies", [])
                except ClientError:
                    attached = []

            for pol in attached:
                if pol.get("PolicyName") == "AdministratorAccess":
                    cmd = (f"# With {entity_name}'s credentials:\n"
                           f"aws iam list-roles  # full AWS admin access")
                    return True, f"AdministratorAccess policy confirmed attached to {entity_name}", cmd
        except ClientError:
            pass
        return None, "Could not verify IAM admin policy", ""

    def _verify_iam_wildcard(self, finding: Dict) -> Tuple[Optional[bool], str, str]:
        policy_arn = finding.get("resource", "")
        try:
            iam = self.session.client("iam")
            versions = iam.list_policy_versions(PolicyArn=policy_arn).get("Versions", [])
            default  = next((v for v in versions if v.get("IsDefaultVersion")), None)
            if default:
                doc = iam.get_policy_version(
                    PolicyArn=policy_arn, VersionId=default["VersionId"]
                ).get("PolicyVersion", {}).get("Document", {})
                stmts = doc.get("Statement", [])
                for stmt in stmts:
                    if stmt.get("Effect") == "Allow":
                        actions = stmt.get("Action", [])
                        if isinstance(actions, str):
                            actions = [actions]
                        wildcards = [a for a in actions if "*" in a]
                        if wildcards:
                            cmd = f"# Entity with this policy can execute: {', '.join(wildcards[:3])}"
                            return True, f"Wildcard actions found: {', '.join(wildcards[:3])}", cmd
        except ClientError:
            pass
        return None, "Could not verify policy contents", ""

    def _verify_lambda_secrets(self, finding: Dict) -> Tuple[Optional[bool], str, str]:
        fn_name = finding.get("resource", "").split(":")[-1]
        try:
            lmb = self.session.client("lambda", region_name=self.region)
            config = lmb.get_function_configuration(FunctionName=fn_name)
            env_vars = config.get("Environment", {}).get("Variables", {})
            secret_keys = [k for k in env_vars.keys() if self.SECRET_ENV_PATTERNS.search(k)]
            if secret_keys:
                cmd = (f"aws lambda get-function-configuration --function-name {fn_name} "
                       f"--query 'Environment.Variables'")
                return True, f"Secret-named env vars: {', '.join(secret_keys)}", cmd
        except ClientError:
            pass
        return None, "Could not verify Lambda environment variables", ""


# ══════════════════════════════════════════════════════════════════════════════
#  📡 CANARY TOKEN INJECTOR
#  Plants AWS honeytokens in misconfigured resources.
#  When an attacker accesses them, you get an alert with their IP/identity.
# ══════════════════════════════════════════════════════════════════════════════

class CanaryInjector:
    """
    Creates lightweight honeypot resources to detect attacker activity.

    Strategy by service:
      S3   → uploads a file named 'credentials.txt' / 'secrets.env' with
              a fake IAM key that CloudTrail will log on first GetObject
      IAM  → creates a dedicated honeypot user with console password;
              any login triggers a CloudWatch alarm
      Lambda → creates a function with a logged trigger that fires on invoke

    Each canary is logged to the SQLite DB with its token_id so you can
    check later if any were triggered.
    """

    CANARY_FILENAMES = [
        "credentials.txt",
        ".env",
        "secrets.env",
        "aws_credentials",
        "config/secrets.yml",
        "backup/db_password.txt",
    ]

    def __init__(self, session: boto3.Session, region: str, db: ScanHistoryDB):
        self.session = session
        self.region  = region
        self.db      = db

    def inject_all(self, findings: List[Dict], dry_run: bool = True) -> List[Dict]:
        """Inject canaries into misconfigured resources from findings."""
        canaries = []
        s3_findings = [f for f in findings if f.get("service") == "S3"
                       and f.get("severity") in ("CRITICAL", "HIGH")]

        print(f"\n  📡 Canary injection {'(DRY RUN)' if dry_run else ''}...")

        for f in s3_findings[:3]:   # cap at 3 S3 canaries
            c = self._inject_s3_canary(f, dry_run)
            if c:
                canaries.append(c)

        iam_critical = [f for f in findings if f.get("service") == "IAM"
                        and f.get("check_id") == "iam_root_no_mfa"]
        if iam_critical:
            c = self._inject_iam_canary(dry_run)
            if c:
                canaries.append(c)

        print(f"     → {len(canaries)} canaries {'would be' if dry_run else ''} planted")
        return canaries

    def _inject_s3_canary(self, finding: Dict, dry_run: bool) -> Optional[Dict]:
        bucket   = finding.get("resource", "").replace("arn:aws:s3:::", "").split("/")[0]
        token_id = f"canary-{_rand_id(12)}"
        filename = random.choice(self.CANARY_FILENAMES)

        # Generate a fake but realistic-looking IAM key
        fake_key    = "AKIA" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
        fake_secret = ''.join(random.choices(string.ascii_letters + string.digits + '/+', k=40))

        content = (
            f"[default]\n"
            f"aws_access_key_id = {fake_key}\n"
            f"aws_secret_access_key = {fake_secret}\n"
            f"region = {self.region}\n"
            f"# token_id: {token_id}\n"
        )

        canary = {
            "token_id":  token_id,
            "service":   "S3",
            "resource":  f"s3://{bucket}/{filename}",
            "bucket":    bucket,
            "filename":  filename,
            "fake_key":  fake_key,
            "dry_run":   dry_run,
        }

        if not dry_run:
            try:
                s3 = self.session.client("s3")
                s3.put_object(
                    Bucket=bucket,
                    Key=filename,
                    Body=content.encode(),
                    ContentType="text/plain",
                    Metadata={"canary-token": token_id},
                )
                self.db.log_canary(token_id, "S3", f"s3://{bucket}/{filename}")
                print(f"       ✓ S3 canary planted: s3://{bucket}/{filename}")
            except ClientError as e:
                print(f"       ✗ Failed to plant S3 canary: {e.response['Error']['Code']}")
                return None
        else:
            print(f"       [DRY RUN] Would plant: s3://{bucket}/{filename}")

        return canary

    def _inject_iam_canary(self, dry_run: bool) -> Optional[Dict]:
        token_id  = f"canary-iam-{_rand_id(8)}"
        user_name = f"cloudguard-honeypot-{_rand_id(6)}"

        canary = {
            "token_id":  token_id,
            "service":   "IAM",
            "resource":  f"iam::user/{user_name}",
            "user_name": user_name,
            "dry_run":   dry_run,
        }

        if not dry_run:
            try:
                iam = self.session.client("iam")
                iam.create_user(
                    UserName=user_name,
                    Tags=[
                        {"Key": "Purpose",  "Value": "SecurityHoneypot"},
                        {"Key": "TokenId",  "Value": token_id},
                        {"Key": "ManagedBy","Value": "CloudGuard"},
                    ]
                )
                # Give it a console password — login attempt = alert
                import secrets as pysec
                pw = pysec.token_urlsafe(24) + "!A1"
                iam.create_login_profile(
                    UserName=user_name, Password=pw, PasswordResetRequired=False
                )
                self.db.log_canary(token_id, "IAM", f"iam::user/{user_name}")
                print(f"       ✓ IAM honeypot user planted: {user_name}")
                canary["console_password"] = pw
            except ClientError as e:
                print(f"       ✗ Failed to plant IAM canary: {e.response['Error']['Code']}")
                return None
        else:
            print(f"       [DRY RUN] Would create IAM honeypot user: {user_name}")

        return canary

    def check_triggered(self) -> List[Dict]:
        """Check which canaries have been accessed (via CloudTrail lookup)."""
        triggered = []
        try:
            ct = self.session.client("cloudtrail", region_name=self.region)
            events = ct.lookup_events(
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "GetObject"}],
                MaxResults=50,
            ).get("Events", [])
            canaries = self.db.get_canaries()
            for event in events:
                for canary in canaries:
                    if canary["token_id"] in json.dumps(event):
                        self.db.trigger_canary(canary["token_id"])
                        triggered.append({
                            "canary":    canary,
                            "event":     event,
                            "triggered_at": event.get("EventTime", ""),
                        })
        except ClientError:
            pass
        return triggered


# ══════════════════════════════════════════════════════════════════════════════
#  🔄 AUTO-REMEDIATION ENGINE
#  Dry-run + confirm mode. Actually fixes misconfigurations via boto3.
# ══════════════════════════════════════════════════════════════════════════════

class AutoRemediator:
    """
    Applies automated fixes for findings that have a remediation_fn.
    Always runs in dry_run=True by default — pass dry_run=False to actually fix.

    Each fix method:
      1. Logs the proposed action
      2. Executes it (unless dry_run)
      3. Records the result in the SQLite remediation log
    """

    def __init__(self, session: boto3.Session, region: str, db: ScanHistoryDB):
        self.session  = session
        self.region   = region
        self.db       = db
        self._applied = 0
        self._skipped = 0
        self._failed  = 0

    def remediate_all(self, findings: List[Dict], dry_run: bool = True,
                      safe_only: bool = True) -> Dict:
        print(f"\n  🔄 Auto-Remediation Engine {'(DRY RUN — pass --remediate to apply)' if dry_run else '⚡ LIVE MODE'}")
        if safe_only:
            print(f"     (safe_only=True: skipping DISRUPTIVE remediations)")

        results = []
        for f in findings:
            check_id = f.get("check_id", "")
            ctrl     = CONTROLS.get(check_id, {})
            fn_name  = ctrl.get("remediation_fn")
            if not fn_name:
                continue
            risk = REMEDIATION_RISK.get(fn_name, "UNKNOWN")
            if safe_only and risk == "DISRUPTIVE":
                self._skipped += 1
                continue

            fn = getattr(self, fn_name, None)
            if not fn:
                continue

            try:
                action, status = fn(f, dry_run)
                results.append({"finding": f, "action": action, "status": status})
                if not dry_run:
                    self.db.log_remediation(check_id, f.get("resource",""), action, status)
                if status == "OK":
                    self._applied += 1
                else:
                    self._failed += 1
            except Exception as e:
                self._failed += 1
                results.append({"finding": f, "action": fn_name, "status": f"ERROR: {e}"})

        print(f"     → Applied: {self._applied}  Skipped: {self._skipped}  Failed: {self._failed}")
        return {"results": results, "applied": self._applied,
                "skipped": self._skipped, "failed": self._failed}

    # ── S3 fixes ─────────────────────────────────────────────────────────────

    def fix_s3_public_acl(self, f: Dict, dry_run: bool) -> Tuple[str, str]:
        bucket = f.get("resource", "").replace("arn:aws:s3:::", "").split("/")[0]
        action = f"Put PublicAccessBlock(BlockPublicAcls=True) on s3://{bucket}"
        if dry_run:
            print(f"     [DRY] {action}")
            return action, "DRY_RUN"
        s3 = self.session.client("s3")
        s3.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
            }
        )
        print(f"     ✅ {action}")
        return action, "OK"

    def fix_s3_public_policy(self, f: Dict, dry_run: bool) -> Tuple[str, str]:
        return self.fix_s3_public_acl(f, dry_run)   # same fix

    def fix_s3_encryption(self, f: Dict, dry_run: bool) -> Tuple[str, str]:
        bucket = f.get("resource", "").replace("arn:aws:s3:::", "").split("/")[0]
        action = f"Enable AES256 SSE on s3://{bucket}"
        if dry_run:
            print(f"     [DRY] {action}")
            return action, "DRY_RUN"
        s3 = self.session.client("s3")
        s3.put_bucket_encryption(
            Bucket=bucket,
            ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        )
        print(f"     ✅ {action}")
        return action, "OK"

    def fix_s3_versioning(self, f: Dict, dry_run: bool) -> Tuple[str, str]:
        bucket = f.get("resource", "").replace("arn:aws:s3:::", "").split("/")[0]
        action = f"Enable versioning on s3://{bucket}"
        if dry_run:
            print(f"     [DRY] {action}")
            return action, "DRY_RUN"
        s3 = self.session.client("s3")
        s3.put_bucket_versioning(
            Bucket=bucket, VersioningConfiguration={"Status": "Enabled"}
        )
        print(f"     ✅ {action}")
        return action, "OK"

    def fix_s3_logging(self, f: Dict, dry_run: bool) -> Tuple[str, str]:
        bucket = f.get("resource", "").replace("arn:aws:s3:::", "").split("/")[0]
        log_bucket = f"{bucket}-access-logs"
        action = f"Enable access logging on s3://{bucket} → s3://{log_bucket}"
        if dry_run:
            print(f"     [DRY] {action}")
            return action, "DRY_RUN"
        s3 = self.session.client("s3")
        # Ensure log bucket exists
        try:
            s3.head_bucket(Bucket=log_bucket)
        except ClientError:
            s3.create_bucket(Bucket=log_bucket)
        s3.put_bucket_logging(
            Bucket=bucket,
            BucketLoggingStatus={
                "LoggingEnabled": {"TargetBucket": log_bucket, "TargetPrefix": f"{bucket}/"}
            }
        )
        print(f"     ✅ {action}")
        return action, "OK"

    def fix_s3_mfa_delete(self, f: Dict, dry_run: bool) -> Tuple[str, str]:
        bucket = f.get("resource", "").replace("arn:aws:s3:::", "").split("/")[0]
        action = f"Enable MFA Delete on s3://{bucket} (requires root credentials)"
        print(f"     ⚠️  {action}  — cannot automate, requires root session")
        return action, "MANUAL_REQUIRED"

    # ── IAM fixes ────────────────────────────────────────────────────────────

    def fix_iam_password_policy(self, f: Dict, dry_run: bool) -> Tuple[str, str]:
        action = "Enforce strong IAM password policy (min 14 chars, symbols, rotation 90d)"
        if dry_run:
            print(f"     [DRY] {action}")
            return action, "DRY_RUN"
        iam = self.session.client("iam")
        iam.update_account_password_policy(
            MinimumPasswordLength=14,
            RequireSymbols=True,
            RequireNumbers=True,
            RequireUppercaseCharacters=True,
            RequireLowercaseCharacters=True,
            MaxPasswordAge=90,
            PasswordReusePrevention=24,
            HardExpiry=False,
        )
        print(f"     ✅ {action}")
        return action, "OK"

    def fix_iam_stale_credentials(self, f: Dict, dry_run: bool) -> Tuple[str, str]:
        user = f.get("resource", "").split("/")[-1]
        action = f"Disable console login for stale user: {user}"
        if dry_run:
            print(f"     [DRY] {action}")
            return action, "DRY_RUN"
        iam = self.session.client("iam")
        try:
            iam.delete_login_profile(UserName=user)
        except ClientError:
            pass
        print(f"     ✅ {action}")
        return action, "OK"

    def fix_iam_stale_access_key(self, f: Dict, dry_run: bool) -> Tuple[str, str]:
        resource = f.get("resource", "")
        # resource format: iam::user/username::key/AKIAXXXXXXXX
        parts = resource.split("::")
        user = parts[1].replace("user/", "") if len(parts) > 1 else resource.split("/")[-1]
        action = f"Deactivate stale access keys for IAM user: {user}"
        if dry_run:
            print(f"     [DRY] {action}")
            return action, "DRY_RUN"
        iam = self.session.client("iam")
        keys = iam.list_access_keys(UserName=user).get("AccessKeyMetadata", [])
        ninety_days_ago = datetime.now(timezone.utc) - timedelta(days=90)
        for k in keys:
            created = k.get("CreateDate")
            if created and created < ninety_days_ago:
                iam.update_access_key(
                    UserName=user, AccessKeyId=k["AccessKeyId"], Status="Inactive"
                )
                print(f"     ✅ Deactivated key {k['AccessKeyId']} for {user}")
        return action, "OK"

    def fix_iam_admin_policy(self, f: Dict, dry_run: bool) -> Tuple[str, str]:
        entity = f.get("resource", "").split("/")[-1]
        action = f"Detach AdministratorAccess from {entity} (review manually)"
        print(f"     ⚠️  {action}  — marking as REVIEW_REQUIRED to avoid lockout")
        return action, "REVIEW_REQUIRED"

    # ── EC2 fixes ────────────────────────────────────────────────────────────

    def fix_ec2_sg_port(self, f: Dict, dry_run: bool) -> Tuple[str, str]:
        sg_id = f.get("resource", "")
        check = f.get("check_id", "")
        port_map = {
            "ec2_ssh_open":       22,
            "ec2_rdp_open":       3389,
            "ec2_db_port_open":   None,
            "ec2_all_ports_open": None,
        }
        port = port_map.get(check, None)
        action = (f"Revoke 0.0.0.0/0 ingress on port {port if port else 'all'} "
                  f"in SG {sg_id}")
        if dry_run:
            print(f"     [DRY] {action}")
            return action, "DRY_RUN"
        ec2 = self.session.client("ec2", region_name=self.region)
        try:
            sgs = ec2.describe_security_groups(GroupIds=[sg_id]).get("SecurityGroups", [])
            for sg in sgs:
                for rule in sg.get("IpPermissions", []):
                    from_p = rule.get("FromPort", 0)
                    to_p   = rule.get("ToPort", 65535)
                    if port is None or from_p <= port <= to_p:
                        cidr_open = [r for r in rule.get("IpRanges", [])
                                     if r.get("CidrIp") == "0.0.0.0/0"]
                        if cidr_open:
                            revoke_rule = {k: v for k, v in rule.items()}
                            revoke_rule["IpRanges"] = cidr_open
                            ec2.revoke_security_group_ingress(
                                GroupId=sg_id, IpPermissions=[revoke_rule]
                            )
                            print(f"     ✅ {action}")
        except ClientError as e:
            return action, f"FAILED: {e.response['Error']['Code']}"
        return action, "OK"

    def fix_ec2_imdsv2(self, f: Dict, dry_run: bool) -> Tuple[str, str]:
        instance_id = f.get("resource", "")
        action = f"Enforce IMDSv2 (HttpTokens=required) on {instance_id}"
        if dry_run:
            print(f"     [DRY] {action}")
            return action, "DRY_RUN"
        ec2 = self.session.client("ec2", region_name=self.region)
        ec2.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens="required",
            HttpPutResponseHopLimit=1,
        )
        print(f"     ✅ {action}")
        return action, "OK"

    def fix_ec2_snapshot_visibility(self, f: Dict, dry_run: bool) -> Tuple[str, str]:
        snap_id = f.get("resource", "")
        action  = f"Remove public createVolumePermission from snapshot {snap_id}"
        if dry_run:
            print(f"     [DRY] {action}")
            return action, "DRY_RUN"
        ec2 = self.session.client("ec2", region_name=self.region)
        ec2.modify_snapshot_attribute(
            SnapshotId=snap_id,
            Attribute="createVolumePermission",
            OperationType="remove",
            GroupNames=["all"],
        )
        print(f"     ✅ {action}")
        return action, "OK"

    # ── RDS fixes ────────────────────────────────────────────────────────────

    def fix_rds_public_access(self, f: Dict, dry_run: bool) -> Tuple[str, str]:
        db_id  = f.get("resource", "").split(":")[-1]
        action = f"Disable PubliclyAccessible on RDS instance {db_id}"
        if dry_run:
            print(f"     [DRY] {action}")
            return action, "DRY_RUN"
        rds = self.session.client("rds", region_name=self.region)
        rds.modify_db_instance(
            DBInstanceIdentifier=db_id,
            PubliclyAccessible=False,
            ApplyImmediately=True,
        )
        print(f"     ✅ {action}")
        return action, "OK"

    def fix_rds_backup(self, f: Dict, dry_run: bool) -> Tuple[str, str]:
        db_id  = f.get("resource", "").split(":")[-1]
        action = f"Enable 7-day automated backup on RDS instance {db_id}"
        if dry_run:
            print(f"     [DRY] {action}")
            return action, "DRY_RUN"
        rds = self.session.client("rds", region_name=self.region)
        rds.modify_db_instance(
            DBInstanceIdentifier=db_id,
            BackupRetentionPeriod=7,
            ApplyImmediately=False,
        )
        print(f"     ✅ {action}")
        return action, "OK"

    def fix_rds_deletion_protection(self, f: Dict, dry_run: bool) -> Tuple[str, str]:
        db_id  = f.get("resource", "").split(":")[-1]
        action = f"Enable DeletionProtection on RDS instance {db_id}"
        if dry_run:
            print(f"     [DRY] {action}")
            return action, "DRY_RUN"
        rds = self.session.client("rds", region_name=self.region)
        rds.modify_db_instance(
            DBInstanceIdentifier=db_id,
            DeletionProtection=True,
            ApplyImmediately=True,
        )
        print(f"     ✅ {action}")
        return action, "OK"

    # ── CloudTrail fixes ─────────────────────────────────────────────────────

    def fix_cloudtrail_enable(self, f: Dict, dry_run: bool) -> Tuple[str, str]:
        trail = f.get("resource", "").split("/")[-1]
        action = f"Start logging on CloudTrail: {trail}"
        if dry_run:
            print(f"     [DRY] {action}")
            return action, "DRY_RUN"
        ct = self.session.client("cloudtrail", region_name=self.region)
        ct.start_logging(Name=trail)
        print(f"     ✅ {action}")
        return action, "OK"

    def fix_cloudtrail_validation(self, f: Dict, dry_run: bool) -> Tuple[str, str]:
        trail  = f.get("resource", "").split("/")[-1]
        action = f"Enable log file validation on CloudTrail: {trail}"
        if dry_run:
            print(f"     [DRY] {action}")
            return action, "DRY_RUN"
        ct = self.session.client("cloudtrail", region_name=self.region)
        ct.update_trail(Name=trail, EnableLogFileValidation=True)
        print(f"     ✅ {action}")
        return action, "OK"

    # ── KMS fixes ────────────────────────────────────────────────────────────

    def fix_kms_rotation(self, f: Dict, dry_run: bool) -> Tuple[str, str]:
        key_id = f.get("resource", "").split("/")[-1]
        action = f"Enable annual key rotation on KMS key {key_id}"
        if dry_run:
            print(f"     [DRY] {action}")
            return action, "DRY_RUN"
        kms = self.session.client("kms", region_name=self.region)
        kms.enable_key_rotation(KeyId=key_id)
        print(f"     ✅ {action}")
        return action, "OK"


# ══════════════════════════════════════════════════════════════════════════════
#  📊 SCAN DIFF ENGINE
#  Git-style delta between two scan reports.
# ══════════════════════════════════════════════════════════════════════════════

class ScanDiffEngine:
    """
    Produces a structured diff between two scan reports:
      + NEW findings (appeared in new scan, not in old)
      - FIXED findings (in old scan, gone in new)
      ~ CHANGED findings (same resource, different severity/score)
      = PERSISTENT findings (unchanged across both scans)

    Also produces:
      - Score delta
      - Regression / improvement summary
      - Most-improved / most-regressed services
    """

    def diff(self, old: Dict, new: Dict) -> Dict:
        old_finds = {self._key(f): f for f in old.get("findings", [])}
        new_finds = {self._key(f): f for f in new.get("findings", [])}

        added      = []
        fixed      = []
        changed    = []
        persistent = []

        for k, f in new_finds.items():
            if k not in old_finds:
                added.append({**f, "status": "NEW"})
            elif old_finds[k].get("severity") != f.get("severity"):
                changed.append({
                    "finding":      f,
                    "old_severity": old_finds[k].get("severity"),
                    "new_severity": f.get("severity"),
                    "regressed":    self._sev_rank(f.get("severity","LOW")) >
                                    self._sev_rank(old_finds[k].get("severity","LOW")),
                    "status": "CHANGED",
                })
            else:
                persistent.append({**f, "status": "PERSISTENT"})

        for k, f in old_finds.items():
            if k not in new_finds:
                fixed.append({**f, "status": "FIXED"})

        old_score = old.get("summary", {}).get("compliance_score", 0)
        new_score = new.get("summary", {}).get("compliance_score", 0)
        delta     = round(new_score - old_score, 1)

        # Per-service breakdown
        svc_old = defaultdict(int)
        svc_new = defaultdict(int)
        for f in old.get("findings", []):
            svc_old[f.get("service","?")] += 1
        for f in new.get("findings", []):
            svc_new[f.get("service","?")] += 1

        svc_delta = {
            svc: svc_new.get(svc, 0) - svc_old.get(svc, 0)
            for svc in set(list(svc_old.keys()) + list(svc_new.keys()))
        }

        return {
            "old_scan_time":  old.get("scan_time", ""),
            "new_scan_time":  new.get("scan_time", ""),
            "score_delta":    delta,
            "score_old":      old_score,
            "score_new":      new_score,
            "trend":          "IMPROVING" if delta > 0 else "REGRESSING" if delta < 0 else "FLAT",
            "added":          added,
            "fixed":          fixed,
            "changed":        changed,
            "persistent":     persistent,
            "summary": {
                "new_findings":        len(added),
                "fixed_findings":      len(fixed),
                "changed_findings":    len(changed),
                "persistent_findings": len(persistent),
                "regressions":         sum(1 for c in changed if c.get("regressed")),
                "improvements":        sum(1 for c in changed if not c.get("regressed")),
            },
            "service_deltas": svc_delta,
            "most_improved_service":  min(svc_delta, key=svc_delta.get) if svc_delta else None,
            "most_regressed_service": max(svc_delta, key=svc_delta.get) if svc_delta else None,
        }

    def _key(self, f: Dict) -> str:
        return f"{f.get('check_id','')}-{f.get('resource','')}"

    def _sev_rank(self, sev: str) -> int:
        return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(sev, 0)

    def print_diff(self, diff: Dict):
        d = diff
        print(f"\n{'═'*70}")
        print(f"  📊 SCAN DIFF:  {d['old_scan_time'][:19]}  →  {d['new_scan_time'][:19]}")
        print(f"{'═'*70}")
        trend_sym = "📈" if d["trend"]=="IMPROVING" else "📉" if d["trend"]=="REGRESSING" else "➡️"
        score_str = (f"+{d['score_delta']}" if d["score_delta"] > 0 else str(d["score_delta"]))
        print(f"  Compliance Score: {d['score_old']}% → {d['score_new']}%  ({score_str})  {trend_sym}")

        s = d["summary"]
        print(f"\n  {green('+')} {s['new_findings']} NEW findings")
        print(f"  {red('-')} {s['fixed_findings']} FIXED findings")
        print(f"  {'~'} {s['changed_findings']} CHANGED findings  "
              f"({s['regressions']} regressions / {s['improvements']} improvements)")
        print(f"  {'='} {s['persistent_findings']} persistent findings")

        if d.get("added"):
            print(f"\n  {green('NEW FINDINGS')}:")
            for f in d["added"][:10]:
                print(f"    + [{f['severity']:8}] {f['service']:12} {f['resource'][:40]}")

        if d.get("fixed"):
            print(f"\n  {red('FIXED FINDINGS')}:")
            for f in d["fixed"][:10]:
                print(f"    - [{f['severity']:8}] {f['service']:12} {f['resource'][:40]}")

        if d.get("changed"):
            print(f"\n  CHANGED FINDINGS:")
            for c in d["changed"][:10]:
                direction = "⬆️ REGRESSED" if c.get("regressed") else "⬇️ improved"
                print(f"    ~ [{c['old_severity']} → {c['new_severity']}] {direction}  "
                      f"{c['finding']['resource'][:40]}")

        sd = d.get("service_deltas", {})
        if sd:
            print(f"\n  SERVICE BREAKDOWN (delta):")
            for svc, delta in sorted(sd.items(), key=lambda x: x[1]):
                sym = green(f"+{delta}") if delta < 0 else (red(f"+{delta}") if delta > 0 else "  0")
                print(f"    {svc:15} {sym}")
        print()


# ══════════════════════════════════════════════════════════════════════════════
#  🌐 CROSS-ACCOUNT PIVOT MAPPER
#  Traces trust relationships across your entire AWS Organization.
#  Finds paths where compromising account A lets you move to account B.
# ══════════════════════════════════════════════════════════════════════════════

class CrossAccountPivotMapper:
    """
    For each account in the AWS Org, enumerates:
      - IAM roles with cross-account trust
      - S3 bucket policies granting cross-account access
      - KMS key policies granting cross-account decrypt
      - SNS/SQS policies with cross-account principal

    Builds a directed graph: nodes = accounts, edges = trust paths.
    Outputs "if you compromise account X, you can pivot to account Y via Z".
    """

    def __init__(self, master_session: boto3.Session, region: str):
        self.master_session = master_session
        self.region         = region
        self.account_graph  = nx.DiGraph() if HAS_NETWORKX else None

    def map(self, accounts: List[Dict], role_name: str = "SecurityScannerRole",
            stealth: bool = False) -> Dict:
        print(f"\n  🌐 Cross-account pivot mapping across {len(accounts)} accounts...")

        pivot_edges = []
        account_ids = [a["Id"] for a in accounts]

        for acct in accounts:
            acct_id  = acct["Id"]
            acct_name = acct.get("Name", acct_id)
            try:
                sts       = self.master_session.client("sts")
                assumed   = sts.assume_role(
                    RoleArn=f"arn:aws:iam::{acct_id}:role/{role_name}",
                    RoleSessionName="CloudGuardPivotScan",
                )
                creds     = assumed["Credentials"]
                session   = boto3.Session(
                    aws_access_key_id=creds["AccessKeyId"],
                    aws_secret_access_key=creds["SecretAccessKey"],
                    aws_session_token=creds["SessionToken"],
                    region_name=self.region,
                )
                _stealth_sleep(stealth)

                # Check IAM cross-account trusts
                pivots = self._check_iam_trusts(session, acct_id, account_ids, acct_name)
                pivot_edges.extend(pivots)

                # Check S3 cross-account policies
                pivots = self._check_s3_cross_account(session, acct_id, account_ids, acct_name)
                pivot_edges.extend(pivots)

            except ClientError as e:
                print(f"     ✗ Cannot assume role in {acct_name}: {e.response['Error']['Code']}")

        # Build graph
        graph_nodes = [{"id": a["Id"], "name": a.get("Name", a["Id"])} for a in accounts]

        if self.account_graph:
            for edge in pivot_edges:
                self.account_graph.add_edge(
                    edge["from_account"], edge["to_account"],
                    pivot_type=edge["pivot_type"],
                )

        # Find most dangerous pivots (critical compromise chains)
        chains = []
        if self.account_graph and HAS_NETWORKX:
            for src in self.account_graph.nodes():
                for dst in self.account_graph.nodes():
                    if src != dst:
                        try:
                            paths = list(nx.all_simple_paths(
                                self.account_graph, src, dst, cutoff=4
                            ))
                            chains.extend(paths)
                        except Exception:
                            pass

        print(f"     → {len(pivot_edges)} cross-account pivot paths found")
        print(f"     → {len(chains)} compromise chains identified")

        return {
            "accounts":      graph_nodes,
            "pivot_edges":   pivot_edges,
            "chains":        [{"path": c, "hops": len(c)-1} for c in chains[:20]],
            "most_connected": self._most_connected(),
        }

    def _check_iam_trusts(self, session: boto3.Session, from_acct: str,
                          all_accounts: List[str], acct_name: str) -> List[Dict]:
        pivots = []
        try:
            iam   = session.client("iam")
            roles = iam.list_roles(MaxItems=100).get("Roles", [])
            for role in roles:
                doc   = role.get("AssumeRolePolicyDocument", {})
                stmts = doc.get("Statement", [])
                for stmt in stmts:
                    if stmt.get("Effect") != "Allow":
                        continue
                    principal = stmt.get("Principal", {})
                    if isinstance(principal, dict):
                        aws_p = principal.get("AWS", [])
                        if isinstance(aws_p, str):
                            aws_p = [aws_p]
                        for p in aws_p:
                            for other_acct in all_accounts:
                                if other_acct in p and other_acct != from_acct:
                                    pivots.append({
                                        "from_account": other_acct,
                                        "to_account":   from_acct,
                                        "pivot_type":   "IAM_ROLE_TRUST",
                                        "resource":     role["Arn"],
                                        "description":  (
                                            f"Account {other_acct} can assume "
                                            f"{role['RoleName']} in {acct_name}"
                                        ),
                                    })
        except ClientError:
            pass
        return pivots

    def _check_s3_cross_account(self, session: boto3.Session, from_acct: str,
                                 all_accounts: List[str], acct_name: str) -> List[Dict]:
        pivots = []
        try:
            s3      = session.client("s3")
            buckets = s3.list_buckets().get("Buckets", [])
            for b in buckets[:20]:   # cap to avoid throttling
                bname = b["Name"]
                try:
                    pol = s3.get_bucket_policy(Bucket=bname).get("Policy", "{}")
                    doc = json.loads(pol)
                    for stmt in doc.get("Statement", []):
                        if stmt.get("Effect") != "Allow":
                            continue
                        principal = stmt.get("Principal", {})
                        if isinstance(principal, dict):
                            aws_p = principal.get("AWS", [])
                        elif isinstance(principal, str) and principal == "*":
                            aws_p = ["*"]
                        else:
                            aws_p = []
                        if isinstance(aws_p, str):
                            aws_p = [aws_p]
                        for p in aws_p:
                            for other_acct in all_accounts:
                                if other_acct in p and other_acct != from_acct:
                                    pivots.append({
                                        "from_account": other_acct,
                                        "to_account":   from_acct,
                                        "pivot_type":   "S3_BUCKET_POLICY",
                                        "resource":     f"arn:aws:s3:::{bname}",
                                        "description":  (
                                            f"Account {other_acct} can access "
                                            f"s3://{bname} in {acct_name}"
                                        ),
                                    })
                except ClientError:
                    pass
        except ClientError:
            pass
        return pivots

    def _most_connected(self) -> Optional[str]:
        if not self.account_graph or not self.account_graph.nodes():
            return None
        return max(self.account_graph.nodes(),
                   key=lambda n: self.account_graph.degree(n),
                   default=None)


# ══════════════════════════════════════════════════════════════════════════════
#  CORE SECURITY SCANNER  (expanded from v2.0)
# ══════════════════════════════════════════════════════════════════════════════

class SecurityScanner:
    def __init__(self, session: boto3.Session, region: str = "us-east-1",
                 services: Optional[List[str]] = None, stealth: bool = False):
        self.session  = session
        self.region   = region
        self.services = services or ["s3","iam","ec2","rds","cloudtrail","vpc",
                                     "lambda","sns","sqs","kms"]
        self.stealth  = stealth
        self.findings: List[Dict] = []
        self._ttb = TimeToBreach()

        # Get account info
        try:
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            self.account_id = identity.get("Account", "unknown")
        except Exception:
            self.account_id = "unknown"

    def _find(self, check_id: str, service: str, resource: str,
              message: str, extra: Optional[Dict] = None, age_days: int = 0) -> Dict:
        ctrl = CONTROLS.get(check_id, {})
        sev  = ctrl.get("severity", "MEDIUM")
        cvss = ctrl.get("cvss", 5.0)
        public = any(k in message.lower() for k in ["public","0.0.0.0","::/0"])
        rs   = _risk_score(sev, cvss, public, age_days)
        ttb  = self._ttb.estimate({
            "check_id": check_id, "severity": sev, "message": message,
            "age_days": age_days,
        })
        f = {
            "check_id":   check_id,
            "service":    service,
            "resource":   resource,
            "severity":   sev,
            "message":    message,
            "risk_score": rs,
            "cis":        ctrl.get("cis", "—"),
            "nist":       ctrl.get("nist", "—"),
            "pci":        ctrl.get("pci", "—"),
            "mitre":      ctrl.get("mitre", "—"),
            "mitre_name": ctrl.get("mitre_name", ""),
            "cvss":       cvss,
            "ttb_days":   ttb["estimated_days"],
            "ttb_urgency":ttb["urgency"],
            "remediation_fn": ctrl.get("remediation_fn"),
            "age_days":   age_days,
        }
        if extra:
            f.update(extra)
        return f

    def run(self) -> Dict:
        scan_time = _ts()
        print(f"\n{'═'*70}")
        print(f"  CloudGuard ULTRA  v4.0  —  Account: {self.account_id}  "
              f"Region: {self.region}")
        if self.stealth:
            print(f"  {cyan('🔇 LOW-NOISE MODE ACTIVE')}  (rate-limited, inter-request delays)")
        print(f"{'═'*70}\n")

        dispatch = {
            "s3":         self._scan_s3,
            "iam":        self._scan_iam,
            "ec2":        self._scan_ec2,
            "rds":        self._scan_rds,
            "cloudtrail": self._scan_cloudtrail,
            "vpc":        self._scan_vpc,
            "lambda":     self._scan_lambda,
            "sns":        self._scan_sns,
            "sqs":        self._scan_sqs,
            "kms":        self._scan_kms,
        }

        if self.stealth:
            # Sequential scan with inter-request delays in low-noise mode
            for svc in self.services:
                fn = dispatch.get(svc)
                if fn:
                    fn()
                    _low_noise_sleep(True)
        else:
            # Parallel scan — one thread per service
            with ThreadPoolExecutor(max_workers=len(self.services)) as ex:
                futures = {ex.submit(dispatch[svc]): svc
                           for svc in self.services if svc in dispatch}
                for fut in as_completed(futures):
                    svc = futures[fut]
                    try:
                        fut.result()
                    except Exception as e:
                        print(f"  ✗ {svc} scan error: {e}")

        self.findings.sort(key=lambda x: (-x["risk_score"], x["severity"]))
        return self._build_report(scan_time)

    @classmethod
    def scan_region(cls, session: boto3.Session, region: str,
                    services: List[str], stealth: bool) -> Dict:
        """Scan a single region — callable from ThreadPoolExecutor."""
        scanner = cls(session, region=region, services=services, stealth=stealth)
        return scanner.run()

    @classmethod
    def run_all_regions(cls, session: boto3.Session, services: List[str],
                        stealth: bool = False) -> Dict[str, Dict]:
        """
        Multi-Region Parallel Scan — discovers all enabled regions via EC2
        describe_regions, then fans out with ThreadPoolExecutor.

        Returns: {region_name: report_dict}
        """
        print(f"\n  🌍 Multi-region mode: discovering enabled regions...")
        try:
            ec2   = session.client("ec2", region_name="us-east-1",
                                   config=BOTO_RETRY_CONFIG)
            pages = _paginate(ec2, "describe_regions", "Regions",
                              Filters=[{"Name": "opt-in-status",
                                        "Values": ["opted-in", "opt-in-not-required"]}])
            regions = [r["RegionName"] for r in pages]
        except ClientError:
            regions = ["us-east-1"]

        print(f"     → Scanning {len(regions)} regions in parallel: "
              f"{', '.join(regions)}")

        results: Dict[str, Dict] = {}
        lock = threading.Lock()

        def _scan(region: str) -> None:
            try:
                report = cls.scan_region(session, region, services, stealth)
                with lock:
                    results[region] = report
            except Exception as e:
                with lock:
                    results[region] = {"error": str(e), "region": region,
                                       "findings": [], "summary": {}}

        # Cap workers at 5 to avoid rate-limit hammering
        with ThreadPoolExecutor(max_workers=min(5, len(regions))) as ex:
            list(ex.map(_scan, regions))

        print(f"  ✓ Multi-region scan complete: "
              f"{sum(1 for v in results.values() if 'error' not in v)} "
              f"regions succeeded")
        return results

    # ── S3 ───────────────────────────────────────────────────────────────────

    def _scan_s3(self):
        print("  [S3] Scanning...")
        _stealth_sleep(self.stealth)
        try:
            s3 = self.session.client("s3")
            buckets = s3.list_buckets().get("Buckets", [])
        except ClientError as e:
            print(f"  ✗ S3: {e.response['Error']['Code']}")
            return

        def _check_bucket(b):
            name = b["Name"]
            arn  = f"arn:aws:s3:::{name}"
            created = b.get("CreationDate")
            age_days = (datetime.now(timezone.utc) - created).days if created else 0

            _stealth_sleep(self.stealth)

            # Public ACL
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    if grantee.get("URI", "").endswith("AllUsers"):
                        self.findings.append(self._find(
                            "s3_public_acl", "S3", arn,
                            f"Bucket '{name}' has public ACL grant to AllUsers",
                            age_days=age_days,
                        ))
            except ClientError:
                pass

            # Public policy + block config
            try:
                pab = s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})
                if not pab.get("BlockPublicPolicy"):
                    try:
                        policy = json.loads(s3.get_bucket_policy(Bucket=name).get("Policy", "{}"))
                        for stmt in policy.get("Statement", []):
                            if stmt.get("Effect") == "Allow":
                                principal = stmt.get("Principal", "")
                                if principal == "*" or (isinstance(principal, dict) and
                                   principal.get("AWS") == "*"):
                                    self.findings.append(self._find(
                                        "s3_public_policy", "S3", arn,
                                        f"Bucket '{name}' policy grants public access (*)",
                                        age_days=age_days,
                                    ))
                    except ClientError:
                        pass
            except ClientError:
                pass

            # Encryption
            try:
                s3.get_bucket_encryption(Bucket=name)
            except ClientError:
                self.findings.append(self._find(
                    "s3_no_encryption", "S3", arn,
                    f"Bucket '{name}' has no server-side encryption",
                    age_days=age_days,
                ))

            # Versioning
            try:
                ver = s3.get_bucket_versioning(Bucket=name)
                status = ver.get("Status", "")
                mfa    = ver.get("MFADelete", "Disabled")
                if status != "Enabled":
                    self.findings.append(self._find(
                        "s3_no_versioning", "S3", arn,
                        f"Bucket '{name}' versioning is {status or 'Disabled'}",
                        age_days=age_days,
                    ))
                elif mfa != "Enabled":
                    self.findings.append(self._find(
                        "s3_no_mfa_delete", "S3", arn,
                        f"Bucket '{name}' versioning enabled but MFA Delete is off",
                        age_days=age_days,
                    ))
            except ClientError:
                pass

            # Logging
            try:
                logging_cfg = s3.get_bucket_logging(Bucket=name)
                if not logging_cfg.get("LoggingEnabled"):
                    self.findings.append(self._find(
                        "s3_no_logging", "S3", arn,
                        f"Bucket '{name}' has no access logging enabled",
                        age_days=age_days,
                    ))
            except ClientError:
                pass

        with ThreadPoolExecutor(max_workers=4) as ex:
            list(ex.map(_check_bucket, buckets))

        print(f"  ✓ S3: {len(buckets)} buckets scanned")

    # ── IAM ──────────────────────────────────────────────────────────────────

    def _scan_iam(self):
        print("  [IAM] Scanning...")
        _stealth_sleep(self.stealth)
        try:
            iam = self.session.client("iam")
        except ClientError:
            return

        # Root account checks
        try:
            summary = iam.get_account_summary().get("SummaryMap", {})
            if summary.get("AccountMFAEnabled", 0) == 0:
                self.findings.append(self._find(
                    "iam_root_no_mfa", "IAM", "arn:aws:iam::root",
                    "Root account does not have MFA enabled",
                ))
            if summary.get("AccountAccessKeysPresent", 0) > 0:
                self.findings.append(self._find(
                    "iam_root_access_keys", "IAM", "arn:aws:iam::root",
                    "Root account has active access keys",
                ))
        except ClientError:
            pass

        # Password policy
        try:
            pol = iam.get_account_password_policy().get("PasswordPolicy", {})
            if (pol.get("MinimumPasswordLength", 0) < 14 or
                    not pol.get("RequireSymbols") or
                    not pol.get("RequireNumbers") or
                    pol.get("MaxPasswordAge", 999) > 90):
                self.findings.append(self._find(
                    "iam_weak_password_policy", "IAM", "arn:aws:iam::password-policy",
                    "IAM password policy does not meet minimum security standards",
                ))
        except ClientError:
            self.findings.append(self._find(
                "iam_weak_password_policy", "IAM", "arn:aws:iam::password-policy",
                "No IAM password policy configured",
            ))

        # Users
        try:
            users = _paginate(iam, "list_users", "Users")
            ninety_days_ago = datetime.now(timezone.utc) - timedelta(days=90)

            for user in users:
                uname = user["UserName"]
                u_arn = user["Arn"]
                created = user.get("CreateDate", datetime.now(timezone.utc))
                age_days = (datetime.now(timezone.utc) - created).days

                # MFA check for console users
                try:
                    login = iam.get_login_profile(UserName=uname)
                    mfa_devices = iam.list_mfa_devices(UserName=uname).get("MFADevices", [])
                    if not mfa_devices:
                        self.findings.append(self._find(
                            "iam_user_no_mfa", "IAM", u_arn,
                            f"Console user '{uname}' has no MFA device",
                            age_days=age_days,
                        ))
                except ClientError:
                    pass

                # Stale credentials
                last_used = user.get("PasswordLastUsed")
                if last_used and last_used < ninety_days_ago and age_days > 90:
                    self.findings.append(self._find(
                        "iam_stale_credentials", "IAM", u_arn,
                        f"User '{uname}' has not logged in for {age_days} days",
                        age_days=age_days,
                    ))

                # Access keys
                try:
                    keys = iam.list_access_keys(UserName=uname).get("AccessKeyMetadata", [])
                    for k in keys:
                        if k.get("Status") == "Active":
                            key_created = k.get("CreateDate", datetime.now(timezone.utc))
                            key_age     = (datetime.now(timezone.utc) - key_created).days
                            if key_age > 90:
                                self.findings.append(self._find(
                                    "iam_stale_access_key", "IAM",
                                    f"{u_arn}::key/{k['AccessKeyId']}",
                                    f"Access key {k['AccessKeyId']} for '{uname}' "
                                    f"is {key_age} days old",
                                    age_days=key_age,
                                ))
                except ClientError:
                    pass

                # Attached policies
                try:
                    attached = iam.list_attached_user_policies(UserName=uname).get("AttachedPolicies", [])
                    for pol in attached:
                        if pol.get("PolicyName") == "AdministratorAccess":
                            self.findings.append(self._find(
                                "iam_admin_policy", "IAM", u_arn,
                                f"User '{uname}' has AdministratorAccess policy attached",
                                age_days=age_days,
                            ))
                except ClientError:
                    pass
        except ClientError:
            pass

        # Managed policies — wildcard actions and iam:PassRole
        try:
            paginator = iam.get_paginator("list_policies")
            for page in paginator.paginate(Scope="Local", OnlyAttached=True):
                for pol in page.get("Policies", []):
                    pol_arn = pol["Arn"]
                    try:
                        ver_id = pol["DefaultVersionId"]
                        doc    = iam.get_policy_version(
                            PolicyArn=pol_arn, VersionId=ver_id
                        ).get("PolicyVersion", {}).get("Document", {})
                        for stmt in doc.get("Statement", []):
                            if stmt.get("Effect") != "Allow":
                                continue
                            actions = stmt.get("Action", [])
                            if isinstance(actions, str):
                                actions = [actions]
                            if any("*" in a for a in actions):
                                self.findings.append(self._find(
                                    "iam_wildcard_action_policy", "IAM", pol_arn,
                                    f"Policy '{pol['PolicyName']}' allows wildcard actions",
                                ))
                            if "iam:PassRole" in actions or "iam:*" in actions:
                                self.findings.append(self._find(
                                    "iam_pass_role_escalation", "IAM", pol_arn,
                                    f"Policy '{pol['PolicyName']}' allows iam:PassRole — "
                                    f"potential privilege escalation",
                                ))
                    except ClientError:
                        pass
        except ClientError:
            pass

        print(f"  ✓ IAM: scan complete")

    # ── EC2 ──────────────────────────────────────────────────────────────────

    def _scan_ec2(self):
        print("  [EC2] Scanning...")
        _stealth_sleep(self.stealth)
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
        except ClientError:
            return

        DB_PORTS = {1433, 1521, 3306, 5432, 5433, 27017, 6379, 9200, 9300}

        # Security groups
        try:
            sgs = _paginate(ec2, "describe_security_groups", "SecurityGroups")
            for sg in sgs:
                sg_id   = sg["GroupId"]
                sg_name = sg.get("GroupName", "")

                # Default SG in use
                if sg_name == "default":
                    assoc = ec2.describe_network_interfaces(
                        Filters=[{"Name": "group-id", "Values": [sg_id]}]
                    ).get("NetworkInterfaces", [])
                    if assoc:
                        self.findings.append(self._find(
                            "ec2_default_sg_in_use", "EC2", sg_id,
                            f"Default security group '{sg_id}' is in use by "
                            f"{len(assoc)} network interface(s)",
                        ))

                for rule in sg.get("IpPermissions", []):
                    from_p = rule.get("FromPort", 0)
                    to_p   = rule.get("ToPort", 65535)
                    proto  = rule.get("IpProtocol", "-1")

                    open_to_world = any(
                        r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", [])
                    ) or any(
                        r.get("CidrIpv6") == "::/0" for r in rule.get("Ipv6Ranges", [])
                    )

                    if not open_to_world:
                        continue

                    if proto == "-1":
                        self.findings.append(self._find(
                            "ec2_all_ports_open", "EC2", sg_id,
                            f"Security group '{sg_id}' allows ALL traffic from 0.0.0.0/0",
                        ))
                        continue

                    for port, check in [(22, "ec2_ssh_open"), (3389, "ec2_rdp_open")]:
                        if from_p <= port <= to_p:
                            self.findings.append(self._find(
                                check, "EC2", sg_id,
                                f"Security group '{sg_id}' allows port {port} from 0.0.0.0/0",
                            ))

                    for db_port in DB_PORTS:
                        if from_p <= db_port <= to_p:
                            self.findings.append(self._find(
                                "ec2_db_port_open", "EC2", sg_id,
                                f"Security group '{sg_id}' exposes DB port {db_port} "
                                f"to 0.0.0.0/0",
                            ))
                            break
        except ClientError:
            pass

        # IMDSv1 and EBS encryption per instance
        try:
            reservations = _paginate(ec2, "describe_instances", "Reservations")
            for res in reservations:
                for inst in res.get("Instances", []):
                    iid     = inst.get("InstanceId", "")
                    state   = inst.get("State", {}).get("Name", "")
                    if state not in ("running", "stopped"):
                        continue

                    launch  = inst.get("LaunchTime", datetime.now(timezone.utc))
                    age_days = (datetime.now(timezone.utc) - launch).days

                    opts = inst.get("MetadataOptions", {})
                    if opts.get("HttpTokens", "optional") != "required":
                        self.findings.append(self._find(
                            "ec2_imdsv1_enabled", "EC2", iid,
                            f"Instance '{iid}' allows IMDSv1 (HttpTokens=optional) — "
                            f"SSRF → credential theft",
                            age_days=age_days,
                        ))

                    for mapping in inst.get("BlockDeviceMappings", []):
                        vol_id = mapping.get("Ebs", {}).get("VolumeId", "")
                        if vol_id:
                            try:
                                vols = ec2.describe_volumes(
                                    VolumeIds=[vol_id]
                                ).get("Volumes", [])
                                for vol in vols:
                                    if not vol.get("Encrypted"):
                                        self.findings.append(self._find(
                                            "ec2_ebs_no_encryption", "EC2", vol_id,
                                            f"EBS volume '{vol_id}' on '{iid}' is unencrypted",
                                            age_days=age_days,
                                        ))
                            except ClientError:
                                pass
        except ClientError:
            pass

        # Public snapshots
        try:
            snaps = _paginate(ec2, "describe_snapshots", "Snapshots", OwnerIds=["self"])
            for snap in snaps:
                snap_id = snap["SnapshotId"]
                if snap.get("State") != "completed":
                    continue
                try:
                    attrs = ec2.describe_snapshot_attribute(
                        SnapshotId=snap_id, Attribute="createVolumePermission"
                    )
                    perms = attrs.get("CreateVolumePermissions", [])
                    if any(p.get("Group") == "all" for p in perms):
                        self.findings.append(self._find(
                            "ec2_ebs_snapshot_public", "EC2", snap_id,
                            f"EBS snapshot '{snap_id}' is publicly shared",
                        ))
                except ClientError:
                    pass
        except ClientError:
            pass

        print(f"  ✓ EC2: scan complete")

    # ── RDS ──────────────────────────────────────────────────────────────────

    def _scan_rds(self):
        print("  [RDS] Scanning...")
        _stealth_sleep(self.stealth)
        try:
            rds = self.session.client("rds", region_name=self.region,
                                      config=BOTO_RETRY_CONFIG)
            dbs = _paginate(rds, "describe_db_instances", "DBInstances")
        except ClientError:
            print("  ✗ RDS: insufficient permissions")
            return

        for db in dbs:
            db_id   = db["DBInstanceIdentifier"]
            db_arn  = db["DBInstanceArn"]
            engine  = db.get("Engine", "?")
            created = db.get("InstanceCreateTime", datetime.now(timezone.utc))
            age_days = (datetime.now(timezone.utc) - created).days

            if db.get("PubliclyAccessible"):
                endpoint = db.get("Endpoint", {}).get("Address", "")
                self.findings.append(self._find(
                    "rds_publicly_accessible", "RDS", db_arn,
                    f"RDS {engine} instance '{db_id}' is publicly accessible "
                    f"at {endpoint}",
                    age_days=age_days,
                ))

            if not db.get("StorageEncrypted"):
                self.findings.append(self._find(
                    "rds_no_encryption", "RDS", db_arn,
                    f"RDS instance '{db_id}' ({engine}) storage is not encrypted",
                    age_days=age_days,
                ))

            if db.get("BackupRetentionPeriod", 0) == 0:
                self.findings.append(self._find(
                    "rds_no_backup", "RDS", db_arn,
                    f"RDS instance '{db_id}' has automated backups disabled",
                    age_days=age_days,
                ))

            if not db.get("DeletionProtection"):
                self.findings.append(self._find(
                    "rds_no_deletion_protection", "RDS", db_arn,
                    f"RDS instance '{db_id}' has no deletion protection",
                    age_days=age_days,
                ))

        print(f"  ✓ RDS: {len(dbs)} instances scanned")

    # ── CloudTrail ────────────────────────────────────────────────────────────

    def _scan_cloudtrail(self):
        print("  [CloudTrail] Scanning...")
        _stealth_sleep(self.stealth)
        try:
            ct = self.session.client("cloudtrail", region_name=self.region)
            trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        except ClientError:
            return

        if not trails:
            self.findings.append(self._find(
                "cloudtrail_disabled", "CloudTrail", "arn:aws:cloudtrail",
                "No CloudTrail trails configured in this region",
            ))
            return

        for trail in trails:
            arn  = trail.get("TrailARN", "")
            name = trail.get("Name", "")

            # Check if logging is active
            try:
                status = ct.get_trail_status(Name=arn)
                if not status.get("IsLogging"):
                    self.findings.append(self._find(
                        "cloudtrail_disabled", "CloudTrail", arn,
                        f"CloudTrail '{name}' exists but logging is DISABLED",
                    ))
            except ClientError:
                pass

            if not trail.get("LogFileValidationEnabled"):
                self.findings.append(self._find(
                    "cloudtrail_no_log_validation", "CloudTrail", arn,
                    f"CloudTrail '{name}' has log file integrity validation disabled",
                ))

            if not trail.get("IsMultiRegionTrail"):
                self.findings.append(self._find(
                    "cloudtrail_not_multiregion", "CloudTrail", arn,
                    f"CloudTrail '{name}' is single-region only — other regions unmonitored",
                ))

        print(f"  ✓ CloudTrail: {len(trails)} trails scanned")

    # ── VPC ──────────────────────────────────────────────────────────────────

    def _scan_vpc(self):
        print("  [VPC] Scanning...")
        _stealth_sleep(self.stealth)
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            vpcs = ec2.describe_vpcs().get("Vpcs", [])
        except ClientError:
            return

        for vpc in vpcs:
            vpc_id = vpc["VpcId"]

            # Flow logs
            try:
                flow_logs = ec2.describe_flow_logs(
                    Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
                ).get("FlowLogs", [])
                if not flow_logs:
                    self.findings.append(self._find(
                        "cloudtrail_not_multiregion", "VPC", vpc_id,
                        f"VPC '{vpc_id}' has no flow logs enabled — network blind spot",
                    ))
            except ClientError:
                pass

        print(f"  ✓ VPC: {len(vpcs)} VPCs scanned")

    # ── Lambda ────────────────────────────────────────────────────────────────

    def _scan_lambda(self):
        print("  [Lambda] Scanning...")
        _stealth_sleep(self.stealth)
        try:
            lmb = self.session.client("lambda", region_name=self.region)
            functions = []
            paginator = lmb.get_paginator("list_functions")
            for page in paginator.paginate():
                functions.extend(page.get("Functions", []))
        except ClientError:
            return

        SECRET_PATTERNS = re.compile(
            r'(?i)(password|secret|token|api_?key|access_?key|private_?key|db_?pass)',
            re.IGNORECASE
        )

        for fn in functions:
            fn_name = fn["FunctionName"]
            fn_arn  = fn["FunctionArn"]

            # Public function URL
            try:
                url_config = lmb.get_function_url_config(FunctionName=fn_name)
                auth_type  = url_config.get("AuthType", "")
                if auth_type == "NONE":
                    url = url_config.get("FunctionUrl", "")
                    self.findings.append(self._find(
                        "lambda_public_url", "Lambda", fn_arn,
                        f"Lambda '{fn_name}' has a public URL with no auth: {url}",
                    ))
            except ClientError:
                pass

            # Secret env vars
            try:
                config  = lmb.get_function_configuration(FunctionName=fn_name)
                env_vars = config.get("Environment", {}).get("Variables", {})
                secret_keys = [k for k in env_vars.keys() if SECRET_PATTERNS.search(k)]
                if secret_keys:
                    self.findings.append(self._find(
                        "lambda_env_secrets", "Lambda", fn_arn,
                        f"Lambda '{fn_name}' has potential secrets in env vars: "
                        f"{', '.join(secret_keys)}",
                    ))
            except ClientError:
                pass

            # Excessive permissions (admin role)
            role_arn = fn.get("Role", "")
            if role_arn:
                try:
                    iam      = self.session.client("iam")
                    role_name = role_arn.split("/")[-1]
                    attached  = iam.list_attached_role_policies(
                        RoleName=role_name
                    ).get("AttachedPolicies", [])
                    for pol in attached:
                        if pol.get("PolicyName") == "AdministratorAccess":
                            self.findings.append(self._find(
                                "lambda_excessive_permissions", "Lambda", fn_arn,
                                f"Lambda '{fn_name}' execution role has "
                                f"AdministratorAccess",
                            ))
                except ClientError:
                    pass

        print(f"  ✓ Lambda: {len(functions)} functions scanned")

    # ── SNS ──────────────────────────────────────────────────────────────────

    def _scan_sns(self):
        print("  [SNS] Scanning...")
        _stealth_sleep(self.stealth)
        try:
            sns    = self.session.client("sns", region_name=self.region,
                                         config=BOTO_RETRY_CONFIG)
            topics = _paginate(sns, "list_topics", "Topics")
        except ClientError:
            return

        for topic in topics:
            arn = topic["TopicArn"]
            try:
                attrs = sns.get_topic_attributes(TopicArn=arn).get("Attributes", {})
                policy_str = attrs.get("Policy", "{}")
                policy     = json.loads(policy_str)
                for stmt in policy.get("Statement", []):
                    if stmt.get("Effect") == "Allow":
                        principal = stmt.get("Principal", {})
                        if principal == "*" or (isinstance(principal, dict) and
                                                principal.get("AWS") == "*"):
                            self.findings.append(self._find(
                                "sns_public_topic", "SNS", arn,
                                f"SNS topic '{arn.split(':')[-1]}' allows public access (*)",
                            ))
            except ClientError:
                pass

        print(f"  ✓ SNS: {len(topics)} topics scanned")

    # ── SQS ──────────────────────────────────────────────────────────────────

    def _scan_sqs(self):
        print("  [SQS] Scanning...")
        _stealth_sleep(self.stealth)
        try:
            sqs   = self.session.client("sqs", region_name=self.region,
                                        config=BOTO_RETRY_CONFIG)
            urls  = _paginate(sqs, "list_queues", "QueueUrls")
        except ClientError:
            return

        for url in urls:
            try:
                attrs = sqs.get_queue_attributes(
                    QueueUrl=url, AttributeNames=["Policy", "QueueArn"]
                ).get("Attributes", {})
                arn        = attrs.get("QueueArn", url)
                policy_str = attrs.get("Policy", "")
                if not policy_str:
                    continue
                policy = json.loads(policy_str)
                for stmt in policy.get("Statement", []):
                    if stmt.get("Effect") == "Allow":
                        principal = stmt.get("Principal", {})
                        if principal == "*" or (isinstance(principal, dict) and
                                                principal.get("AWS") == "*"):
                            self.findings.append(self._find(
                                "sqs_public_queue", "SQS", arn,
                                f"SQS queue '{arn.split(':')[-1]}' allows public access (*)",
                            ))
            except ClientError:
                pass

        print(f"  ✓ SQS: {len(urls)} queues scanned")

    # ── KMS ──────────────────────────────────────────────────────────────────

    def _scan_kms(self):
        print("  [KMS] Scanning...")
        _stealth_sleep(self.stealth)
        try:
            kms  = self.session.client("kms", region_name=self.region,
                                       config=BOTO_RETRY_CONFIG)
            keys = _paginate(kms, "list_keys", "Keys")
        except ClientError:
            return

        for key in keys:
            key_id = key["KeyId"]
            try:
                meta = kms.describe_key(KeyId=key_id).get("KeyMetadata", {})
                if meta.get("KeyManager") == "AWS":
                    continue  # AWS-managed keys, skip
                if meta.get("KeyState") != "Enabled":
                    continue

                # Key rotation
                try:
                    rot = kms.get_key_rotation_status(KeyId=key_id)
                    if not rot.get("KeyRotationEnabled"):
                        self.findings.append(self._find(
                            "kms_key_rotation_disabled", "KMS",
                            f"arn:aws:kms:{self.region}:{self.account_id}:key/{key_id}",
                            f"KMS key '{key_id}' has automatic rotation disabled",
                        ))
                except ClientError:
                    pass

                # Public key policy
                try:
                    pol    = json.loads(kms.get_key_policy(KeyId=key_id, PolicyName="default").get("Policy","{}"))
                    for stmt in pol.get("Statement", []):
                        if stmt.get("Effect") == "Allow":
                            principal = stmt.get("Principal", {})
                            if principal == "*" or (isinstance(principal, dict) and
                                                    principal.get("AWS") == "*"):
                                self.findings.append(self._find(
                                    "kms_public_key_policy", "KMS",
                                    f"arn:aws:kms:{self.region}:{self.account_id}:key/{key_id}",
                                    f"KMS key '{key_id}' policy grants access to * (public)",
                                ))
                except ClientError:
                    pass

            except ClientError:
                pass

        print(f"  ✓ KMS: {len(keys)} keys scanned")

    # ── Report builder ────────────────────────────────────────────────────────

    def _build_report(self, scan_time: str) -> Dict:
        sev_counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            sev_counts[f.get("severity", "LOW")] += 1

        total      = len(self.findings)
        all_checks = len(CONTROLS)
        score      = max(0, round(100 - (
            sev_counts["CRITICAL"] * 10 +
            sev_counts["HIGH"]     * 5  +
            sev_counts["MEDIUM"]   * 2  +
            sev_counts["LOW"]      * 0.5
        ), 1))

        # MITRE technique frequency
        mitre_freq: Dict[str, int] = defaultdict(int)
        for f in self.findings:
            mn = f.get("mitre_name", "")
            if mn:
                mitre_freq[mn] += 1
        top_mitre = sorted(mitre_freq.items(), key=lambda x: x[1], reverse=True)[:5]

        # Time-to-breach summary
        urgent_findings = [f for f in self.findings if f.get("ttb_urgency") == "IMMEDIATE"]
        min_ttb = min((f.get("ttb_days", 999) for f in self.findings), default=None)

        # Attack paths (simplified graph)
        attack_paths = self._find_attack_paths()

        return {
            "scan_time":  scan_time,
            "account_id": self.account_id,
            "region":     self.region,
            "stealth_mode": self.stealth,
            "findings":   self.findings,
            "attack_paths": attack_paths,
            "summary": {
                "total_findings":       total,
                "checks_total":         all_checks,
                "checks_passed":        all_checks - total,
                "compliance_score":     score,
                "severity_breakdown":   sev_counts,
                "attack_paths_found":   len(attack_paths),
                "top_mitre_techniques": top_mitre,
                "time_to_breach": {
                    "min_days":         round(min_ttb, 1) if min_ttb else None,
                    "immediate_count":  len(urgent_findings),
                    "urgent_findings":  [f["resource"] for f in urgent_findings[:5]],
                },
            },
            "graph_data": self._build_graph_data(attack_paths),
        }

    def _find_attack_paths(self) -> List[Dict]:
        """Find multi-step attack chains through findings."""
        paths = []
        critical = [f for f in self.findings if f["severity"] == "CRITICAL"]
        high     = [f for f in self.findings if f["severity"] == "HIGH"]

        # Chain: public S3 → IAM creds in bucket → assume role → RDS
        s3_public   = [f for f in critical if "s3_public" in f.get("check_id","")]
        iam_issues  = [f for f in critical + high if f.get("service") == "IAM"]
        rds_public  = [f for f in critical if "rds_public" in f.get("check_id","")]

        if s3_public and iam_issues:
            s3f  = s3_public[0]
            iamf = iam_issues[0]
            rs   = round(max(s3f["risk_score"], iamf["risk_score"]) + 1.5, 1)
            steps = [
                f"Enumerate public bucket: {s3f['resource']}",
                "Download exposed credentials/config files",
                f"Use stolen IAM credentials: {iamf['resource']}",
            ]
            if rds_public:
                steps.append(f"Query exposed RDS database: {rds_public[0]['resource']}")
            paths.append({
                "entry_point": s3f["resource"],
                "target":      rds_public[0]["resource"] if rds_public else iamf["resource"],
                "steps":       steps,
                "hop_count":   len(steps),
                "risk_score":  min(10.0, rs),
                "mitre_chain": ["T1530", "T1078.004", "T1190"],
            })

        # Chain: open SSH → IMDSv1 → credential theft → admin
        ssh_open  = [f for f in critical if f.get("check_id") == "ec2_ssh_open"]
        imds      = [f for f in high     if f.get("check_id") == "ec2_imdsv1_enabled"]
        admin_iam = [f for f in high + critical if f.get("check_id") == "iam_admin_policy"]

        if ssh_open and imds:
            steps = [
                f"SSH brute-force or exploit on: {ssh_open[0]['resource']}",
                f"Access IMDSv1 endpoint: {imds[0]['resource']}",
                "Steal IAM role credentials from instance metadata",
            ]
            if admin_iam:
                steps.append(f"Use admin IAM creds: {admin_iam[0]['resource']}")
            rs = round(max(ssh_open[0]["risk_score"], imds[0]["risk_score"]) + 2.0, 1)
            paths.append({
                "entry_point": ssh_open[0]["resource"],
                "target":      admin_iam[0]["resource"] if admin_iam else imds[0]["resource"],
                "steps":       steps,
                "hop_count":   len(steps),
                "risk_score":  min(10.0, rs),
                "mitre_chain": ["T1021.004", "T1552.005", "T1078.004"],
            })

        paths.sort(key=lambda x: -x["risk_score"])
        return paths[:10]

    def _build_graph_data(self, attack_paths: List[Dict]) -> Dict:
        nodes: List[Dict] = []
        links: List[Dict] = []
        node_ids: Set[str] = set()

        def _add_node(resource: str, service: str, sensitive: bool = False):
            if resource not in node_ids:
                node_ids.add(resource)
                nodes.append({
                    "id": resource[:50],
                    "service": service,
                    "sensitive": sensitive,
                })

        for f in self.findings:
            svc = f.get("service", "?")
            sensitive = f.get("severity") in ("CRITICAL", "HIGH")
            _add_node(f.get("resource", ""), svc, sensitive)

        for ap in attack_paths:
            ep = ap.get("entry_point", "")[:50]
            tg = ap.get("target", "")[:50]
            if ep and tg and ep != tg:
                links.append({"source": ep, "target": tg, "attack_type": True})

        return {"nodes": nodes, "links": links}


# ══════════════════════════════════════════════════════════════════════════════
#  MULTI-ACCOUNT SCANNER  (unchanged from v2, enhanced error reporting)
# ══════════════════════════════════════════════════════════════════════════════

class MultiAccountScanner:
    def __init__(self, master_session: boto3.Session, role_name: str = "SecurityScannerRole"):
        self.master_session = master_session
        self.role_name      = role_name

    def _list_accounts(self) -> List[Dict]:
        try:
            org = self.master_session.client("organizations")
            paginator = org.get_paginator("list_accounts")
            accounts  = []
            for page in paginator.paginate():
                accounts.extend(page.get("Accounts", []))
            return [a for a in accounts if a.get("Status") == "ACTIVE"]
        except ClientError as e:
            print(f"  ✗ Cannot list Org accounts: {e.response['Error']['Code']}")
            return []

    def scan_all(self, region: str, services: List[str],
                 stealth: bool = False, db: Optional[ScanHistoryDB] = None) -> Dict[str, Dict]:
        accounts = self._list_accounts()
        if not accounts:
            print("  No accounts found — scanning current account only")
            return {}

        results  = {}
        sts = self.master_session.client("sts")

        for acct in accounts:
            acct_id   = acct["Id"]
            acct_name = acct.get("Name", acct_id)
            print(f"\n  → Scanning account {acct_name} ({acct_id})...")

            try:
                assumed = sts.assume_role(
                    RoleArn=f"arn:aws:iam::{acct_id}:role/{self.role_name}",
                    RoleSessionName="CloudGuardUltra",
                )
                creds   = assumed["Credentials"]
                session = boto3.Session(
                    aws_access_key_id=creds["AccessKeyId"],
                    aws_secret_access_key=creds["SecretAccessKey"],
                    aws_session_token=creds["SessionToken"],
                    region_name=region,
                )
                scanner = SecurityScanner(session, region=region, services=services,
                                          stealth=stealth)
                report  = scanner.run()
                results[acct_id] = report
                if db:
                    db.save(report)
            except ClientError as e:
                results[acct_id] = {"error": str(e), "account_id": acct_id}
                print(f"  ✗ {acct_name}: {e.response['Error']['Code']}")

        return results


# ══════════════════════════════════════════════════════════════════════════════
#  OUTPUT FORMATTERS
# ══════════════════════════════════════════════════════════════════════════════

def save_json(report: Dict, path: str):
    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"   📄 JSON  → {path}")

def save_csv(report: Dict, path: str):
    fields = ["check_id","service","severity","resource","message",
              "risk_score","cvss","ttb_days","ttb_urgency",
              "cis","nist","pci","mitre","mitre_name"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(report.get("findings", []))
    print(f"   📊 CSV   → {path}")

def save_html(report: Dict, path: str):
    """Generate a self-contained HTML report with D3 graph + TTB timeline."""
    s     = report.get("summary", {})
    sev   = s.get("severity_breakdown", {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0})
    finds = report.get("findings", [])
    paths = report.get("attack_paths", [])
    gd    = report.get("graph_data", {"nodes":[],"links":[]})
    mitre = s.get("top_mitre_techniques", [])
    ttb_s = s.get("time_to_breach", {})

    score = s.get("compliance_score", 0)
    score_color = ("#22c55e" if score >= 80 else
                   "#f97316" if score >= 50 else "#dc2626")

    def badge(sv):
        c = {"CRITICAL":"#dc2626","HIGH":"#ea580c","MEDIUM":"#d97706","LOW":"#65a30d"}
        return f'<span class="badge" style="background:{c.get(sv,"#6b7280")}">{sv}</span>'

    def ttb_color(days):
        if days < 1:   return "#dc2626"
        if days < 3:   return "#ea580c"
        if days < 7:   return "#d97706"
        if days < 30:  return "#65a30d"
        return "#22c55e"

    find_rows = "".join(f"""
    <tr>
      <td>{badge(f["severity"])}</td>
      <td>{f["service"]}</td>
      <td class="mono">{f["resource"][:40]}</td>
      <td>{f["message"][:80]}</td>
      <td class="risk" style="color:{'#dc2626' if f.get('risk_score',0)>=8 else '#ea580c' if f.get('risk_score',0)>=6 else '#64748b'}">{f.get('risk_score','—')}</td>
      <td style="color:{ttb_color(f.get('ttb_days',999))};font-weight:700;text-align:center">{f.get('ttb_days','?')}d</td>
      <td class="sm gray">{f.get('cis','—')}</td>
      <td class="sm"><span class="mitre-badge">{f.get('mitre','—')}</span></td>
      <td class="sm gray">{f.get('remediation_fn','—')}</td>
    </tr>""" for f in finds[:200])

    path_rows = "".join(f"""
    <tr>
      <td class="mono sm">{ap['entry_point'][:35]}</td>
      <td class="mono sm">{ap['target'][:35]}</td>
      <td style="text-align:center">{ap.get('hop_count','?')}</td>
      <td style="color:#dc2626;font-weight:700;text-align:center">{ap['risk_score']}</td>
      <td class="sm">{(' → '.join(ap.get('mitre_chain',[])))}</td>
      <td class="sm">{('<br>→ '.join(ap.get('steps',[])))}</td>
    </tr>""" for ap in paths[:10])

    # TTB timeline items
    ttb_items = sorted(
        [f for f in finds if f.get("ttb_days") is not None],
        key=lambda x: x.get("ttb_days", 999)
    )[:15]

    ttb_bars = "".join(f"""
    <div style="margin-bottom:8px">
      <div style="display:flex;justify-content:space-between;margin-bottom:2px">
        <span style="font-size:11px;color:#c7d2fe">{f['resource'][:35]}</span>
        <span style="font-size:11px;font-weight:700;color:{ttb_color(f['ttb_days'])}">{f['ttb_days']}d</span>
      </div>
      <div style="background:#0f172a;border-radius:3px;height:4px">
        <div style="background:{ttb_color(f['ttb_days'])};border-radius:3px;height:4px;
             width:{min(f['ttb_days']/30*100,100):.0f}%"></div>
      </div>
    </div>""" for f in ttb_items) or "<p class='sm gray'>No TTB data.</p>"

    mitre_bars = "".join(f"""
    <div style="margin-bottom:10px">
      <div style="display:flex;justify-content:space-between;margin-bottom:3px">
        <span style="font-size:12px;color:#c7d2fe">{name}</span>
        <span style="font-size:11px;color:#64748b">{cnt}</span>
      </div>
      <div style="background:#0f172a;border-radius:3px;height:5px">
        <div style="background:#6366f1;border-radius:3px;height:5px;
             width:{min(cnt/max(mitre[0][1] if mitre else 1,1)*100,100):.0f}%"></div>
      </div>
    </div>""" for name, cnt in mitre) or "<p class='sm gray'>No data yet.</p>"

    ttb_min = ttb_s.get("min_days", "—")
    ttb_imm = ttb_s.get("immediate_count", 0)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CloudGuard ULTRA — Security Report</title>
<script src="https://d3js.org/d3.v7.min.js"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#f1f5f9;min-height:100vh}}
nav{{background:#1e293b;border-bottom:2px solid #6366f1;padding:0 36px;height:56px;display:flex;align-items:center;gap:16px}}
.logo{{font-size:18px;font-weight:800;color:#38bdf8}}
.logo span{{color:#f97316}}
.nav-badge{{background:#1e1b4b;color:#a5b4fc;font-size:10px;padding:2px 8px;border-radius:10px;border:1px solid #4f46e5}}
.nav-r{{margin-left:auto;font-size:12px;color:#64748b}}
.wrap{{max-width:1600px;margin:0 auto;padding:26px 36px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:18px}}
.card{{background:#1e293b;border-radius:10px;padding:18px;border:1px solid #334155}}
.card .lbl{{font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px}}
.card .val{{font-size:30px;font-weight:800}}
.card .sub{{font-size:10px;color:#64748b;margin-top:4px}}
.sec{{background:#1e293b;border-radius:10px;padding:20px;margin-bottom:16px;border:1px solid #334155}}
.sec h2{{font-size:15px;font-weight:700;color:#e2e8f0;margin-bottom:14px}}
.g2{{display:grid;grid-template-columns:2fr 1fr;gap:16px;margin-bottom:16px}}
.g3{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:16px}}
.g4{{display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:16px;margin-bottom:16px}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{text-align:left;padding:8px 10px;background:#0f172a;color:#64748b;font-size:10px;text-transform:uppercase;white-space:nowrap}}
td{{padding:8px 10px;border-bottom:1px solid #0f172a;vertical-align:top;color:#cbd5e1}}
tr:hover td{{background:#0f172a50}}
.badge{{padding:2px 7px;border-radius:3px;font-size:10px;font-weight:700;color:#fff}}
.mono{{font-family:monospace;font-size:11px}}
.sm{{font-size:11px}} .gray{{color:#64748b}} .risk{{text-align:center;font-weight:700}}
.mitre-badge{{background:#312e81;color:#a5b4fc;padding:1px 5px;border-radius:3px;font-family:monospace;font-size:10px}}
.score-ring{{width:68px;height:68px;border-radius:50%;border:5px solid {score_color};display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:800;color:{score_color};margin:4px auto}}
.pulse{{animation:pulse 2s infinite}}
@keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.5}}}}
.filter-bar{{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap}}
.fb{{background:#0f172a;border:1px solid #334155;color:#94a3b8;padding:4px 12px;border-radius:6px;cursor:pointer;font-size:11px}}
.fb.on{{background:#1e1b4b;border-color:#6366f1;color:#a5b4fc}}
#graph-wrap{{width:100%;height:440px;background:#0f172a;border-radius:8px;overflow:hidden}}
</style>
</head>
<body>
<nav>
  <div class="logo">Cloud<span>Guard</span> ULTRA</div>
  <span class="nav-badge">v4.0</span>
  {'<span class="nav-badge" style="background:#0c1a0c;border-color:#22c55e;color:#86efac">🔇 LOW-NOISE</span>' if report.get('stealth_mode') else ''}
  <div class="nav-r">
    {report.get('account_id','—')} · {report.get('region','—')} · {report.get('scan_time','')[:19]} UTC
  </div>
</nav>

<div class="wrap">
<!-- KPI cards -->
<div class="cards">
  <div class="card">
    <div class="lbl">Compliance Score</div>
    <div class="score-ring">{score}</div>
  </div>
  <div class="card">
    <div class="lbl">Critical</div>
    <div class="val" style="color:#dc2626">{sev['CRITICAL']}</div>
  </div>
  <div class="card">
    <div class="lbl">High</div>
    <div class="val" style="color:#ea580c">{sev['HIGH']}</div>
  </div>
  <div class="card">
    <div class="lbl">Medium</div>
    <div class="val" style="color:#d97706">{sev['MEDIUM']}</div>
  </div>
  <div class="card">
    <div class="lbl">Low</div>
    <div class="val" style="color:#65a30d">{sev['LOW']}</div>
  </div>
  <div class="card">
    <div class="lbl">Min Time-to-Breach</div>
    <div class="val {'pulse' if ttb_min != '—' and float(ttb_min) < 3 else ''}" 
         style="color:{'#dc2626' if ttb_min != '—' and float(str(ttb_min)) < 3 else '#f97316'}">{ttb_min}d</div>
    <div class="sub">{ttb_imm} immediate threats</div>
  </div>
  <div class="card">
    <div class="lbl">Attack Paths</div>
    <div class="val" style="color:#f43f5e">{s.get('attack_paths_found',0)}</div>
  </div>
  <div class="card">
    <div class="lbl">Total Findings</div>
    <div class="val">{s.get('total_findings',0)}</div>
    <div class="sub">{s.get('checks_passed',0)}/{s.get('checks_total',0)} checks passed</div>
  </div>
</div>

<!-- TTB + MITRE + Graph -->
<div class="g3">
  <div class="sec">
    <h2>⏱️ Time-to-Breach Estimator <span style="font-size:10px;color:#64748b">(days until exploitation)</span></h2>
    {ttb_bars}
  </div>
  <div class="sec">
    <h2>🎯 MITRE ATT&amp;CK Top Techniques</h2>
    {mitre_bars}
  </div>
  <div class="sec">
    <h2>⛓️ Attack Paths</h2>
    <table>
      <tr><th>From</th><th>To</th><th>Hops</th><th>Risk</th><th>MITRE</th><th>Steps</th></tr>
      {path_rows or '<tr><td colspan="6" class="gray" style="text-align:center">No attack paths found</td></tr>'}
    </table>
  </div>
</div>

<!-- Resource Graph -->
<div class="sec">
  <h2>🕸️ Resource Compromise Graph</h2>
  <div id="graph-wrap"></div>
</div>

<!-- Findings table -->
<div class="sec">
  <h2>🔍 All Findings</h2>
  <div class="filter-bar">
    <button class="fb on" onclick="filt(this,'ALL')">All ({s.get('total_findings',0)})</button>
    <button class="fb" onclick="filt(this,'CRITICAL')" style="color:#dc2626">CRITICAL ({sev['CRITICAL']})</button>
    <button class="fb" onclick="filt(this,'HIGH')" style="color:#ea580c">HIGH ({sev['HIGH']})</button>
    <button class="fb" onclick="filt(this,'MEDIUM')" style="color:#d97706">MEDIUM ({sev['MEDIUM']})</button>
    <button class="fb" onclick="filt(this,'LOW')" style="color:#65a30d">LOW ({sev['LOW']})</button>
  </div>
  <table>
    <thead>
      <tr>
        <th>Severity</th><th>Service</th><th>Resource</th><th>Message</th>
        <th>Risk</th><th>TTB</th><th>CIS</th><th>MITRE</th><th>Auto-Fix</th>
      </tr>
    </thead>
    <tbody id="ftbody">{find_rows}</tbody>
  </table>
</div>

</div><!-- /wrap -->

<script>
// Filter
function filt(btn,sev){{
  document.querySelectorAll('.fb').forEach(b=>b.classList.remove('on'));
  btn.classList.add('on');
  const body=document.getElementById('ftbody');
  if(!body)return;
  body.querySelectorAll('tr').forEach(r=>{{
    const b=r.querySelector('span');
    r.style.display=(sev==='ALL'||b?.textContent===sev)?'':'none';
  }});
}}

// D3 Graph
(function(){{
  const gd={json.dumps(gd)};
  const wrap=document.getElementById('graph-wrap');
  const W=wrap.clientWidth||1200, H=440;
  const svg=d3.select('#graph-wrap').append('svg').attr('width','100%').attr('height',H);

  if(!gd.nodes.length){{
    svg.append('text').attr('x',W/2).attr('y',H/2).attr('text-anchor','middle')
      .attr('fill','#334155').attr('font-size',14)
      .text('No graph data — run a full scan to populate this view');
    return;
  }}

  svg.append('defs').append('marker').attr('id','arr')
    .attr('viewBox','0 -5 10 10').attr('refX',22).attr('refY',0)
    .attr('markerWidth',5).attr('markerHeight',5).attr('orient','auto')
    .append('path').attr('d','M0,-5L10,0L0,5').attr('fill','#ef4444');

  const sim=d3.forceSimulation(gd.nodes)
    .force('link',d3.forceLink(gd.links).id(d=>d.id).distance(160))
    .force('charge',d3.forceManyBody().strength(-600))
    .force('center',d3.forceCenter(W/2,H/2))
    .force('collision',d3.forceCollide(26));

  const link=svg.append('g').selectAll('line').data(gd.links).join('line')
    .attr('stroke',d=>d.attack_type?'#ef4444':'#334155')
    .attr('stroke-width',d=>d.attack_type?2.5:1)
    .attr('stroke-opacity',0.8)
    .attr('marker-end',d=>d.attack_type?'url(#arr)':null);

  const cm={{S3:'#f59e0b',IAM:'#6366f1',IAM_USER:'#818cf8',EC2:'#10b981',
             RDS:'#3b82f6',Lambda:'#8b5cf6',SNS:'#ec4899',SQS:'#06b6d4',
             KMS:'#f43f5e',CloudTrail:'#84cc16',VPC:'#14b8a6'}};

  const node=svg.append('g').selectAll('circle').data(gd.nodes).join('circle')
    .attr('r',d=>d.sensitive?18:13)
    .attr('fill',d=>cm[d.service]||'#94a3b8')
    .attr('stroke',d=>d.sensitive?'#fbbf24':'#1e293b')
    .attr('stroke-width',d=>d.sensitive?3:1.5)
    .style('cursor','pointer')
    .call(d3.drag()
      .on('start',(e,d)=>{{if(!e.active)sim.alphaTarget(0.3).restart();d.fx=d.x;d.fy=d.y;}})
      .on('drag',(e,d)=>{{d.fx=e.x;d.fy=e.y;}})
      .on('end',(e,d)=>{{if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null;}}));

  const tip=d3.select('body').append('div')
    .style('position','fixed').style('background','#1e293b')
    .style('border','1px solid #334155').style('border-radius','6px')
    .style('padding','8px 12px').style('font-size','12px')
    .style('color','#e2e8f0').style('pointer-events','none')
    .style('opacity',0).style('max-width','280px').style('z-index',9999);

  node.on('mouseover',(e,d)=>{{
    tip.style('opacity',1).style('left',e.clientX+14+'px').style('top',e.clientY-10+'px')
      .html(`<strong>[${{d.service}}]</strong> ${{d.id}}${{d.sensitive?'<br><span style="color:#fbbf24">⚠ HIGH RISK</span>':''}}`);
  }}).on('mouseout',()=>tip.style('opacity',0));

  const lbl=svg.append('g').selectAll('text').data(gd.nodes).join('text')
    .attr('font-size',9).attr('fill','#64748b').attr('text-anchor','middle').attr('dy',29)
    .text(d=>d.id.length>20?d.id.slice(0,18)+'…':d.id);

  sim.on('tick',()=>{{
    link.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y)
        .attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);
    node.attr('cx',d=>d.x).attr('cy',d=>d.y);
    lbl.attr('x',d=>d.x).attr('y',d=>d.y);
  }});
}})();
</script>
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html)
    print(f"   🌐 HTML  → {path}")


# ══════════════════════════════════════════════════════════════════════════════
#  CLI PRINT SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

def print_summary(report: Dict):
    s    = report.get("summary", {})
    sev  = s.get("severity_breakdown", {})
    ttb  = s.get("time_to_breach", {})

    print(f"\n{'═'*70}")
    print(f"  CloudGuard ULTRA  —  Scan Results")
    print(f"{'═'*70}")
    print(f"  Account          : {report.get('account_id','—')}")
    print(f"  Region           : {report.get('region','—')}")
    print(f"  Scan Time        : {report.get('scan_time','—')[:19]} UTC")
    print(f"  Compliance Score : {s.get('compliance_score',0)}%  "
          f"({s.get('checks_passed',0)}/{s.get('checks_total',0)} checks passed)")
    print(f"  Total Findings   : {s.get('total_findings',0)}")
    print(f"  {red('CRITICAL')}        : {sev.get('CRITICAL',0)}")
    print(f"  {yellow('HIGH')}            : {sev.get('HIGH',0)}")
    print(f"  {cyan('MEDIUM')}          : {sev.get('MEDIUM',0)}")
    print(f"  {green('LOW')}             : {sev.get('LOW',0)}")
    print(f"  Attack Paths     : {s.get('attack_paths_found',0)}")

    if ttb.get("min_days") is not None:
        min_d = ttb["min_days"]
        color = red if min_d < 3 else yellow if min_d < 7 else green
        print(f"  {color('Min Time-to-Breach')}: {color(str(min_d) + ' days')}  "
              f"({ttb.get('immediate_count',0)} immediate threats)")

    print(f"{'═'*70}")

    if report.get("findings"):
        print(f"\n  🔴 TOP 10 FINDINGS (by risk score):\n")
        for i, f in enumerate(report["findings"][:10], 1):
            sev_str = sev_color(f['severity'], f'[{f["severity"]:8}]')
            ttb_str = f"TTB:{f.get('ttb_days','?')}d"
            print(f"  {i:2}. {sev_str} risk={f.get('risk_score','?'):4}  "
                  f"{f['service']:12} {f['resource'][:28]:28} "
                  f"MITRE:{f.get('mitre','—')}  {ttb_str}")

    if report.get("attack_paths"):
        print(f"\n  ⛓️  ATTACK PATHS:\n")
        for ap in report["attack_paths"][:5]:
            print(f"  [{ap['risk_score']:4}] {ap['entry_point'][:30]} → {ap['target'][:30]} "
                  f"({ap['hop_count']} hops)")
            for step in ap.get("steps", []):
                print(f"         → {step}")

    if s.get("top_mitre_techniques"):
        print(f"\n  🎯 TOP MITRE ATT&CK TECHNIQUES:\n")
        for name, cnt in s["top_mitre_techniques"]:
            bar = "█" * min(cnt, 30)
            print(f"  {cnt:3}x  {bar}  {name}")


# ══════════════════════════════════════════════════════════════════════════════
#  📋 EXECUTIVE BREACH IMPACT REPORT
#  Business-language summary with financial exposure, regulatory risk, and
#  recommended immediate actions — written for a non-technical audience.
# ══════════════════════════════════════════════════════════════════════════════

def generate_executive_report(report: Dict, blast: Optional[Dict] = None) -> str:
    """
    Generates a plain-English executive summary of the security posture.

    Sections:
      1. Overall Security Posture (score + grade)
      2. Immediate Risk Assessment (TTB-driven)
      3. Business Impact Estimate (regulatory + financial exposure)
      4. Attack Path Summary
      5. Blast Radius Summary (if available)
      6. Top 5 Recommended Immediate Actions
      7. Compliance Gaps
    """
    s     = report.get("summary", {})
    sev   = s.get("severity_breakdown", {})
    score = s.get("compliance_score", 0)
    ttb_s = s.get("time_to_breach", {})
    paths = report.get("attack_paths", [])
    finds = report.get("findings", [])
    now   = datetime.now().strftime("%B %d, %Y")

    # ── Grade
    if score >= 90:   grade = "A — Strong"
    elif score >= 75: grade = "B — Adequate"
    elif score >= 60: grade = "C — Needs Attention"
    elif score >= 45: grade = "D — At Risk"
    else:             grade = "F — Critical Risk"

    # ── Financial exposure estimate
    critical_n = sev.get("CRITICAL", 0)
    high_n     = sev.get("HIGH", 0)
    # Conservative estimate: $50K per critical finding, $15K per high
    # based on IBM Cost of a Data Breach 2023 ($4.45M average ÷ typical finding ratios)
    low_est  = critical_n * 50_000  + high_n * 15_000
    high_est = critical_n * 500_000 + high_n * 100_000
    low_fmt  = f"${low_est:,}"
    high_fmt = f"${high_est:,}"

    # ── Regulatory flags
    reg_flags = []
    mitre_names = {f.get("mitre_name", "") for f in finds}
    check_ids   = {f.get("check_id", "") for f in finds}
    if any("s3_public" in c for c in check_ids):
        reg_flags.append("GDPR Art. 32 (unauthorized data access risk)")
        reg_flags.append("HIPAA §164.312 (access controls)")
    if any("rds_no_encryption" in c for c in check_ids):
        reg_flags.append("PCI-DSS Req. 3.4 (data-at-rest encryption)")
    if any("cloudtrail" in c for c in check_ids):
        reg_flags.append("SOC 2 CC7.2 (audit logging)")
    if any("iam_root" in c for c in check_ids):
        reg_flags.append("CIS AWS 1.4/1.5 (root account security)")
    if not reg_flags:
        reg_flags.append("No critical regulatory violations detected")

    # ── Top immediate actions (from CRITICAL/HIGH findings sorted by TTB)
    urgent = sorted(
        [f for f in finds if f.get("severity") in ("CRITICAL", "HIGH")],
        key=lambda x: x.get("ttb_days", 999)
    )[:5]

    action_lines = []
    for i, f in enumerate(urgent, 1):
        days_str = f"{f.get('ttb_days', '?')}d"
        rem_fn   = f.get("remediation_fn") or "Manual review required"
        action_lines.append(
            f"  {i}. [{f['service']}] {f.get('check_id','').replace('_',' ').title()}\n"
            f"     Resource   : {f.get('resource','')[:70]}\n"
            f"     Time-to-Breach: {days_str}  ({f.get('ttb_urgency','')})\n"
            f"     Auto-fix   : {rem_fn}\n"
            f"     CIS Control: {f.get('cis','—')}  |  MITRE: {f.get('mitre','—')}"
        )

    # ── Blast radius summary
    blast_section = ""
    if blast:
        blast_section = f"""
BLAST RADIUS ANALYSIS
{'─'*60}
  Mapped resources        : {blast.get('total_resources', 0)}
  Compromised entry points: {blast.get('compromised_entry_points', 0)}
  Resources reachable     : {blast.get('total_reachable', 0)}
  Blast radius            : {blast.get('blast_radius_pct', 0)}% of environment
  Max propagated risk     : {blast.get('max_propagated_risk', 0)}/10.0

  Crown Jewels at Risk:"""
        for t in blast.get("highest_value_targets", [])[:3]:
            prop = t.get("propagated_risk", t.get("target_value_score", 0))
            blast_section += (f"\n    - [{t.get('service','?')}] {t.get('id','')[:60]}"
                              f"  (propagated risk: {prop})")

        leaders = blast.get("centrality_leaders", [])
        if leaders:
            blast_section += "\n\n  Chokepoint Nodes (highest betweenness centrality):"
            for node in leaders[:3]:
                blast_section += (f"\n    - {node['node'][:60]}"
                                  f"  (BC: {node.get('betweenness', 0):.4f})")

    # ── Compliance gaps
    ctrl_ids = {f.get("check_id") for f in finds}
    cis_fails = sorted({CONTROLS[c]["cis"] for c in ctrl_ids
                        if c in CONTROLS and CONTROLS[c].get("cis") != "—"})

    report_text = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                  CLOUDGUARD ULTRA — EXECUTIVE SECURITY REPORT               ║
║                              CONFIDENTIAL                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

  Prepared   : {now}
  Account    : {report.get('account_id', '—')}
  Region(s)  : {report.get('region', '—')}
  Scan Time  : {report.get('scan_time', '—')[:19]} UTC

{'═'*78}
EXECUTIVE SUMMARY
{'─'*60}
  Security Grade  : {grade}
  Compliance Score: {score}%  (100% = all checks passing)
  Total Findings  : {s.get('total_findings', 0)}
                    {sev.get('CRITICAL',0)} Critical  ·  {sev.get('HIGH',0)} High  ·  {sev.get('MEDIUM',0)} Medium  ·  {sev.get('LOW',0)} Low
  Attack Paths    : {s.get('attack_paths_found', 0)} confirmed multi-hop exploit chains

{'═'*78}
IMMEDIATE RISK ASSESSMENT
{'─'*60}
  Fastest Time-to-Breach  : {ttb_s.get('min_days', '—')} days
  Findings exploitable NOW: {ttb_s.get('immediate_count', 0)} (TTB < 24 hours)

  This environment has {critical_n} critical finding(s) that could be exploited
  within days by an attacker with basic cloud reconnaissance skills.

{'═'*78}
ESTIMATED BUSINESS IMPACT
{'─'*60}
  Financial Exposure Range: {low_fmt} — {high_fmt}
  (Conservative model: critical findings × $50K–$500K, high findings × $15K–$100K.
   Based on IBM Cost of a Data Breach 2023: $4.45M average per incident.)

  Regulatory Risk:
{chr(10).join("    • " + r for r in reg_flags)}

{'═'*78}
ATTACK PATH SUMMARY
{'─'*60}
  {len(paths)} confirmed attack chain(s) detected across your infrastructure.
{"".join(chr(10) + "  Chain " + str(i+1) + ": " + " → ".join(p.get("steps",["?"])[:3]) + f"  [Risk: {p.get('risk_score','?')}/10]" for i, p in enumerate(paths[:5])) or chr(10) + "  No multi-hop attack paths detected."}
{blast_section}

{'═'*78}
TOP 5 RECOMMENDED IMMEDIATE ACTIONS
{'─'*60}
  (Sorted by time-to-breach — fastest exploited first)

{chr(10).join(action_lines) or "  No critical/high findings."}

{'═'*78}
COMPLIANCE GAPS (CIS AWS Foundations v1.5)
{'─'*60}
  Failing controls: {', '.join(cis_fails) or 'None'}

{'═'*78}
NEXT STEPS
{'─'*60}
  1. Run:  python scanner_ultra.py --remediate --no-dry-run
           (applies all safe auto-fixes immediately)
  2. Run:  python scanner_ultra.py --inject-canaries --no-dry-run
           (plants honeytokens to detect active attackers)
  3. Schedule daily scans via AWS Lambda + EventBridge
  4. Review DISRUPTIVE remediations with your team before applying

  Full technical report: scan_*.json / scan_*.html
{'═'*78}
"""
    return report_text


# ══════════════════════════════════════════════════════════════════════════════
#  PREDICTIVE TREND ANALYSIS  (SQLite historical data)
#  Linear regression over scan history to forecast compliance score
# ══════════════════════════════════════════════════════════════════════════════

def predict_trend(db: ScanHistoryDB, days_ahead: int = 30) -> Optional[Dict]:
    """
    Fits a simple linear model to historical compliance scores
    and extrapolates forward by days_ahead.
    """
    trends = db.get_trends(limit=20)
    if len(trends) < 3:
        return None

    scores = [t.get("score", 0) for t in trends]
    x      = list(range(len(scores)))

    # Simple linear regression: y = mx + b
    n  = len(x)
    sx = sum(x)
    sy = sum(scores)
    sx2 = sum(xi**2 for xi in x)
    sxy = sum(xi * yi for xi, yi in zip(x, scores))
    m   = (n * sxy - sx * sy) / (n * sx2 - sx ** 2 + 1e-9)
    b   = (sy - m * sx) / n

    # Forecast
    x_future = len(x) - 1 + days_ahead
    predicted = m * x_future + b
    predicted = max(0, min(100, predicted))

    trend = "IMPROVING" if m > 0.2 else "REGRESSING" if m < -0.2 else "FLAT"

    return {
        "current_score":    scores[-1],
        "predicted_score":  round(predicted, 1),
        "days_ahead":       days_ahead,
        "trend":            trend,
        "slope_per_scan":   round(m, 3),
        "scans_analyzed":   len(scores),
        "alert": predicted < 50 and trend == "REGRESSING",
    }


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN  CLI
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="CloudGuard ULTRA — AWS Security Posture Scanner v4.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner_ultra.py                                   # basic scan
  python scanner_ultra.py --low-noise                       # rate-limited scan
  python scanner_ultra.py --all-regions                     # scan all enabled regions
  python scanner_ultra.py --simulate-attacks                # verify + score exploitability
  python scanner_ultra.py --blast-radius                    # map compromise impact
  python scanner_ultra.py --time-to-breach                  # TTB report
  python scanner_ultra.py --executive-report                # business-language summary
  python scanner_ultra.py --inject-canaries                 # plant honeytokens (dry-run)
  python scanner_ultra.py --inject-canaries --no-dry-run   # actually plant them
  python scanner_ultra.py --remediate                       # dry-run auto-fixes
  python scanner_ultra.py --remediate --no-dry-run         # LIVE auto-fix
  python scanner_ultra.py --diff reports/scan_old.json     # compare scans
  python scanner_ultra.py --pivot-map                       # cross-account trusts
  python scanner_ultra.py --predict-trend                   # forecast score
  python scanner_ultra.py --multi-account --simulate-attacks --blast-radius  # nuclear

SQLite history: cloudguard.db  (auto-created)
Dashboard:      python dashboard.py
        """
    )

    # Core
    parser.add_argument("--profile",        default=None)
    parser.add_argument("--region",         default="us-east-1")
    parser.add_argument("--all-regions",    action="store_true",
                        help="Scan ALL enabled AWS regions in parallel")
    parser.add_argument("--services",       nargs="+",
                        default=["s3","iam","ec2","rds","cloudtrail","vpc","lambda","sns","sqs","kms"],
                        choices=["s3","iam","ec2","rds","cloudtrail","vpc","lambda","sns","sqs","kms"])
    parser.add_argument("--output",         nargs="+", default=["json","html"],
                        choices=["json","html","csv"])
    parser.add_argument("--output-dir",     default="reports")
    parser.add_argument("--no-db",          action="store_true")

    # Multi-account
    parser.add_argument("--multi-account",  action="store_true")
    parser.add_argument("--role",           default="SecurityScannerRole")

    # 🔇 Low-noise (renamed from stealth — same behaviour, honest framing)
    parser.add_argument("--low-noise",      action="store_true",
                        help="Rate-limited scan with inter-request delays (reduced API call density)")
    parser.add_argument("--stealth",        action="store_true",
                        help="Alias for --low-noise (backwards compatibility)")

    # 🔴 Attack simulator
    parser.add_argument("--simulate-attacks", action="store_true",
                        help="Live boto3 verification + simulation scoring per finding")

    # 🧬 Blast radius
    parser.add_argument("--blast-radius",   action="store_true",
                        help="Map compromise blast radius with centrality + risk propagation")

    # ⏱️ TTB report
    parser.add_argument("--time-to-breach", action="store_true",
                        help="Print full time-to-breach breakdown per finding")

    # 📋 Executive report
    parser.add_argument("--executive-report", action="store_true",
                        help="Generate business-language executive breach impact summary")

    # 📡 Canary injection
    parser.add_argument("--inject-canaries", action="store_true",
                        help="Plant AWS honeytokens in misconfigured resources")
    parser.add_argument("--check-canaries",  action="store_true",
                        help="Check whether any planted canaries have been triggered")

    # 🔄 Auto-remediation
    parser.add_argument("--remediate",      action="store_true",
                        help="Run auto-remediation engine (dry-run by default)")
    parser.add_argument("--no-dry-run",     action="store_true",
                        help="ACTUALLY apply remediations / plant canaries")
    parser.add_argument("--remediate-all",  action="store_true",
                        help="Include DISRUPTIVE remediations (requires --no-dry-run)")

    # 📊 Diff
    parser.add_argument("--diff",           default=None, metavar="OLD_SCAN.json",
                        help="Compare this scan to a previous JSON report")

    # 🌐 Cross-account pivot
    parser.add_argument("--pivot-map",      action="store_true",
                        help="Map cross-account IAM trust and S3 pivot paths")

    # 📈 Trend prediction
    parser.add_argument("--predict-trend",  action="store_true",
                        help="Forecast compliance score using historical scan data")

    args = parser.parse_args()

    # Merge --stealth into --low-noise for backwards compat
    low_noise = args.low_noise or args.stealth

    # ── Auth ──────────────────────────────────────────────────────────────────
    try:
        session = (boto3.Session(profile_name=args.profile, region_name=args.region)
                   if args.profile else boto3.Session(region_name=args.region))
        identity = session.client("sts").get_caller_identity()
        print(f"✅ Authenticated as: {identity.get('Arn','—')}")
    except NoCredentialsError:
        print("❌ No AWS credentials found.")
        print("   Set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY or use --profile")
        sys.exit(1)
    except ClientError as e:
        print(f"❌ AWS auth error: {e}")
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)
    db  = None if args.no_db else ScanHistoryDB()
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    dry_run = not args.no_dry_run

    print(f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║             CloudGuard ULTRA  v4.0  —  AWS Security Scanner 💀              ║
╚══════════════════════════════════════════════════════════════════════════════╝
  Low-noise mode  : {'🔇 ON (rate-limited, inter-request delays)' if low_noise else 'OFF'}
  All regions     : {'🌍 ON' if args.all_regions else 'OFF'}
  Attack sim      : {'🔴 ON (live verify + simulation scoring)' if args.simulate_attacks else 'OFF'}
  Blast radius    : {'🧬 ON (centrality + risk propagation)' if args.blast_radius else 'OFF'}
  Executive report: {'📋 ON' if args.executive_report else 'OFF'}
  Canary inject   : {'📡 ON (' + ('DRY RUN' if dry_run else 'LIVE') + ')' if args.inject_canaries else 'OFF'}
  Auto-remediate  : {'🔄 ON (' + ('DRY RUN' if dry_run else '⚡ LIVE') + ')' if args.remediate else 'OFF'}
  Pivot map       : {'🌐 ON' if args.pivot_map else 'OFF'}
  Services        : {', '.join(args.services)}
""")

    def _save(report: Dict, suffix: str = ""):
        tag = f"_{suffix}" if suffix else ""
        if "json" in args.output:
            save_json(report, os.path.join(args.output_dir, f"scan_{ts}{tag}.json"))
        if "html" in args.output:
            save_html(report, os.path.join(args.output_dir, f"scan_{ts}{tag}.html"))
        if "csv" in args.output:
            save_csv(report, os.path.join(args.output_dir, f"scan_{ts}{tag}.csv"))

    # ── Predict trend (pre-scan, uses existing DB) ────────────────────────────
    if args.predict_trend and db:
        pred = predict_trend(db)
        if pred:
            trend_sym = "📈" if pred["trend"] == "IMPROVING" else \
                        "📉" if pred["trend"] == "REGRESSING" else "➡️"
            print(f"  📈 TREND FORECAST:")
            print(f"     Current score  : {pred['current_score']}%")
            print(f"     Predicted ({pred['days_ahead']}d): {pred['predicted_score']}%  {trend_sym} {pred['trend']}")
            if pred.get("alert"):
                print(f"     {red('⚠️  ALERT: Score predicted to fall below 50% — take action now')}")
        else:
            print("  📈 Not enough historical data for trend forecast (need ≥3 scans)")

    # ── Check canaries ────────────────────────────────────────────────────────
    if args.check_canaries and db:
        print(f"\n  📡 Checking canaries for triggers...")
        injector  = CanaryInjector(session, args.region, db)
        triggered = injector.check_triggered()
        if triggered:
            print(f"\n  🚨 {red('CANARIES TRIGGERED!')} An attacker may be in your environment:\n")
            for t in triggered:
                print(f"     Resource : {t['canary']['resource']}")
                print(f"     Triggered: {t['triggered_at']}")
        else:
            print(f"     No canaries triggered.")

    # ── Multi-region scan ─────────────────────────────────────────────────────
    if args.all_regions:
        region_reports = SecurityScanner.run_all_regions(
            session, services=args.services, stealth=low_noise
        )
        # Merge all findings into one combined report for summary
        all_findings = []
        for r_name, r_report in region_reports.items():
            if "error" not in r_report:
                all_findings.extend(r_report.get("findings", []))
                print_summary(r_report)
                _prefix = r_name.replace("-", "_")
                if "json" in args.output:
                    save_json(r_report, os.path.join(args.output_dir,
                                                     f"scan_{ts}_{_prefix}.json"))
                if "html" in args.output:
                    save_html(r_report, os.path.join(args.output_dir,
                                                     f"scan_{ts}_{_prefix}.html"))
        print(f"\n  🌍 Multi-region total: {len(all_findings)} findings across "
              f"{len(region_reports)} regions")
        return 0

    # ── Multi-account scan ────────────────────────────────────────────────────
    elif args.multi_account:
        print("\n🌐 Multi-account mode — discovering AWS Organization accounts...")
        ma = MultiAccountScanner(session, role_name=args.role)
        all_reports = ma.scan_all(
            region=args.region, services=args.services,
            stealth=low_noise, db=db,
        )
        for acct_id, report in all_reports.items():
            if "error" not in report:
                print_summary(report)
                _save(report, suffix=acct_id)

        # Cross-account pivot map
        if args.pivot_map and HAS_NETWORKX:
            accounts = [{"Id": k, "Name": k} for k in all_reports.keys()]
            mapper   = CrossAccountPivotMapper(session, args.region)
            pivot    = mapper.map(accounts, role_name=args.role, stealth=low_noise)
            pivot_path = os.path.join(args.output_dir, f"pivot_map_{ts}.json")
            with open(pivot_path, "w") as f:
                json.dump(pivot, f, indent=2, default=str)
            print(f"\n   🌐 Pivot map → {pivot_path}")
            print(f"      {len(pivot['pivot_edges'])} cross-account paths, "
                  f"{len(pivot['chains'])} compromise chains")

    # ── Single-region scan ────────────────────────────────────────────────────
    else:
        scanner = SecurityScanner(
            session, region=args.region, services=args.services,
            stealth=low_noise,
        )
        report = scanner.run()
        print_summary(report)

        findings = report.get("findings", [])
        blast    = None

        # 🔴 Attack simulation
        if args.simulate_attacks:
            sim = AttackPathSimulator(session, args.region)
            findings = sim.simulate(findings, stealth=low_noise)
            report["findings"] = findings

            verified = [f for f in findings if f.get("verified_exploitable")]
            print(f"\n  🔴 CONFIRMED EXPLOITABLE FINDINGS:\n")
            for f in verified[:10]:
                sim_score = f.get("sim_score", 0)
                bar       = "█" * (sim_score // 10) + "░" * (10 - sim_score // 10)
                print(f"     [{f['severity']:8}] {f['service']:12} {f['resource'][:40]}")
                print(f"       Evidence    : {f.get('sim_evidence','')}")
                print(f"       Sim Score   : {sim_score:3}/100  [{bar}]")
                if f.get("proof_of_concept"):
                    print(f"       PoC         : {cyan(f['proof_of_concept'])}")

        # 🧬 Blast radius
        if args.blast_radius and HAS_NETWORKX:
            br_calc  = BlastRadiusCalculator(session, args.region, findings)
            blast    = br_calc.build_graph(low_noise=low_noise)
            report["blast_radius"] = blast
            print(f"\n  🧬 BLAST RADIUS SUMMARY:")
            print(f"     Resources mapped      : {blast['total_resources']}")
            print(f"     Compromised entries   : {blast['compromised_entry_points']}")
            print(f"     Reachable via pivots  : {blast['total_reachable']}")
            print(f"     Blast radius          : {red(str(blast['blast_radius_pct']) + '%')}")
            print(f"     Max propagated risk   : {blast.get('max_propagated_risk', 0)}/10.0")
            if blast.get("centrality_leaders"):
                print(f"     Chokepoints (by betweenness centrality):")
                for n in blast["centrality_leaders"][:3]:
                    print(f"       - {n['node'][:50]}  (BC: {n.get('betweenness',0):.4f})")
            if blast.get("highest_value_targets"):
                print(f"     Crown jewels:")
                for t in blast["highest_value_targets"][:3]:
                    print(f"       - [{t['service']}] {t['id'][:50]}  "
                          f"(propagated risk: {t.get('propagated_risk', t.get('target_value_score', 0))})")

        # ⏱️ Time-to-breach breakdown
        if args.time_to_breach:
            print(f"\n  ⏱️  TIME-TO-BREACH BREAKDOWN:\n")
            sorted_f = sorted(findings, key=lambda x: x.get("ttb_days", 999))
            for f in sorted_f[:20]:
                days   = f.get("ttb_days", "?")
                urg    = f.get("ttb_urgency", "")
                color  = red if urg == "IMMEDIATE" else yellow if urg in ("CRITICAL","HIGH") else green
                print(f"     {color(f'{days:>6}d')}  {urg:9}  [{f['severity']:8}]  "
                      f"{f['service']:10}  {f['resource'][:35]}")

        # 📋 Executive breach report
        if args.executive_report:
            exec_report = generate_executive_report(report, blast=blast)
            print(exec_report)
            exec_path   = os.path.join(args.output_dir, f"executive_report_{ts}.txt")
            with open(exec_path, "w") as ef:
                ef.write(exec_report)
            print(f"   📋 Executive report → {exec_path}")

        # 🔄 Auto-remediation
        if args.remediate and db:
            remediator = AutoRemediator(session, args.region, db)
            rem_results = remediator.remediate_all(
                findings,
                dry_run=dry_run,
                safe_only=not args.remediate_all,
            )
            report["remediation"] = rem_results

        # 📡 Canary injection
        if args.inject_canaries and db:
            injector = CanaryInjector(session, args.region, db)
            canaries = injector.inject_all(findings, dry_run=dry_run)
            report["canaries_injected"] = canaries

        # 📊 Diff
        if args.diff:
            try:
                with open(args.diff) as f:
                    old_report = json.load(f)
                differ = ScanDiffEngine()
                diff   = differ.diff(old_report, report)
                differ.print_diff(diff)
                diff_path = os.path.join(args.output_dir, f"diff_{ts}.json")
                with open(diff_path, "w") as f:
                    json.dump(diff, f, indent=2, default=str)
                print(f"   📊 Diff  → {diff_path}")
            except FileNotFoundError:
                print(f"  ✗ Diff file not found: {args.diff}")
            except Exception as e:
                print(f"  ✗ Diff error: {e}")

        # Save DB
        if db:
            scan_id = db.save(report)
            trends  = db.get_trends()
            print(f"\n  📂 Scan saved to DB (id={scan_id})  |  "
                  f"{len(trends)} total scan(s) in cloudguard.db")

            # Post-scan trend prediction
            pred = predict_trend(db)
            if pred:
                trend_sym = "📈" if pred["trend"]=="IMPROVING" else \
                            "📉" if pred["trend"]=="REGRESSING" else "➡️"
                print(f"  {trend_sym} Score trend: {pred['current_score']}% → "
                      f"predicted {pred['predicted_score']}% in {pred['days_ahead']} days "
                      f"({pred['trend']})")
                if pred.get("alert"):
                    print(f"  {red('⚠️  Score predicted to breach 50% threshold!')}")

        print(f"\n  📂 Reports → {args.output_dir}/")
        _save(report)

    print(f"\n  ✅ Done!\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())