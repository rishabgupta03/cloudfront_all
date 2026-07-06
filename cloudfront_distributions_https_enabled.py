#!/usr/bin/env python3
"""
Control: CloudFront Distribution Has Viewer Protocol Policy Set to
HTTPS Only or Redirect to HTTPS
------------------------------------------------------------------------
CloudFront is a global service (single API endpoint - us-east-1).
ViewerProtocolPolicy is set per cache behavior (DefaultCacheBehavior and
each entry in CacheBehaviors.Items[]), with possible values:
  - allow-all
  - https-only
  - redirect-to-https

Unlike a "default behavior only" check, this control is evaluated across
ALL cache behaviors (default + additional path patterns). If even one
path-specific behavior allows plain HTTP (allow-all), that path is still
exploitable regardless of what the default behavior enforces. So the
distribution is only COMPLIANT if every behavior enforces HTTPS.
"""

import boto3
import argparse
import csv
from tqdm import tqdm
from botocore.exceptions import ClientError

CONTROL_NAME = (
    "CloudFront Distribution Has Viewer Protocol Policy Set to "
    "HTTPS Only or Redirect to HTTPS"
)
GLOBAL_REGION = "us-east-1"  # CloudFront API is only available here
SECURE_POLICIES = {"https-only", "redirect-to-https"}

# ==================================================
# AUTH
# ==================================================
def get_session(role_arn=None):
    if role_arn:
        base = boto3.Session()
        sts = base.client("sts")
        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="control-audit"
        )
        creds = assumed["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]
        )
    return boto3.Session()


def get_account_id(session):
    return session.client("sts").get_caller_identity()["Account"]


# ==================================================
# REGIONS
# ==================================================
# CloudFront is global - single API endpoint. Kept as a no-op function so
# the script structure stays consistent with regional controls.
def get_regions(session):
    return [GLOBAL_REGION]


# ==================================================
# HELPERS
# ==================================================
def classify_error(e: ClientError) -> str:
    """Map a ClientError to a short, human-readable skip reason."""
    code = e.response.get("Error", {}).get("Code", "Unknown")
    reasons = {
        "AccessDenied": "Access denied - insufficient IAM permissions",
        "AccessDeniedException": "Access denied - insufficient IAM permissions",
        "UnrecognizedClientException": "Auth/token issue - unable to authenticate",
        "ExpiredToken": "Session token expired",
        "Throttling": "Throttled by AWS API - skipped",
        "InvalidClientTokenId": "Invalid credentials",
    }
    return reasons.get(code, f"Skipped due to error [{code}]")


def evaluate_viewer_protocol_policy(dist: dict):
    """
    Returns (status, evidence). Checks DefaultCacheBehavior plus every
    additional cache behavior. Any behavior with allow-all fails the
    whole distribution, and is named explicitly in the evidence.
    """
    violations = []

    default_behavior = dist.get("DefaultCacheBehavior", {}) or {}
    default_policy = default_behavior.get("ViewerProtocolPolicy", "allow-all")
    if default_policy not in SECURE_POLICIES:
        violations.append(f"DefaultCacheBehavior (policy={default_policy})")

    additional_behaviors = dist.get("CacheBehaviors", {}).get("Items", []) or []
    for behavior in additional_behaviors:
        path_pattern = behavior.get("PathPattern", "unknown-path")
        policy = behavior.get("ViewerProtocolPolicy", "allow-all")
        if policy not in SECURE_POLICIES:
            violations.append(f"PathPattern '{path_pattern}' (policy={policy})")

    total_behaviors = 1 + len(additional_behaviors)

    if violations:
        return (
            "NON_COMPLIANT",
            f"{len(violations)}/{total_behaviors} cache behavior(s) allow HTTP: "
            + "; ".join(violations)
        )

    return (
        "COMPLIANT",
        f"All {total_behaviors} cache behavior(s) enforce HTTPS "
        f"(https-only or redirect-to-https)"
    )


# ==================================================
# CONTROL LOGIC
# ==================================================
def check_control(session):
    account_id = get_account_id(session)

    results = []
    total_checked = 0
    compliant = 0
    non_compliant = 0
    skipped = 0

    client = session.client("cloudfront", region_name=GLOBAL_REGION)

    try:
        paginator = client.get_paginator("list_distributions")
        distributions = []
        for page in paginator.paginate():
            items = page.get("DistributionList", {}).get("Items", [])
            distributions.extend(items)
    except ClientError as e:
        skipped += 1
        results.append({
            "Region": "global",
            "DistributionId": "N/A",
            "DistributionArn": "N/A",
            "Status": "SKIPPED",
            "Evidence": classify_error(e)
        })
        return results, total_checked, compliant, non_compliant, skipped, account_id

    print(f"\nDistributions to Scan: {len(distributions)}\n")

    for dist in tqdm(distributions, desc="Scanning CloudFront Distributions"):
        total_checked += 1
        dist_id = dist.get("Id", "N/A")
        dist_arn = dist.get("ARN", "N/A")

        status, evidence = evaluate_viewer_protocol_policy(dist)

        if status == "COMPLIANT":
            compliant += 1
        else:
            non_compliant += 1

        results.append({
            "Region": "global",
            "DistributionId": dist_id,
            "DistributionArn": dist_arn,
            "Status": status,
            "Evidence": evidence
        })

    return results, total_checked, compliant, non_compliant, skipped, account_id


# ==================================================
# CSV
# ==================================================
def write_csv(results, account_id):
    filename = f"cloudfront_viewer_protocol_policy_{account_id}.csv"
    fieldnames = ["Account", "Region", "DistributionId", "DistributionArn", "Status", "Evidence"]

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            writer.writerow({
                "Account": account_id,
                "Region": row["Region"],
                "DistributionId": row["DistributionId"],
                "DistributionArn": row["DistributionArn"],
                "Status": row["Status"],
                "Evidence": row["Evidence"]
            })

    return filename


# ==================================================
# MAIN
# ==================================================
def main():
    parser = argparse.ArgumentParser(description=CONTROL_NAME)
    parser.add_argument("-R", "--role-arn", help="IAM Role ARN to assume", default=None)
    args = parser.parse_args()

    session = get_session(args.role_arn)

    results, total_checked, compliant, non_compliant, skipped, account_id = check_control(session)
    overall_status = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"

    csv_file = write_csv(results, account_id)

    print("\n" + "=" * 60)
    print(f"CONTROL: {CONTROL_NAME}")
    print(f"ACCOUNT: {account_id}")
    print("=" * 60)
    print(f"Total Checked   : {total_checked}")
    print(f"Compliant       : {compliant}")
    print(f"Non-Compliant   : {non_compliant}")
    print(f"Skipped         : {skipped}")
    print(f"Overall Status  : {overall_status}")
    print("=" * 60)
    print(f"CSV report generated: {csv_file}\n")


if __name__ == "__main__":
    main()