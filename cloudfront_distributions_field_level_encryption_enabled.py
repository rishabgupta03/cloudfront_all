#!/usr/bin/env python3
"""
Control: CloudFront Distribution Has Field-Level Encryption Enabled
------------------------------------------------------------------------
CloudFront is a global service (single API endpoint - us-east-1).
Field-level encryption is configured per cache behavior via
FieldLevelEncryptionId (empty string = not configured).

Compliance is evaluated against DefaultCacheBehavior.FieldLevelEncryptionId,
since that behavior handles all traffic not matched by a more specific
path pattern. Additional cache behaviors (if present) are inspected too,
and their FLE status is surfaced in Evidence for visibility - but it does
NOT affect the Status decision. That's a policy call, not baked in here.
"""

import boto3
import argparse
import csv
from tqdm import tqdm
from botocore.exceptions import ClientError

CONTROL_NAME = "CloudFront Distribution Has Field-Level Encryption Enabled"
GLOBAL_REGION = "us-east-1"  # CloudFront API is only available here

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


def evaluate_field_level_encryption(dist: dict):
    """
    Returns (status, evidence).
    Compliance is based on DefaultCacheBehavior.FieldLevelEncryptionId.
    Additional cache behaviors are summarized in evidence only, for
    visibility - they do not change the Status.
    """
    default_behavior = dist.get("DefaultCacheBehavior", {}) or {}
    default_fle_id = default_behavior.get("FieldLevelEncryptionId", "")

    additional_behaviors = dist.get("CacheBehaviors", {}).get("Items", []) or []
    additional_total = len(additional_behaviors)
    additional_with_fle = sum(
        1 for b in additional_behaviors if b.get("FieldLevelEncryptionId", "")
    )

    additional_note = ""
    if additional_total > 0:
        additional_note = (
            f" | {additional_with_fle}/{additional_total} additional "
            f"cache behavior(s) also have field-level encryption configured"
        )

    if default_fle_id:
        return (
            "COMPLIANT",
            f"Default cache behavior uses field-level encryption config: "
            f"{default_fle_id}{additional_note}"
        )

    return (
        "NON_COMPLIANT",
        f"Default cache behavior does not have field-level encryption configured{additional_note}"
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

        status, evidence = evaluate_field_level_encryption(dist)

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
    filename = f"cloudfront_field_level_encryption_{account_id}.csv"
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