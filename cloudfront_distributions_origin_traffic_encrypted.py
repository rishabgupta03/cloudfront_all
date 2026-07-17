#!/usr/bin/env python3
"""
Control: CloudFront Distribution Encrypts Traffic to Custom Origins
------------------------------------------------------------------------
CloudFront is a global service (single API endpoint - us-east-1).
Origins.Items[] is included directly in the list_distributions summary.

Each origin is either:
  - S3OriginConfig    -> CloudFront always talks to S3 over HTTPS natively.
                         No OriginProtocolPolicy field. Not applicable here.
  - CustomOriginConfig -> has OriginProtocolPolicy:
        https-only   -> origin traffic always encrypted
        http-only    -> origin traffic never encrypted
        match-viewer -> origin traffic is ONLY encrypted if the viewer also
                         connected over HTTPS. A plain-HTTP viewer request
                         means the origin leg is plaintext too, so this does
                         NOT guarantee encryption and is treated as
                         NON_COMPLIANT here.

Per distribution:
  - No custom origins at all (S3-only)   -> SKIPPED (not applicable)
  - All custom origins use https-only     -> COMPLIANT
  - Any custom origin uses http-only/match-viewer -> NON_COMPLIANT
    (named explicitly in evidence)
"""

import boto3
import argparse
import csv
from tqdm import tqdm
from botocore.exceptions import ClientError

CONTROL_NAME = "CloudFront Distribution Encrypts Traffic to Custom Origins"
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


def evaluate_custom_origin_encryption(dist: dict):
    """
    Returns (status, evidence). Only CustomOriginConfig origins are
    evaluated; S3OriginConfig origins are always encrypted natively and
    are excluded from the check entirely.

    The SKIPPED evidence now lists each origin's domain name and
    detected type, so a "not applicable" result is verifiable at a
    glance instead of a bare "no custom origins" message - if every
    origin genuinely is S3OriginConfig, that will be visible directly
    in the CSV rather than requiring a separate AWS CLI check.
    """
    origins = dist.get("Origins", {}).get("Items", []) or []

    if not origins:
        return "SKIPPED", "Distribution has no origins defined at all (unexpected - check manually)"

    custom_origins = [o for o in origins if "CustomOriginConfig" in o]

    if not custom_origins:
        origin_summary = ", ".join(
            f"{o.get('Id', 'unknown')} ({o.get('DomainName', 'unknown-domain')})"
            for o in origins
        )
        return (
            "SKIPPED",
            f"No custom origins present - all {len(origins)} origin(s) are native S3 "
            f"(S3OriginConfig), not applicable: {origin_summary}"
        )

    violations = []
    compliant_origins = []

    for origin in custom_origins:
        origin_id = origin.get("Id", "unknown-origin")
        policy = origin.get("CustomOriginConfig", {}).get("OriginProtocolPolicy", "http-only")

        if policy == "https-only":
            compliant_origins.append(f"{origin_id} (https-only)")
        else:
            violations.append(f"{origin_id} (policy={policy})")

    if violations:
        return (
            "NON_COMPLIANT",
            f"{len(violations)}/{len(custom_origins)} custom origin(s) not fully "
            f"encrypted: {', '.join(violations)}"
        )

    return (
        "COMPLIANT",
        f"All {len(custom_origins)} custom origin(s) use https-only: "
        + ", ".join(compliant_origins)
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

        status, evidence = evaluate_custom_origin_encryption(dist)

        if status == "COMPLIANT":
            compliant += 1
        elif status == "NON_COMPLIANT":
            non_compliant += 1
        else:
            skipped += 1

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
    filename = f"cloudfront_custom_origin_encryption_{account_id}.csv"
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
