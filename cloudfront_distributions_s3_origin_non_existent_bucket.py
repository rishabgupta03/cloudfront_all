#!/usr/bin/env python3
"""
Control: CloudFront Distribution S3 Origins Reference Existing Buckets
------------------------------------------------------------------------
CloudFront is a global service (single API endpoint - us-east-1), but
this control is a CROSS-SERVICE check: CloudFront's own API has no idea
whether the S3 bucket an origin points to still exists. A dangling
S3 origin (bucket deleted, DNS name still referenced) is a known
subdomain/bucket-takeover risk, so this is checked against S3 directly.

Unit of evaluation is the ORIGIN, not the distribution - a distribution
can have multiple S3 origins pointing at different buckets. A
distribution with no S3OriginConfig origins contributes zero rows
(not applicable), same outcome as other "not applicable" cases in the
other CloudFront scripts, just without a placeholder row since the
natural unit here is finer-grained than the distribution.

Per S3 origin:
  head_bucket succeeds              -> COMPLIANT (bucket exists)
  head_bucket fails 404/NoSuchBucket -> NON_COMPLIANT (dangling origin)
  head_bucket fails 403/AccessDenied -> SKIPPED (can't confirm either way -
                                         bucket may exist in another account)
  other errors                       -> SKIPPED (classified error)
"""

import re
import boto3
import argparse
import csv
from tqdm import tqdm
from botocore.exceptions import ClientError

CONTROL_NAME = "CloudFront Distribution S3 Origins Reference Existing Buckets"
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


def extract_bucket_name(domain_name: str) -> str:
    """
    Parses the bucket name out of an S3 origin's DomainName, e.g.
    'my-bucket.s3.amazonaws.com' or 'my-bucket.s3.ap-south-1.amazonaws.com'
    -> 'my-bucket'
    """
    match = re.match(r"^([^.]+)\.s3[.-]", domain_name)
    if match:
        return match.group(1)
    return domain_name.split(".")[0]


def collect_s3_origins(distributions):
    """
    Flattens all distributions down to a list of individual S3 origins
    to evaluate, since the unit of compliance here is the origin.
    """
    flat = []
    for dist in distributions:
        dist_id = dist.get("Id", "N/A")
        origins = dist.get("Origins", {}).get("Items", []) or []
        for origin in origins:
            if "S3OriginConfig" in origin:
                flat.append({
                    "DistributionId": dist_id,
                    "OriginId": origin.get("Id", "unknown-origin"),
                    "DomainName": origin.get("DomainName", ""),
                })
    return flat


def check_bucket_exists(s3_client, bucket_name: str):
    """
    Returns (status, evidence) after calling head_bucket for the bucket.
    """
    try:
        s3_client.head_bucket(Bucket=bucket_name)
        return "COMPLIANT", f"Bucket '{bucket_name}' exists"
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        http_status = e.response.get("ResponseMetadata", {}).get("HTTPStatusCode", "")

        if code in ("404", "NoSuchBucket") or http_status == 404:
            return (
                "NON_COMPLIANT",
                f"Bucket '{bucket_name}' does not exist - dangling origin "
                f"(potential subdomain takeover risk)"
            )

        if code in ("403", "AccessDenied") or http_status == 403:
            return (
                "SKIPPED",
                f"Access denied checking bucket '{bucket_name}' - cannot confirm "
                f"existence (may belong to another account)"
            )

        return "SKIPPED", classify_error(e)


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

    cf_client = session.client("cloudfront", region_name=GLOBAL_REGION)
    s3_client = session.client("s3", region_name=GLOBAL_REGION)

    try:
        paginator = cf_client.get_paginator("list_distributions")
        distributions = []
        for page in paginator.paginate():
            items = page.get("DistributionList", {}).get("Items", [])
            distributions.extend(items)
    except ClientError as e:
        skipped += 1
        results.append({
            "DistributionId": "N/A",
            "OriginId": "N/A",
            "BucketName": "N/A",
            "Status": "SKIPPED",
            "Evidence": classify_error(e)
        })
        return results, total_checked, compliant, non_compliant, skipped, account_id

    s3_origins = collect_s3_origins(distributions)
    print(f"\nS3 Origins to Verify: {len(s3_origins)}\n")

    for origin_info in tqdm(s3_origins, desc="Verifying S3 Origin Buckets"):
        total_checked += 1
        bucket_name = extract_bucket_name(origin_info["DomainName"])

        status, evidence = check_bucket_exists(s3_client, bucket_name)

        if status == "COMPLIANT":
            compliant += 1
        elif status == "NON_COMPLIANT":
            non_compliant += 1
        else:
            skipped += 1

        results.append({
            "DistributionId": origin_info["DistributionId"],
            "OriginId": origin_info["OriginId"],
            "BucketName": bucket_name,
            "Status": status,
            "Evidence": evidence
        })

    return results, total_checked, compliant, non_compliant, skipped, account_id


# ==================================================
# CSV
# ==================================================
def write_csv(results, account_id):
    filename = f"cloudfront_s3_origin_bucket_existence_{account_id}.csv"
    fieldnames = ["Account", "DistributionId", "OriginId", "BucketName", "Status", "Evidence"]

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            writer.writerow({
                "Account": account_id,
                "DistributionId": row["DistributionId"],
                "OriginId": row["OriginId"],
                "BucketName": row["BucketName"],
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