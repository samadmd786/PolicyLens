#!/usr/bin/env python3
"""Export IAM role policies to a JSON file for review in PolicyLens.

Runs entirely on YOUR machine with YOUR AWS CLI profile. It makes only
read-only IAM calls (iam:List*, iam:Get*). Your credentials never leave your
computer, and PolicyLens (the web app) never sees them. Upload the exported
JSON file to the app to review policies from your real account, one at a time.

Read-only permissions used:
    iam:ListRoles, iam:ListRolePolicies, iam:GetRolePolicy,
    iam:ListAttachedRolePolicies, iam:GetPolicy, iam:GetPolicyVersion

Usage:
    python scripts/fetch_policies.py --profile myprofile --out my-policies.json
    AWS_PROFILE=myprofile python scripts/fetch_policies.py

Output is a JSON array; each entry is:
    {
      "role_name": "...",
      "policy_name": "...",
      "policy_type": "inline" | "managed",
      "policy_arn": "..." | null,
      "policy_document": { ...IAM policy JSON... }
    }
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
from typing import Any, Callable

Entry = dict[str, Any]


def _paginate(fn: Callable[..., dict[str, Any]], key: str, **kwargs: Any) -> list[Any]:
    """Collect all items across IAM's Marker/IsTruncated pagination."""
    items: list[Any] = []
    marker: str | None = None
    while True:
        call_kwargs = dict(kwargs)
        if marker:
            call_kwargs["Marker"] = marker
        resp = fn(**call_kwargs)
        items.extend(resp.get(key, []))
        if resp.get("IsTruncated"):
            marker = resp.get("Marker")
        else:
            break
    return items


def _decode_document(doc: Any) -> Any:
    """Normalize an IAM policy document to a dict.

    IAM sometimes returns the document as a URL-encoded JSON string and
    sometimes as a parsed dict, depending on the call and botocore version.
    Handle both so downstream always gets a dict.
    """
    if isinstance(doc, str):
        return json.loads(urllib.parse.unquote(doc))
    return doc


def _entry(
    role_name: str,
    policy_name: str,
    policy_type: str,
    document: Any,
    policy_arn: str | None = None,
) -> Entry:
    return {
        "role_name": role_name,
        "policy_name": policy_name,
        "policy_type": policy_type,
        "policy_arn": policy_arn,
        "policy_document": _decode_document(document),
    }


def fetch_export(iam: Any) -> list[Entry]:
    """Build the export array from an IAM client (real or mocked).

    Pure read-only. Kept free of argparse/boto3 setup so it is unit-testable
    with a mock client.
    """
    entries: list[Entry] = []
    roles = _paginate(iam.list_roles, "Roles")
    for role in roles:
        role_name = role["RoleName"]

        # Inline policies live on the role itself.
        for policy_name in _paginate(
            iam.list_role_policies, "PolicyNames", RoleName=role_name
        ):
            resp = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            entries.append(
                _entry(role_name, policy_name, "inline", resp["PolicyDocument"])
            )

        # Managed policies are attached by ARN; fetch the default version doc.
        for attached in _paginate(
            iam.list_attached_role_policies, "AttachedPolicies", RoleName=role_name
        ):
            arn = attached["PolicyArn"]
            policy = iam.get_policy(PolicyArn=arn)["Policy"]
            version_id = policy["DefaultVersionId"]
            version = iam.get_policy_version(PolicyArn=arn, VersionId=version_id)
            entries.append(
                _entry(
                    role_name,
                    attached.get("PolicyName", arn.split("/")[-1]),
                    "managed",
                    version["PolicyVersion"]["Document"],
                    policy_arn=arn,
                )
            )

    return entries


def _build_client(profile: str | None, region: str | None) -> Any:
    """Create a read-only IAM client. boto3 imported lazily for offline tests."""
    import boto3  # noqa: PLC0415

    session = boto3.Session(profile_name=profile, region_name=region)
    return session.client("iam")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Export IAM role policies to JSON for PolicyLens (read-only)."
    )
    parser.add_argument("--profile", help="AWS CLI profile name to use.")
    parser.add_argument("--region", help="AWS region (IAM is global; optional).")
    parser.add_argument(
        "--out",
        default="policylens-policies.json",
        help="Output file path (default: policylens-policies.json).",
    )
    args = parser.parse_args(argv)

    try:
        iam = _build_client(args.profile, args.region)
        entries = fetch_export(iam)
    except Exception as exc:  # surface a clean message, no stack trace
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(entries, fh, indent=2)

    roles = len({e["role_name"] for e in entries})
    print(f"Exported {len(entries)} policies across {roles} roles to {args.out}")
    print("Your credentials stayed on this machine. Upload this file to PolicyLens.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
