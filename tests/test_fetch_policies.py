"""Tests for scripts/fetch_policies.py with a mocked IAM client.

No live AWS. A hand-rolled fake IAM client returns canned, paginated responses
so we can assert pagination handling and the export JSON shape.
"""

from __future__ import annotations

import json
import sys
import urllib.parse
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import fetch_policies  # noqa: E402

INLINE_DOC = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
}
MANAGED_DOC = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}],
}


class FakeIam:
    """Minimal fake IAM client with two-page list_roles pagination."""

    def list_roles(self, **kwargs):
        # Page 1 is truncated; page 2 (Marker set) is the last page.
        if kwargs.get("Marker") == "page2":
            return {"Roles": [{"RoleName": "role-b"}], "IsTruncated": False}
        return {
            "Roles": [{"RoleName": "role-a"}],
            "IsTruncated": True,
            "Marker": "page2",
        }

    def list_role_policies(self, RoleName, **kwargs):
        # role-a has one inline policy; role-b has none.
        if RoleName == "role-a":
            return {"PolicyNames": ["inline-a"], "IsTruncated": False}
        return {"PolicyNames": [], "IsTruncated": False}

    def get_role_policy(self, RoleName, PolicyName):
        # Return a URL-encoded string to exercise _decode_document.
        encoded = urllib.parse.quote(json.dumps(INLINE_DOC))
        return {
            "RoleName": RoleName,
            "PolicyName": PolicyName,
            "PolicyDocument": encoded,
        }

    def list_attached_role_policies(self, RoleName, **kwargs):
        # role-b has one managed policy; role-a has none.
        if RoleName == "role-b":
            return {
                "AttachedPolicies": [
                    {
                        "PolicyName": "managed-b",
                        "PolicyArn": "arn:aws:iam::123456789012:policy/managed-b",
                    }
                ],
                "IsTruncated": False,
            }
        return {"AttachedPolicies": [], "IsTruncated": False}

    def get_policy(self, PolicyArn):
        return {"Policy": {"Arn": PolicyArn, "DefaultVersionId": "v3"}}

    def get_policy_version(self, PolicyArn, VersionId):
        # Return an already-parsed dict document to exercise the other branch.
        assert VersionId == "v3"
        return {"PolicyVersion": {"Document": MANAGED_DOC, "VersionId": VersionId}}


def test_pagination_collects_all_roles():
    iam = FakeIam()
    roles = fetch_policies._paginate(iam.list_roles, "Roles")
    assert [r["RoleName"] for r in roles] == ["role-a", "role-b"]


def test_export_shape_and_types():
    entries = fetch_policies.fetch_export(FakeIam())

    # One inline (role-a) + one managed (role-b).
    assert len(entries) == 2
    by_type = {e["policy_type"]: e for e in entries}
    assert set(by_type) == {"inline", "managed"}

    inline = by_type["inline"]
    assert inline["role_name"] == "role-a"
    assert inline["policy_name"] == "inline-a"
    assert inline["policy_arn"] is None
    assert inline["policy_document"] == INLINE_DOC  # decoded from URL-encoding

    managed = by_type["managed"]
    assert managed["role_name"] == "role-b"
    assert managed["policy_name"] == "managed-b"
    assert managed["policy_arn"] == "arn:aws:iam::123456789012:policy/managed-b"
    assert managed["policy_document"] == MANAGED_DOC


def test_decode_document_handles_string_and_dict():
    encoded = urllib.parse.quote(json.dumps(INLINE_DOC))
    assert fetch_policies._decode_document(encoded) == INLINE_DOC
    assert fetch_policies._decode_document(MANAGED_DOC) == MANAGED_DOC


def test_export_documents_feed_run_checks():
    # The exported documents must be directly analyzable by Layer 1.
    from backend.checks import run_checks

    entries = fetch_policies.fetch_export(FakeIam())
    for entry in entries:
        findings = run_checks(entry["policy_document"])
        assert isinstance(findings, list)


def test_main_writes_file(tmp_path, monkeypatch):
    out = tmp_path / "export.json"
    monkeypatch.setattr(fetch_policies, "_build_client", lambda profile, region: FakeIam())
    rc = fetch_policies.main(["--out", str(out)])
    assert rc == 0
    data = json.loads(out.read_text())
    assert len(data) == 2
    assert {e["policy_type"] for e in data} == {"inline", "managed"}
