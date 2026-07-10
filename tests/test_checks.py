"""Tests for the Layer 1 deterministic engine.

Fully offline. No AWS, no LLM. Every rule gets a positive case (it fires) and
a negative case (it stays quiet on a clean statement), plus edge cases for
string-vs-list fields, single-statement documents, missing fields, and
malformed JSON.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# Make backend/ importable without installing a package.
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from backend.checks import (  # noqa: E402
    PolicyParseError,
    parse_policy,
    rank,
    run_checks,
    run_checks_safe,
)

SAMPLES = REPO_ROOT / "samples"


def rule_ids(findings: list[dict]) -> list[str]:
    return [f["rule_id"] for f in findings]


def rules_for(findings: list[dict], index: int) -> set[str]:
    return {f["rule_id"] for f in findings if f["statement_index"] == index}


def wrap(statement: dict) -> dict:
    return {"Version": "2012-10-17", "Statement": [statement]}


# --- Rule 1: WILDCARD_ACTION ----------------------------------------------


def test_wildcard_action_star_is_critical():
    findings = run_checks(
        wrap({"Effect": "Allow", "Action": "*", "Resource": "*"})
    )
    hit = [f for f in findings if f["rule_id"] == "WILDCARD_ACTION"]
    assert hit and hit[0]["severity"] == "CRITICAL"


def test_wildcard_action_service_star_is_high():
    findings = run_checks(
        wrap({"Effect": "Allow", "Action": "s3:*", "Resource": "*"})
    )
    hit = [f for f in findings if f["rule_id"] == "WILDCARD_ACTION"]
    assert hit and hit[0]["severity"] == "HIGH"


def test_wildcard_action_negative():
    findings = run_checks(
        wrap(
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::b/*",
            }
        )
    )
    assert "WILDCARD_ACTION" not in rule_ids(findings)


# --- Rule 2: WILDCARD_RESOURCE --------------------------------------------


def test_wildcard_resource_positive_on_write():
    findings = run_checks(
        wrap({"Effect": "Allow", "Action": "s3:PutObject", "Resource": "*"})
    )
    assert "WILDCARD_RESOURCE" in rule_ids(findings)


def test_wildcard_resource_skipped_for_read_only():
    findings = run_checks(
        wrap({"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"})
    )
    assert "WILDCARD_RESOURCE" not in rule_ids(findings)


def test_wildcard_resource_negative_scoped():
    findings = run_checks(
        wrap(
            {
                "Effect": "Allow",
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::b/*",
            }
        )
    )
    assert "WILDCARD_RESOURCE" not in rule_ids(findings)


# --- Rule 3: NO_CONDITION_SENSITIVE ---------------------------------------


def test_no_condition_sensitive_positive():
    findings = run_checks(
        wrap(
            {
                "Effect": "Allow",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*",
            }
        )
    )
    assert "NO_CONDITION_SENSITIVE" in rule_ids(findings)


def test_no_condition_sensitive_negative_with_condition():
    findings = run_checks(
        wrap(
            {
                "Effect": "Allow",
                "Action": "kms:Decrypt",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"kms:ViaService": "s3.us-east-1.amazonaws.com"}
                },
            }
        )
    )
    assert "NO_CONDITION_SENSITIVE" not in rule_ids(findings)


# --- Rule 4: PASSROLE_UNCONSTRAINED ---------------------------------------


def test_passrole_unconstrained_positive():
    findings = run_checks(
        wrap({"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"})
    )
    hit = [f for f in findings if f["rule_id"] == "PASSROLE_UNCONSTRAINED"]
    assert hit and hit[0]["severity"] == "CRITICAL"


def test_passrole_negative_with_passedtoservice_condition():
    findings = run_checks(
        wrap(
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "iam:PassedToService": "lambda.amazonaws.com"
                    }
                },
            }
        )
    )
    assert "PASSROLE_UNCONSTRAINED" not in rule_ids(findings)


def test_passrole_negative_with_scoped_resource():
    findings = run_checks(
        wrap(
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "arn:aws:iam::123456789012:role/app-exec",
            }
        )
    )
    assert "PASSROLE_UNCONSTRAINED" not in rule_ids(findings)


# --- Rule 5: NOTACTION_ALLOW ----------------------------------------------


def test_notaction_allow_positive():
    findings = run_checks(
        wrap({"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"})
    )
    assert "NOTACTION_ALLOW" in rule_ids(findings)


def test_notaction_allow_negative_on_deny():
    findings = run_checks(
        wrap({"Effect": "Deny", "NotAction": "s3:*", "Resource": "*"})
    )
    assert "NOTACTION_ALLOW" not in rule_ids(findings)


# --- Rule 6: NOTRESOURCE_ALLOW --------------------------------------------


def test_notresource_allow_positive():
    findings = run_checks(
        wrap(
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "NotResource": "arn:aws:s3:::secret/*",
            }
        )
    )
    assert "NOTRESOURCE_ALLOW" in rule_ids(findings)


def test_notresource_allow_negative():
    findings = run_checks(
        wrap(
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::b/*",
            }
        )
    )
    assert "NOTRESOURCE_ALLOW" not in rule_ids(findings)


# --- Rule 7: ADMIN_EQUIVALENT ---------------------------------------------


def test_admin_equivalent_positive():
    findings = run_checks(
        wrap(
            {
                "Effect": "Allow",
                "Action": [
                    "iam:AttachUserPolicy",
                    "iam:CreatePolicyVersion",
                ],
                "Resource": "*",
            }
        )
    )
    hit = [f for f in findings if f["rule_id"] == "ADMIN_EQUIVALENT"]
    assert hit and hit[0]["severity"] == "CRITICAL"


def test_admin_equivalent_negative_scoped_resource():
    findings = run_checks(
        wrap(
            {
                "Effect": "Allow",
                "Action": "iam:AttachUserPolicy",
                "Resource": "arn:aws:iam::123456789012:user/app",
            }
        )
    )
    assert "ADMIN_EQUIVALENT" not in rule_ids(findings)


# --- Rule 8: MISSING_MFA_CONDITION ----------------------------------------


def test_missing_mfa_positive():
    findings = run_checks(
        wrap({"Effect": "Allow", "Action": "iam:CreateUser", "Resource": "*"})
    )
    assert "MISSING_MFA_CONDITION" in rule_ids(findings)


def test_missing_mfa_negative_with_mfa_condition():
    findings = run_checks(
        wrap(
            {
                "Effect": "Allow",
                "Action": "iam:CreateUser",
                "Resource": "*",
                "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
            }
        )
    )
    assert "MISSING_MFA_CONDITION" not in rule_ids(findings)


# --- Rule 9: OVERBROAD_PRINCIPAL ------------------------------------------


def test_overbroad_principal_positive_string():
    findings = run_checks(
        wrap(
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::b/*",
            }
        )
    )
    hit = [f for f in findings if f["rule_id"] == "OVERBROAD_PRINCIPAL"]
    assert hit and hit[0]["severity"] == "CRITICAL"


def test_overbroad_principal_positive_aws_dict():
    findings = run_checks(
        wrap(
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::b/*",
            }
        )
    )
    assert "OVERBROAD_PRINCIPAL" in rule_ids(findings)


def test_overbroad_principal_negative_with_condition():
    findings = run_checks(
        wrap(
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::b/*",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": "123456789012"}
                },
            }
        )
    )
    assert "OVERBROAD_PRINCIPAL" not in rule_ids(findings)


def test_overbroad_principal_negative_scoped_principal():
    findings = run_checks(
        wrap(
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::b/*",
            }
        )
    )
    assert "OVERBROAD_PRINCIPAL" not in rule_ids(findings)


# --- Rule 10: STALE_SID_OR_EMPTY ------------------------------------------


def test_empty_statement_positive():
    findings = run_checks(wrap({"Sid": "Nothing", "Effect": "Allow"}))
    assert "STALE_SID_OR_EMPTY" in rule_ids(findings)


def test_duplicate_sid_positive():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Dup",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::b/*",
            },
            {
                "Sid": "Dup",
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": "arn:aws:s3:::b",
            },
        ],
    }
    dup = [f for f in run_checks(policy) if f["rule_id"] == "STALE_SID_OR_EMPTY"]
    assert dup and any("Duplicate Sid" in f["detail"] for f in dup)


def test_stale_sid_negative_clean():
    findings = run_checks(SAMPLES.joinpath("01_clean_s3_readonly.json").read_text())
    assert "STALE_SID_OR_EMPTY" not in rule_ids(findings)


# --- Edge cases -----------------------------------------------------------


def test_action_as_string_vs_list_equivalent():
    as_string = run_checks(
        wrap({"Effect": "Allow", "Action": "*", "Resource": "*"})
    )
    as_list = run_checks(
        wrap({"Effect": "Allow", "Action": ["*"], "Resource": "*"})
    )
    assert rule_ids(as_string) == rule_ids(as_list)


def test_single_statement_not_wrapped_in_list():
    policy = {
        "Version": "2012-10-17",
        "Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"},
    }
    findings = run_checks(policy)
    assert "WILDCARD_ACTION" in rule_ids(findings)


def test_missing_optional_fields_no_crash():
    # No Version, no Sid, no Condition, Action-only statement.
    findings = run_checks({"Statement": [{"Effect": "Allow", "Action": "s3:*"}]})
    assert "WILDCARD_ACTION" in rule_ids(findings)


def test_malformed_json_returns_clean_error():
    raw = SAMPLES.joinpath("06_malformed.json").read_text()
    result = run_checks_safe(raw)
    assert result["ok"] is False
    assert "JSON" in result["error"]


def test_malformed_json_raises_policyparseerror():
    with pytest.raises(PolicyParseError):
        run_checks("{ not json }")


def test_missing_statement_raises():
    with pytest.raises(PolicyParseError):
        parse_policy({"Version": "2012-10-17"})


def test_non_object_policy_raises():
    with pytest.raises(PolicyParseError):
        parse_policy("[1, 2, 3]")


def test_run_checks_accepts_dict_and_string_equally():
    policy = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    from_dict = run_checks(policy)
    from_str = run_checks(json.dumps(policy))
    assert rule_ids(from_dict) == rule_ids(from_str)


# --- Ranking --------------------------------------------------------------


def test_rank_orders_critical_before_low():
    findings = [
        {"rule_id": "A", "severity": "LOW", "statement_index": 0, "detail": ""},
        {"rule_id": "B", "severity": "CRITICAL", "statement_index": 5, "detail": ""},
        {"rule_id": "C", "severity": "HIGH", "statement_index": 2, "detail": ""},
    ]
    ordered = [f["severity"] for f in rank(findings)]
    assert ordered == ["CRITICAL", "HIGH", "LOW"]


# --- Whole-sample sanity checks -------------------------------------------


def test_clean_sample_has_zero_findings():
    findings = run_checks(SAMPLES.joinpath("01_clean_s3_readonly.json").read_text())
    assert findings == []


def test_gnarly_sample_expected_rules():
    findings = run_checks(
        SAMPLES.joinpath("05_gnarly_notaction_notresource.json").read_text()
    )
    assert "NOTACTION_ALLOW" in rules_for(findings, 0)
    assert "NOTRESOURCE_ALLOW" in rules_for(findings, 1)
    assert "WILDCARD_ACTION" in rules_for(findings, 1)
    assert "ADMIN_EQUIVALENT" in rules_for(findings, 2)


def test_public_bucket_sample_flags_overbroad_principal():
    findings = run_checks(
        SAMPLES.joinpath("07_public_bucket_policy.json").read_text()
    )
    assert "OVERBROAD_PRINCIPAL" in rules_for(findings, 0)
    assert "OVERBROAD_PRINCIPAL" in rules_for(findings, 1)
    assert "WILDCARD_ACTION" in rules_for(findings, 1)


def test_messy_deploy_sample_flags_passrole_and_wildcards():
    findings = run_checks(SAMPLES.joinpath("03_messy_deploy_role.json").read_text())
    assert "PASSROLE_UNCONSTRAINED" in rules_for(findings, 0)
    assert "WILDCARD_ACTION" in rules_for(findings, 0)
    assert "WILDCARD_RESOURCE" in rules_for(findings, 0)


def test_all_samples_parse_or_error_cleanly():
    # No sample should ever throw an uncaught exception through run_checks_safe.
    for path in sorted(SAMPLES.glob("*.json")):
        result = run_checks_safe(path.read_text())
        assert "ok" in result
