"""Tests for the Layer 2 Bedrock pass and the handler wiring.

Fully offline. No live Bedrock, no boto3 required. A fake client stands in for
bedrock-runtime and returns canned Converse-API responses.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from backend.bedrock_client import (  # noqa: E402
    BedrockError,
    invoke_model,
    review,
    validate_model_output,
)
from backend.checks import run_checks  # noqa: E402
from backend.handler import analyze, lambda_handler  # noqa: E402

SAMPLES = REPO_ROOT / "samples"

VALID_REWRITE = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ScopedPut",
            "Effect": "Allow",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::my-app-data/*",
        }
    ],
}


def converse_response(text: str) -> dict:
    """Shape a Bedrock Converse API response around a text block."""
    return {"output": {"message": {"content": [{"text": text}]}}}


class FakeBedrock:
    """Stand-in for a bedrock-runtime client.

    `payload` is returned as the assistant text. If `raises` is set, .converse
    raises it (to simulate throttling / API errors).
    """

    def __init__(self, payload: str | None = None, raises: Exception | None = None):
        self._payload = payload
        self._raises = raises
        self.calls = 0

    def converse(self, **kwargs):
        self.calls += 1
        if self._raises is not None:
            raise self._raises
        return converse_response(self._payload)


def model_json(findings_rule_ids: list[str], rewrite=VALID_REWRITE) -> str:
    return json.dumps(
        {
            "summary": "The policy grants far more than it needs.",
            "findings": [
                {
                    "rule_id": rid,
                    "explanation": f"Explanation for {rid}.",
                    "business_impact": "Could allow account takeover.",
                    "fix": "Scoped it down.",
                }
                for rid in findings_rule_ids
            ],
            "rewritten_policy": rewrite,
        }
    )


# --- invoke_model ----------------------------------------------------------


def test_invoke_model_parses_canned_response():
    client = FakeBedrock(payload=model_json(["WILDCARD_RESOURCE"]))
    out = invoke_model({"Statement": []}, [], client=client)
    assert out["summary"]
    assert out["findings"][0]["rule_id"] == "WILDCARD_RESOURCE"
    assert client.calls == 1


def test_invoke_model_strips_code_fences():
    fenced = "```json\n" + model_json(["WILDCARD_RESOURCE"]) + "\n```"
    client = FakeBedrock(payload=fenced)
    out = invoke_model({"Statement": []}, [], client=client)
    assert out["findings"][0]["rule_id"] == "WILDCARD_RESOURCE"


def test_invoke_model_tolerates_prose_around_json():
    noisy = "Here is the review:\n" + model_json(["WILDCARD_RESOURCE"]) + "\nDone."
    client = FakeBedrock(payload=noisy)
    out = invoke_model({"Statement": []}, [], client=client)
    assert out["summary"]


def test_invoke_model_raises_bedrockerror_on_client_failure():
    client = FakeBedrock(raises=RuntimeError("ThrottlingException: slow down"))
    with pytest.raises(BedrockError):
        invoke_model({"Statement": []}, [], client=client)


def test_invoke_model_raises_on_non_json_output():
    client = FakeBedrock(payload="I could not do that.")
    with pytest.raises(BedrockError):
        invoke_model({"Statement": []}, [], client=client)


def test_invoke_model_raises_on_empty_output():
    client = FakeBedrock(payload="")
    with pytest.raises(BedrockError):
        invoke_model({"Statement": []}, [], client=client)


# --- validate_model_output -------------------------------------------------


def test_validator_keeps_matching_rule_ids():
    layer1 = [
        {"rule_id": "WILDCARD_RESOURCE", "severity": "HIGH", "statement_index": 0, "detail": ""}
    ]
    raw = json.loads(model_json(["WILDCARD_RESOURCE"]))
    result = validate_model_output(raw, layer1)
    assert [f["rule_id"] for f in result["findings"]] == ["WILDCARD_RESOURCE"]


def test_validator_drops_hallucinated_rule_id():
    layer1 = [
        {"rule_id": "WILDCARD_RESOURCE", "severity": "HIGH", "statement_index": 0, "detail": ""}
    ]
    raw = json.loads(model_json(["WILDCARD_RESOURCE", "TOTALLY_MADE_UP_RULE"]))
    result = validate_model_output(raw, layer1)
    kept = [f["rule_id"] for f in result["findings"]]
    assert "TOTALLY_MADE_UP_RULE" not in kept
    assert kept == ["WILDCARD_RESOURCE"]


def test_validator_accepts_valid_rewritten_policy():
    layer1 = [{"rule_id": "WILDCARD_RESOURCE", "severity": "HIGH", "statement_index": 0, "detail": ""}]
    raw = json.loads(model_json(["WILDCARD_RESOURCE"], rewrite=VALID_REWRITE))
    result = validate_model_output(raw, layer1)
    assert result["rewrite_valid"] is True
    assert result["rewritten_policy"] == VALID_REWRITE


def test_validator_rejects_invalid_rewritten_policy():
    layer1 = [{"rule_id": "WILDCARD_RESOURCE", "severity": "HIGH", "statement_index": 0, "detail": ""}]
    # Missing the required Statement field -> not valid IAM JSON.
    bad_rewrite = {"Version": "2012-10-17", "NotAPolicy": True}
    raw = json.loads(model_json(["WILDCARD_RESOURCE"], rewrite=bad_rewrite))
    result = validate_model_output(raw, layer1)
    assert result["rewrite_valid"] is False
    assert result["rewritten_policy"] is None


def test_validator_rejects_non_dict_rewrite():
    layer1 = []
    raw = {"summary": "s", "findings": [], "rewritten_policy": "not a dict"}
    result = validate_model_output(raw, layer1)
    assert result["rewritten_policy"] is None
    assert result["rewrite_valid"] is False


# --- review (invoke + validate) -------------------------------------------


def test_review_end_to_end_with_mock():
    policy = json.loads(SAMPLES.joinpath("02_mild_wildcard_resource.json").read_text())
    layer1 = run_checks(policy)
    ids = [f["rule_id"] for f in layer1]
    client = FakeBedrock(payload=model_json(ids))
    result = review(policy, layer1, client=client)
    assert result["summary"]
    assert result["rewrite_valid"] is True
    assert {f["rule_id"] for f in result["findings"]} == set(ids)


# --- handler graceful degradation -----------------------------------------


def test_analyze_returns_ai_block_when_bedrock_ok():
    raw = SAMPLES.joinpath("02_mild_wildcard_resource.json").read_text()
    layer1_ids = [f["rule_id"] for f in run_checks(raw)]
    client = FakeBedrock(payload=model_json(layer1_ids))
    result = analyze(raw, bedrock_client=client)
    assert result["ok"] is True
    assert result["degraded"] is False
    assert result["ai"] is not None
    assert result["ai"]["summary"]


def test_analyze_degrades_when_bedrock_throttles():
    raw = SAMPLES.joinpath("03_messy_deploy_role.json").read_text()
    client = FakeBedrock(raises=RuntimeError("ThrottlingException"))
    result = analyze(raw, bedrock_client=client)
    # Deterministic findings must still be present.
    assert result["ok"] is True
    assert result["degraded"] is True
    assert result["degraded_reason"]
    assert result["ai"] is None
    assert any(f["rule_id"] == "PASSROLE_UNCONSTRAINED" for f in result["findings"])


def test_analyze_malformed_policy_returns_error():
    raw = SAMPLES.joinpath("06_malformed.json").read_text()
    result = analyze(raw, bedrock_client=FakeBedrock(payload=model_json([])))
    assert result["ok"] is False
    assert "JSON" in result["error"]


# --- lambda_handler shape --------------------------------------------------


def test_lambda_handler_options_preflight():
    event = {"requestContext": {"http": {"method": "OPTIONS"}}}
    resp = lambda_handler(event)
    assert resp["statusCode"] == 200
    assert resp["headers"]["Access-Control-Allow-Origin"] == "*"


def test_lambda_handler_empty_body_is_400():
    event = {"requestContext": {"http": {"method": "POST"}}, "body": ""}
    resp = lambda_handler(event)
    assert resp["statusCode"] == 400
    assert json.loads(resp["body"])["ok"] is False


def test_lambda_handler_accepts_policy_wrapper(monkeypatch):
    # Force the real bedrock path to fail so we exercise degradation without boto3.
    import backend.bedrock_client as bc

    def boom(*args, **kwargs):
        raise BedrockError("no bedrock in tests")

    monkeypatch.setattr(bc, "invoke_model", boom)

    policy = SAMPLES.joinpath("02_mild_wildcard_resource.json").read_text()
    event = {
        "requestContext": {"http": {"method": "POST"}},
        "body": json.dumps({"policy": json.loads(policy)}),
    }
    resp = lambda_handler(event)
    body = json.loads(resp["body"])
    assert resp["statusCode"] == 200
    assert body["ok"] is True
    assert body["degraded"] is True
    assert any(f["rule_id"] == "WILDCARD_RESOURCE" for f in body["findings"])
