"""PolicyLens Layer 2 — Bedrock reasoning pass.

Takes the original policy plus the Layer 1 findings and asks a Bedrock model
to (1) explain the findings in plain English, (2) frame business impact, and
(3) produce a rewritten least-privilege policy.

Hard contract, enforced in code, not trusted to the model:
- The model NEVER invents findings. Every finding it returns must carry a
  rule_id that exists in the Layer 1 output. Any other finding is dropped.
- The rewritten policy must be syntactically valid IAM JSON or it is discarded.
- One model call per review. No chains, no agents.

boto3 is imported lazily inside the client factory so the pytest suite (which
injects a mock client) runs offline without boto3 installed.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

from backend.checks import Finding, PolicyParseError, parse_policy

logger = logging.getLogger("policylens.bedrock")

# Nova Micro (cross-region inference profile) is the default: it is the cheapest
# Bedrock model and is plenty for short explanations plus one policy rewrite,
# which the validator checks regardless. Bump quality with one env var:
#   POLICYLENS_MODEL_ID=us.amazon.nova-lite-v1:0   (a little more, better rewrites)
#   POLICYLENS_MODEL_ID=us.amazon.nova-pro-v1:0    (best, ~10-50x the price)
# Any Bedrock Converse-capable model id works here.
DEFAULT_MODEL_ID = os.environ.get("POLICYLENS_MODEL_ID", "us.amazon.nova-micro-v1:0")
DEFAULT_REGION = os.environ.get("AWS_REGION", "us-east-1")

SYSTEM_PROMPT = (
    "You are a senior AWS security engineer reviewing an IAM policy. Be direct "
    "and specific. No hedging, no filler, no marketing language. You are given "
    "the original policy and a list of findings that a deterministic scanner "
    "already produced. Your job is to explain those findings in plain English "
    "and produce a tighter, least-privilege rewrite of the policy.\n\n"
    "Rules you must follow:\n"
    "- Only discuss findings from the provided list. Do not invent new findings "
    "or reference issues that are not in the list. Each finding you return must "
    "reuse the exact rule_id from the input.\n"
    "- The rewritten policy must be valid IAM JSON and must remove or constrain "
    "the flagged permissions (scope wildcard actions and resources, add "
    "Conditions, split overbroad statements). Preserve the clearly legitimate "
    "access.\n"
    "- Respond with a single JSON object and nothing else. No prose before or "
    "after, no code fences."
)

# The exact JSON schema we tell the model to emit and then validate.
OUTPUT_SCHEMA_HINT = {
    "summary": "2-3 sentence plain-English overview",
    "findings": [
        {
            "rule_id": "must match one of the input finding rule_ids",
            "explanation": "plain English, one short paragraph",
            "business_impact": "one line",
            "fix": "one line describing the change made in the rewritten policy",
        }
    ],
    "rewritten_policy": {"Version": "2012-10-17", "Statement": []},
}


class BedrockError(RuntimeError):
    """Raised when the Bedrock call fails or returns unusable output.

    The handler catches this and degrades to Layer 1 findings only.
    """


def build_user_message(policy: dict[str, Any], findings: list[Finding]) -> str:
    """Assemble the single user turn: the policy, the findings, and the schema."""
    return (
        "ORIGINAL POLICY:\n"
        f"{json.dumps(policy, indent=2)}\n\n"
        "LAYER 1 FINDINGS (the only issues you may discuss):\n"
        f"{json.dumps(findings, indent=2)}\n\n"
        "Respond with a JSON object exactly matching this shape:\n"
        f"{json.dumps(OUTPUT_SCHEMA_HINT, indent=2)}"
    )


def _make_client(region: str | None = None):
    """Create a bedrock-runtime client. boto3 imported lazily on purpose."""
    import boto3  # noqa: PLC0415 — lazy so tests run without boto3

    return boto3.client("bedrock-runtime", region_name=region or DEFAULT_REGION)


def _extract_text(response: dict[str, Any]) -> str:
    """Pull the assistant text out of a Bedrock Converse API response."""
    try:
        content = response["output"]["message"]["content"]
        parts = [block["text"] for block in content if "text" in block]
        text = "".join(parts).strip()
    except (KeyError, TypeError, IndexError) as exc:
        raise BedrockError(f"Unexpected Bedrock response shape: {exc}") from exc
    if not text:
        raise BedrockError("Bedrock returned an empty response.")
    return text


def _loads_lenient(text: str) -> dict[str, Any]:
    """Parse a JSON object out of model text, tolerating code fences/prose.

    Models occasionally wrap JSON in ```json fences or add a stray sentence.
    We strip fences, then fall back to slicing the outermost braces.
    """
    cleaned = text.strip()
    fence = re.match(r"^```(?:json)?\s*(.*?)\s*```$", cleaned, re.DOTALL)
    if fence:
        cleaned = fence.group(1).strip()
    try:
        obj = json.loads(cleaned)
    except json.JSONDecodeError:
        start, end = cleaned.find("{"), cleaned.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise BedrockError("Model output was not valid JSON.")
        try:
            obj = json.loads(cleaned[start : end + 1])
        except json.JSONDecodeError as exc:
            raise BedrockError(f"Model output was not valid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise BedrockError("Model output JSON was not an object.")
    return obj


def invoke_model(
    policy: dict[str, Any],
    findings: list[Finding],
    client: Any = None,
    model_id: str | None = None,
) -> dict[str, Any]:
    """Call Bedrock once and return the parsed (still unvalidated) model object.

    Pass `client` in tests (a mock exposing `.converse(...)`). In production the
    handler passes None and we build a real bedrock-runtime client.

    Raises BedrockError on any API failure, throttle, or unparseable output so
    the handler can degrade cleanly.
    """
    model_id = model_id or DEFAULT_MODEL_ID
    if client is None:
        client = _make_client()

    try:
        response = client.converse(
            modelId=model_id,
            system=[{"text": SYSTEM_PROMPT}],
            messages=[
                {"role": "user", "content": [{"text": build_user_message(policy, findings)}]}
            ],
            inferenceConfig={"maxTokens": 2000, "temperature": 0.2},
        )
    except BedrockError:
        raise
    except Exception as exc:  # boto ClientError, throttling, timeouts, network
        logger.warning("Bedrock call failed: %s", exc)
        raise BedrockError(f"Bedrock call failed: {exc}") from exc

    text = _extract_text(response)
    return _loads_lenient(text)


def validate_model_output(
    model_output: dict[str, Any],
    layer1_findings: list[Finding],
) -> dict[str, Any]:
    """Enforce the Layer 2 contract on raw model output.

    - Drops any finding whose rule_id is not present in the Layer 1 output,
      logging each drop (the model is not allowed to invent findings).
    - Keeps rewritten_policy only if it parses as valid IAM JSON; otherwise sets
      it to None so the UI hides the rewrite rather than showing garbage.

    Returns a clean dict:
        {"summary": str, "findings": [...], "rewritten_policy": dict | None,
         "rewrite_valid": bool}
    """
    allowed = {f["rule_id"] for f in layer1_findings}

    summary = model_output.get("summary")
    if not isinstance(summary, str):
        summary = ""

    validated_findings: list[dict[str, Any]] = []
    for item in model_output.get("findings", []) or []:
        if not isinstance(item, dict):
            continue
        rule_id = item.get("rule_id")
        if rule_id not in allowed:
            logger.warning(
                "Dropping hallucinated model finding with rule_id=%r "
                "(not in Layer 1 output)",
                rule_id,
            )
            continue
        validated_findings.append(
            {
                "rule_id": rule_id,
                "explanation": str(item.get("explanation", "")),
                "business_impact": str(item.get("business_impact", "")),
                "fix": str(item.get("fix", "")),
            }
        )

    rewritten = model_output.get("rewritten_policy")
    rewrite_valid = False
    if isinstance(rewritten, dict):
        try:
            parse_policy(rewritten)
            rewrite_valid = True
        except PolicyParseError as exc:
            logger.warning("Rewritten policy failed IAM validation: %s", exc)
            rewritten = None
    else:
        rewritten = None

    return {
        "summary": summary,
        "findings": validated_findings,
        "rewritten_policy": rewritten,
        "rewrite_valid": rewrite_valid,
    }


def review(
    policy: dict[str, Any],
    layer1_findings: list[Finding],
    client: Any = None,
    model_id: str | None = None,
) -> dict[str, Any]:
    """One call end-to-end: invoke the model, then validate its output.

    Raises BedrockError if the call fails; the handler degrades on that.
    """
    raw = invoke_model(policy, layer1_findings, client=client, model_id=model_id)
    return validate_model_output(raw, layer1_findings)
