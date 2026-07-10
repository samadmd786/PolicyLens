"""PolicyLens Lambda handler.

Flow per review:
    parse input -> Layer 1 deterministic checks -> Layer 2 Bedrock pass
    -> assemble one JSON response.

Degrades, never dies: if the Bedrock call fails or throttles, the response
still carries the Layer 1 findings with degraded=true. The deterministic engine
is the product; the LLM is presentation.

Privacy: submitted policies are never logged or stored. We log rule_ids and
error types only, never the policy body.
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any

from backend.bedrock_client import BedrockError, review
from backend.checks import PolicyParseError, run_checks

logger = logging.getLogger("policylens.handler")

CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
}


def analyze(raw_policy: str | bytes | dict[str, Any], bedrock_client: Any = None) -> dict[str, Any]:
    """Run the full review and return the response body dict.

    `bedrock_client` is injected in tests; production passes None so the
    Bedrock client is built lazily. This function does not raise on Bedrock
    failure; it degrades. It only surfaces PolicyParseError as a clean error
    body (ok=false).
    """
    try:
        # parse_policy runs inside run_checks; a bad policy raises here.
        findings = run_checks(raw_policy)
    except PolicyParseError as exc:
        return {"ok": False, "error": str(exc)}

    # We need the parsed dict for the Bedrock prompt. run_checks already
    # validated it, so re-parsing is cheap and cannot fail here.
    from backend.checks import parse_policy

    policy = parse_policy(raw_policy)

    response: dict[str, Any] = {
        "ok": True,
        "findings": findings,
        "ai": None,
        "degraded": False,
        "degraded_reason": None,
    }

    try:
        response["ai"] = review(policy, findings, client=bedrock_client)
    except BedrockError as exc:
        logger.warning("Degrading to Layer 1 only: %s", exc)
        response["degraded"] = True
        response["degraded_reason"] = (
            "The AI explanation step was unavailable, so only the deterministic "
            "findings are shown."
        )

    return response


def _extract_body(event: dict[str, Any]) -> str:
    """Get the raw request body from a Lambda Function URL / API GW event."""
    body = event.get("body", "")
    if event.get("isBase64Encoded") and isinstance(body, str):
        body = base64.b64decode(body).decode("utf-8")
    return body or ""


def _response(status: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status,
        "headers": CORS_HEADERS,
        "body": json.dumps(body),
    }


def lambda_handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    """Lambda Function URL entry point.

    Accepts a POST whose body is either the raw policy JSON or
    {"policy": <json string or object>}. Returns the analyze() body.
    """
    method = (
        event.get("requestContext", {})
        .get("http", {})
        .get("method", event.get("httpMethod", "POST"))
    )
    if method == "OPTIONS":
        return _response(200, {"ok": True})

    raw_body = _extract_body(event)
    if not raw_body.strip():
        return _response(400, {"ok": False, "error": "Request body was empty."})

    # Accept either a bare policy or {"policy": ...}. Do not log the body.
    policy_input: str | dict[str, Any] = raw_body
    try:
        parsed = json.loads(raw_body)
        if isinstance(parsed, dict) and "policy" in parsed:
            policy_input = parsed["policy"]
    except json.JSONDecodeError:
        # Leave policy_input as the raw string; analyze() will report the error.
        pass

    result = analyze(policy_input)
    status = 200 if result.get("ok") else 400
    return _response(status, result)
