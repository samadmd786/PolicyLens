#!/usr/bin/env python3
"""MANUAL / INTEGRATION script — hits REAL Amazon Bedrock. Not run by pytest.

Run this ONCE to confirm the live Bedrock call works and the cost is sane. It
makes exactly one model call against one sample policy and prints the token
usage so you can eyeball spend.

Prerequisites:
- AWS credentials on your machine (env vars or a configured profile) with
  bedrock:InvokeModel permission.
- Model access enabled in the Bedrock console for the model you target.
- boto3 installed:  pip install boto3

Usage:
    python scripts/live_bedrock_check.py                       # default sample
    python scripts/live_bedrock_check.py samples/03_messy_deploy_role.json
    POLICYLENS_MODEL_ID=us.amazon.nova-lite-v1:0 \
        python scripts/live_bedrock_check.py

This script is intentionally kept out of tests so the suite stays offline and
free.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from backend.bedrock_client import (  # noqa: E402
    DEFAULT_MODEL_ID,
    DEFAULT_REGION,
    build_user_message,
    SYSTEM_PROMPT,
    validate_model_output,
    _extract_text,
    _loads_lenient,
)
from backend.checks import parse_policy, run_checks  # noqa: E402

DEFAULT_SAMPLE = REPO_ROOT / "samples" / "03_messy_deploy_role.json"


def main() -> int:
    import boto3  # local import so the file imports without boto3 present

    sample = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_SAMPLE
    raw = sample.read_text()
    policy = parse_policy(raw)
    findings = run_checks(raw)

    print(f"Sample: {sample.name}")
    print(f"Model:  {DEFAULT_MODEL_ID}  (region {DEFAULT_REGION})")
    print(f"Layer 1 findings: {[f['rule_id'] for f in findings]}\n")

    client = boto3.client("bedrock-runtime", region_name=DEFAULT_REGION)
    response = client.converse(
        modelId=DEFAULT_MODEL_ID,
        system=[{"text": SYSTEM_PROMPT}],
        messages=[
            {"role": "user", "content": [{"text": build_user_message(policy, findings)}]}
        ],
        inferenceConfig={"maxTokens": 2000, "temperature": 0.2},
    )

    usage = response.get("usage", {})
    print("--- token usage (for cost sanity) ---")
    print(f"  input tokens:  {usage.get('inputTokens')}")
    print(f"  output tokens: {usage.get('outputTokens')}")
    print(f"  total tokens:  {usage.get('totalTokens')}\n")

    text = _extract_text(response)
    raw_obj = _loads_lenient(text)
    validated = validate_model_output(raw_obj, findings)

    print("--- validated summary ---")
    print(validated["summary"], "\n")
    print("--- validated findings ---")
    for f in validated["findings"]:
        print(f"  {f['rule_id']}: {f['fix']}")
    print("\n--- rewritten policy valid IAM JSON? ---")
    print(f"  {validated['rewrite_valid']}")
    if validated["rewrite_valid"]:
        print(json.dumps(validated["rewritten_policy"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
