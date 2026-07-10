#!/usr/bin/env bash
# Build the Lambda deployment zip for PolicyLens.
#
# boto3/botocore are already present in the Lambda Python runtime, so there are
# no dependencies to bundle. We just zip the backend/ package.
#
# Result: policylens-lambda.zip at the repo root.
# Lambda handler to set in the console: backend.handler.lambda_handler
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

OUT="policylens-lambda.zip"
rm -f "$OUT"
zip -r "$OUT" backend -x '*__pycache__*' '*.pyc' >/dev/null

echo "Built $OUT"
echo "Set the Lambda handler to: backend.handler.lambda_handler"
unzip -l "$OUT"
