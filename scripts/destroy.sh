#!/usr/bin/env bash
# One-command, terminal-only teardown for PolicyLens.
#
# What it does:
#   1. Deletes the AWS Amplify app (frontend hosting).
#   2. Deletes the backend CloudFormation stack (Lambda, API Gateway, IAM roles).
#   3. Empties and deletes the S3 deployment bucket.
#   4. Cleans up the local dist/ directory.
#
# Usage:
#   scripts/destroy.sh --profile <deployer-profile> [--region us-east-1]
#

set -euo pipefail

PROFILE=""
REGION="us-east-1"
STACK="policylens"
APP_NAME="policylens"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE="$2"; shift 2 ;;
    --region)  REGION="$2";  shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$PROFILE" ]]; then
  echo "Error: --profile <deployer-profile> is required." >&2
  exit 1
fi

for tool in aws; do
  command -v "$tool" >/dev/null 2>&1 || { echo "Error: $tool not found." >&2; exit 1; }
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
aws_() { aws --profile "$PROFILE" --region "$REGION" "$@"; }

echo "==> Checking credentials"
ACCOUNT="$(aws_ sts get-caller-identity --query Account --output text)"
echo "    account $ACCOUNT, region $REGION, profile $PROFILE"

# --- 1. Delete AWS Amplify app ----------------------------------------------
echo "==> Checking for Amplify app '$APP_NAME'"
APP_ID="$(aws_ amplify list-apps --query "apps[?name=='$APP_NAME'].appId | [0]" --output text)"
if [[ "$APP_ID" != "None" && -n "$APP_ID" ]]; then
  echo "==> Deleting Amplify app $APP_ID"
  aws_ amplify delete-app --app-id "$APP_ID" >/dev/null
  echo "    Amplify app deleted."
else
  echo "    Amplify app '$APP_NAME' not found."
fi

# --- 2. Delete CloudFormation stack (Lambda + API Gateway + IAM Role) -------
echo "==> Deleting CloudFormation stack $STACK"
if aws_ cloudformation describe-stacks --stack-name "$STACK" >/dev/null 2>&1; then
  aws_ cloudformation delete-stack --stack-name "$STACK"
  echo "==> Waiting for stack deletion to complete..."
  aws_ cloudformation wait stack-delete-complete --stack-name "$STACK"
  echo "    CloudFormation stack deleted."
else
  echo "    CloudFormation stack '$STACK' not found."
fi

# --- 3. Empty and delete S3 deployment bucket -------------------------------
BUCKET="policylens-deploy-$ACCOUNT-$REGION"
if aws_ s3api head-bucket --bucket "$BUCKET" >/dev/null 2>&1; then
  echo "==> Emptying deployment bucket s3://$BUCKET"
  aws_ s3 rm "s3://$BUCKET" --recursive >/dev/null
  echo "==> Deleting deployment bucket s3://$BUCKET"
  aws_ s3api delete-bucket --bucket "$BUCKET" >/dev/null
  echo "    S3 deployment bucket deleted."
else
  echo "    S3 deployment bucket '$BUCKET' does not exist."
fi

# --- 4. Clean up local build artifacts --------------------------------------
if [[ -d "$REPO_ROOT/dist" ]]; then
  echo "==> Removing local dist/ directory"
  rm -rf "$REPO_ROOT/dist"
  echo "    dist/ removed."
fi

echo
echo "Teardown complete. All deployed AWS resources for PolicyLens have been deleted."

