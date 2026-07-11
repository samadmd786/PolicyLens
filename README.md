# PolicyLens

AI-powered AWS IAM policy reviewer. Paste an IAM policy JSON and get a ranked
list of security findings in plain English, plus a rewritten least-privilege
version shown side by side with the original.

Built for the AWS Builder Center Weekend Productivity Challenge.

**Live demo:** https://main.d2k0p29miy8scd.amplifyapp.com/

## How it works

Deterministic first, AI second.

- **Layer 1 (pure Python, no AWS):** a ten-rule engine that is the source of
  truth for what is wrong with a policy. Runs offline, fully tested.
- **Layer 2 (Amazon Bedrock, Nova Micro):** explains the Layer 1 findings in
  plain English, frames business impact, and produces the rewrite. The model
  never invents findings, and the rewritten policy is validated as real IAM JSON
  before it is shown. If Bedrock is unavailable, the app degrades to the Layer 1
  findings instead of failing.

PolicyLens never asks for your credentials. Nothing is stored or logged beyond
the single analysis call. To review policies from a real account, run
`scripts/fetch_policies.py` locally (read-only) and upload the export.

## Architecture

```
Browser (Amplify Hosting, static HTML/JS)
        |  POST policy JSON
        v
API Gateway (HTTP API)
        |
        v
AWS Lambda
        |
   Layer 1: deterministic checks (pure Python)
        |
   Layer 2: Amazon Bedrock (Nova Micro)
        |
        v
   One JSON response: findings + rewrite
```

## Quickstart (local)

```bash
python3 -m venv .venv
.venv/bin/pip install pytest boto3

# Run the test suite (offline, no AWS)
.venv/bin/python -m pytest -q

# Scan the sample policies from the CLI
.venv/bin/python scripts/scan.py --all

# Run the app locally (real Bedrock if AWS creds are set, else degraded mode)
AWS_PROFILE=<your-bedrock-profile> .venv/bin/python scripts/dev_server.py
# open http://localhost:8000
```

## Deploy

One command, terminal only, no console login:

```bash
scripts/deploy.sh --profile <deployer-profile>
```

It deploys the backend via CloudFormation (API Gateway + Lambda, defined in
`infra/template.yaml`) and the frontend to Amplify. See
**[docs/DEPLOY.md](docs/DEPLOY.md)** for prerequisites, what it creates, and
teardown.

## Repository layout

```
backend/     Layer 1 checks, Layer 2 Bedrock client, Lambda handler
frontend/    Static single-page app (paste, upload, sample gallery, diff view)
samples/     Example IAM policies (clean, messy, gnarly, malformed)
scripts/     CLI scanner, local IAM export, dev server, deploy + teardown
infra/       CloudFormation template (API Gateway + Lambda)
tests/       pytest suite (rule engine, Bedrock validator, fetch_policies)
docs/        Deploy guide, frontend checklist, IAM policies
```

## Testing

```bash
.venv/bin/python -m pytest -q     # all tests, offline and free
```

Every deterministic rule has a positive and a negative test. Bedrock and boto3
are mocked, so the suite never makes a live AWS call.
