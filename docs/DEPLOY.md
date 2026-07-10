# Deploying PolicyLens (CloudFormation + Amplify, terminal only)

All-AWS, Free-Tier-minded, and driven entirely from the terminal. No console
login needed. Two pieces:

- **Backend:** an API Gateway HTTP API in front of a Lambda that runs the
  deterministic checks plus one Amazon Bedrock (Nova Micro) call. Defined in
  [../infra/template.yaml](../infra/template.yaml) (CloudFormation).
- **Frontend:** the static single-page app, deployed to AWS Amplify with a
  Git-less manual upload.

Region assumed throughout: **us-east-1** (where Nova Micro access is enabled).

---

## Prerequisites (one time)

- **AWS CLI v2** and a profile with permissions to create CloudFormation stacks,
  IAM roles, Lambda, S3, and Amplify apps. The Bedrock-only `policylens` user is
  NOT enough for deploying; use an admin/deployer profile here. (The Bedrock-only
  user is what the running Lambda uses, not what deploys it.)
- **Amazon Bedrock model access** enabled for Nova Micro in the target region
  (Bedrock console, one time per account).

---

## One command

```bash
scripts/deploy.sh --profile <deployer-profile> [--region us-east-1]
```

That script does everything:

1. Packages the Lambda (`backend/`) and uploads it to a per-account S3 deploy
   bucket (`policylens-deploy-<account>-<region>`).
2. Deploys the CloudFormation stack `policylens` (Lambda + IAM role scoped to
   Nova Micro + API Gateway HTTP API with public CORS).
3. Reads the API URL from the stack outputs and smoke-tests it.
4. Builds a copy of the frontend with `config.js` pointing at that API URL.
5. Creates (or reuses) an Amplify app named `policylens`, uploads the frontend
   as a manual deployment, and waits for it to go live.

On success it prints the **App URL** (`https://main.<appId>.amplifyapp.com`) and
the **API URL**. Put the app URL in `ARTICLE.md`.

---

## What it creates

| Resource | Purpose |
| --- | --- |
| CloudFormation stack `policylens` | Everything backend, as one unit |
| Lambda `policylens` | Runs Layer 1 checks + the Bedrock call |
| IAM role (in-stack) | Lambda logs + `bedrock:InvokeModel` on Nova Micro only |
| API Gateway HTTP API `policylens-api` | Public `POST /` endpoint, CORS enabled |
| S3 bucket `policylens-deploy-<account>-<region>` | Holds the Lambda zip |
| Amplify app `policylens` | Hosts the static frontend |

---

## Redeploying

Just run `scripts/deploy.sh` again. The Lambda zip is keyed by content hash, so
CloudFormation picks up code changes; the frontend is re-uploaded to the same
Amplify app.

---

## Verify (the Phase 3 gate)

- Open the printed App URL in a normal window: run all three input modes (sample
  chips, paste, upload).
- Open it in an **incognito / logged-out** window: confirm the public link works
  with no AWS login.
- Confirm the GitHub repo is **public**.

Manual API check:

```bash
curl -s -X POST <API_URL> \
  -H 'Content-Type: application/json' \
  -d '{"policy": {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}}'
```

You should get JSON with `"ok": true`, a `findings` array, and an `ai` block.

---

## Cost notes (no Free Tier)

- **Bedrock (Nova Micro):** ~$0.0002 per review. Negligible.
- **Lambda + API Gateway:** billed per request; a handful of demo calls is a
  fraction of a cent.
- **Amplify Hosting:** the only standing cost. Roughly ~$0.15/GB served plus a
  little storage. A weekend demo is cents to low single-digit dollars.
- **S3 + CloudWatch Logs:** pennies. The handler never logs policy bodies.

---

## Teardown

```bash
aws cloudformation delete-stack --stack-name policylens --profile <deployer-profile>
aws amplify delete-app --app-id <appId> --profile <deployer-profile>
aws s3 rb s3://policylens-deploy-<account>-us-east-1 --force --profile <deployer-profile>
```

Optionally delete the `policylens` IAM user. Nothing else was created.
