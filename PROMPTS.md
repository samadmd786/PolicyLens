# PROMPTS.md

A running log of the significant prompts used with an AI coding assistant while
building PolicyLens. Feeds the "How You Built It" section of the challenge
article.

## Phase 1 — Deterministic engine

**Prompt:** "build this project"

Used to kick off Phase 1 per the project build plan. Produced:

- `backend/checks.py` — the 10-rule deterministic engine (Layer 1), pure
  Python, no AWS. Handles Action/Resource as string or list, single statement
  not wrapped in a list, missing optional fields, and malformed JSON via a
  clean `PolicyParseError` (never a stack trace to the user).
- `samples/` — 7 policies: 1 clean (zero findings), 1 mild, 2 realistic messy
  (deploy role, Lambda + secrets), 1 gnarly (NotAction/NotResource + self
  escalation), 1 malformed JSON, 1 public bucket policy (overbroad principal).
- `tests/test_checks.py` — pytest, one positive and one negative case per rule
  plus edge cases and whole-sample sanity checks. Fully offline.
- `scripts/scan.py` — local CLI to eyeball findings against a file or the whole
  samples set.

Design note kept from the project plan: Layer 1 is the source of truth for WHAT
is wrong. The Bedrock layer (Phase 2) only explains and rewrites; it never
invents findings.

## Phase 2 — Bedrock reasoning layer

**Prompt:** "yes" (go-ahead after the Phase 1 gate)

Built the Layer 2 reasoning pass and wired it to Layer 1:

- `backend/bedrock_client.py` — the prompt contract (senior AWS security
  engineer persona), a single Converse-API call (Nova Micro by default,
  configurable via `POLICYLENS_MODEL_ID`), lenient JSON parsing of model output, and
  the contract validator. boto3 is imported lazily so the test suite runs
  offline. `BedrockError` is raised on any API failure so the handler can
  degrade.
- Output validator (`validate_model_output`) — drops any model finding whose
  rule_id is not in the Layer 1 output (logs each drop), and keeps the
  rewritten policy only if it parses as valid IAM JSON, else nulls it.
- `backend/handler.py` — Lambda Function URL entry point. parse -> Layer 1 ->
  Layer 2 -> one JSON response. Degrades to Layer 1 findings with
  `degraded=true` if Bedrock fails. Never logs the policy body.
- `tests/test_bedrock_client.py` — mocked Bedrock (canned Converse responses),
  including the hallucinated-rule_id drop, the invalid-rewrite rejection, and
  the throttle-degradation path. No live calls.
- `scripts/live_bedrock_check.py` — the single, clearly labeled one-off script
  that hits real Bedrock and prints token usage for cost sanity. Kept out of
  pytest on purpose.

Also switched the default model to Nova Micro (`us.amazon.nova-micro-v1:0`), the
cheapest Bedrock model, on request. One live review runs ~1,581 tokens
(~$0.00013). Least-privilege IAM user `policylens` created with a single scoped
`bedrock:InvokeModel` permission.

## Phase 3 — Frontend + deploy

**Prompt:** "yes" (go-ahead after the Phase 2 gate), then "i also want a UI
deployed on aws" and "make sure no secrets are exposed".

Built the frontend, the local IAM export tool, and the deploy path:

- `frontend/` — plain HTML/JS (no build step, clean Amplify deploy). Three input
  modes: paste, file upload (with a multi-policy list view for a
  fetch_policies.py export array), and a 5-policy sample gallery. Results show
  ranked findings merged with the AI explanation/impact/fix, plus a side-by-side
  original vs. rewritten diff with LCS line highlighting. Degraded and error
  states handled. `frontend/config.js` holds the one value to change (the Lambda
  Function URL).
- `scripts/fetch_policies.py` — local, read-only, paginated IAM export
  (iam:List*/Get*). Credentials never leave the machine. Handles URL-encoded and
  dict policy documents.
- `tests/test_fetch_policies.py` — mocked IAM client, asserts pagination and the
  export JSON shape. No live AWS.
- `scripts/dev_server.py` — local-dev-only server (stdlib) that serves the
  frontend and runs the real handler on one origin, so the UI checklist can be
  walked before deploying.
- `scripts/package_lambda.sh`, `amplify.yml`, `docs/DEPLOY.md`,
  `docs/FRONTEND_CHECKLIST.md` — deployment (Lambda Function URL + Amplify) and
  the manual UI test checklist.

Security pass before publishing: `.gitignore` extended to exclude `.venv`, the
Lambda zip, and any `*-policies.json` export (which contains real account ARNs);
the build zip deleted; the real AWS account ID replaced with the canonical
`123456789012` example everywhere; repo scanned for key material (none).
