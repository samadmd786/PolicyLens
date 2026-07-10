# Weekend Productivity Challenge: PolicyLens

Tag: #productivity

## The problem

AWS IAM policies are easy to write and hard to read. A policy that grants
`"Action": "*"` on `"Resource": "*"` looks almost identical to a tightly scoped
one at a glance, and the difference is the whole ballgame for security. Most
people paste a policy, skim it, and move on. Reviewing it properly means holding
a lot of IAM trivia in your head: which actions escalate privilege, why
`iam:PassRole` without a condition is dangerous, what NotAction actually expands
to.

PolicyLens does that review for you. You paste an IAM policy JSON and get back
two things: a ranked list of security findings in plain English, each with a
one line note on why it matters, and a rewritten least-privilege version of the
same policy shown side by side with the original.

## What it does

There are three ways to give it a policy. You can paste JSON directly, click a
sample from the gallery to see a result in one click, or upload a file. The
upload path also accepts an export produced by a small local script, so you can
review policies from a real account, one at a time.

Every review returns ranked findings (CRITICAL down to LOW), a short business
impact line per finding, and a tightened rewrite. If the policy is clean, it
says so instead of inventing problems.

## How it was built

The core design decision is deterministic first, AI second, and it is strict.

Layer 1 is a pure Python rule engine with ten checks. It is the source of truth
for what is wrong: wildcard actions, wildcard resources on write actions,
unconstrained `iam:PassRole`, Allow combined with NotAction or NotResource,
privilege escalation combinations that add up to admin, sensitive actions with
no condition, overbroad principals on resource policies, and a few hygiene
checks. It handles the messy realities of IAM JSON: Action and Resource as a
string or a list, a single statement not wrapped in a list, missing optional
fields, and malformed JSON that returns a clean error instead of a stack trace.
This layer has no dependency on AWS at all, so its tests run offline and free.

Layer 2 is an Amazon Bedrock reasoning pass. It takes the original policy and
the Layer 1 findings and produces the plain-English explanations, the business
impact framing, and the rewritten policy. The important rule is that the model
never invents findings. Every finding it returns has to carry a rule ID that
Layer 1 already produced, and the code drops anything else. The rewritten policy
is validated as real IAM JSON before it is ever shown. If Bedrock is throttled
or unavailable, the app degrades to the deterministic findings rather than
failing. The rule engine is the product; the model is presentation.

One deliberate non-feature: PolicyLens never asks for your credentials. Not an
access key, not a temporary token, nothing. The only path to a real account is a
local read-only script that runs on your machine and exports policies to a file
you upload. Your credentials never leave your laptop.

## AWS services and architecture

```
Browser (Amplify Hosting, static HTML/JS)
        |
        |  POST policy JSON
        v
API Gateway (HTTP API)
        |
        v
AWS Lambda
        |
   Layer 1: deterministic checks (pure Python)
        |
   Layer 2: Amazon Bedrock (Nova Micro) reasoning + rewrite
        |
        v
   One JSON response: findings + rewrite
```

- Amazon Bedrock (Nova Micro) for the reasoning pass. Nova Micro is the cheapest
  Bedrock model and runs a full review for roughly two hundredths of a cent.
- AWS Lambda for the backend logic, one model call per review, fronted by an
  API Gateway HTTP API.
- AWS Amplify Hosting for the static frontend.
- The whole backend is one CloudFormation stack, deployed from the terminal with
  no console login.

## What I learned

Putting a deterministic engine in front of the model changed the whole project
for the better. It made the output trustworthy, because findings come from code
you can test, not from a model you have to second guess. It made the tests fast
and free, because the layer that matters most never touches AWS. And it made
graceful degradation natural: when the model call fails, there is still a real
answer to show. Scoping the IAM user down to a single Bedrock permission, and
keeping IAM read access in a separate optional tool, was a small exercise in the
exact least privilege the app preaches.

## Links

- Live app: https://main.d2k0p29miy8scd.amplifyapp.com/
- Source: https://github.com/samadmd786/PolicyLens
