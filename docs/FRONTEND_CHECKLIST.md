# Frontend manual test checklist

Automated tests cover the rule engine, the Bedrock validator, and
fetch_policies. The UI is verified by hand with this checklist. Run it twice:
once locally with the dev server, once against the deployed Amplify URL.

## Start the local dev server

```bash
AWS_PROFILE=policylens .venv/bin/python scripts/dev_server.py
# open http://localhost:8000
```

(With creds set you get real AI output; without them the app degrades to
deterministic findings, which is fine for testing the UI.)

## Checklist

### Sample chips (the judge's fast path — one click)
- [ ] Click a sample chip. It fills the box AND analyzes in one click; the page
      scrolls to results.
- [ ] "Clean S3 read-only role" produces **zero findings** and the green "looks
      well scoped" summary, no rewrite panel.
- [ ] "Overprivileged deploy role" flags PASSROLE_UNCONSTRAINED + wildcards,
      ranked CRITICAL first with colored severity chips.
- [ ] Each finding shows rule_id, statement index, plain-English detail, and
      (with AI on) Impact and Fix lines. The side-by-side rewrite appears with
      changed lines highlighted.

### Paste flow
- [ ] Paste a messy policy (e.g. `samples/03_messy_deploy_role.json`), click
      Analyze policy. Same results render.

### File upload flow (inline "upload a .json file" link)
- [ ] Upload a single policy `.json` (any file in `samples/` except the
      malformed one): it fills the box and analyzes automatically.
- [ ] Generate an export and upload it:
      `AWS_PROFILE=policylens python scripts/fetch_policies.py --profile policylens`
      then upload `policylens-policies.json`.
- [ ] The multi-policy list appears with one row per policy (role name +
      inline/managed badge). Clicking a row reviews that one policy.

### Error + degraded states
- [ ] Paste malformed JSON (copy `samples/06_malformed.json`): a clean red error
      message appears, no stack trace, no results panel.
- [ ] Empty input + Analyze: prompted to add a policy first.
- [ ] Degraded path: stop the dev server's creds (run it with no AWS_PROFILE) and
      analyze a policy. The summary shows the "AI step unavailable" banner and
      the deterministic findings still render.

### Deployed / logged-out check (Phase 3 gate)
- [ ] Set `frontend/config.js` API_URL to the Lambda Function URL, push, let
      Amplify redeploy.
- [ ] Open the Amplify URL in an **incognito window** (no AWS login). All three
      input modes work end to end.
- [ ] The GitHub repo is public.
