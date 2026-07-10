"""PolicyLens Layer 1 — deterministic IAM policy checks.

Pure Python, no AWS, no LLM. This layer is the source of truth for WHAT is
wrong with a policy. The Bedrock layer (Layer 2) only explains and rewrites
what this file finds; it never invents new findings.

Each rule returns zero or more Finding dicts:
    {"rule_id": str, "severity": str, "statement_index": int, "detail": str}

statement_index is 0-based into the policy's Statement list, or -1 for
document-level findings that are not tied to a single statement.
"""

from __future__ import annotations

import json
from typing import Any, Callable

# Severity levels, ordered most to least severe. Used for ranking output.
SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
}

Finding = dict[str, Any]

# Actions that grant or escalate access and should never be wide open without
# a Condition scoping who/what can use them.
SENSITIVE_ACTIONS: frozenset[str] = frozenset(
    {
        "sts:assumerole",
        "kms:decrypt",
        "secretsmanager:getsecretvalue",
    }
)

# iam:* is treated as sensitive via its service prefix below.
SENSITIVE_SERVICE_PREFIXES: frozenset[str] = frozenset({"iam:"})

# Privilege-escalation actions. Any of these on Resource "*" adds up to admin
# because they let a principal grant themselves further permissions.
ADMIN_EQUIVALENT_ACTIONS: frozenset[str] = frozenset(
    {
        "iam:createpolicyversion",
        "iam:setdefaultpolicyversion",
        "iam:attachuserpolicy",
        "iam:attachrolepolicy",
        "iam:attachgrouppolicy",
        "iam:putuserpolicy",
        "iam:putrolepolicy",
        "iam:putgrouppolicy",
        "iam:createaccesskey",
        "iam:updateassumerolepolicy",
    }
)

# Read-only action verb prefixes. WILDCARD_RESOURCE is only HIGH when the
# statement grants non-read actions on "*". A statement that is purely reads
# on "*" is common and much less dangerous, so we skip it there.
READ_ONLY_VERBS: tuple[str, ...] = (
    "get",
    "list",
    "describe",
    "head",
    "batchget",
    "view",
    "search",
    "query",
    "scan",
    "read",
)


def _as_list(value: Any) -> list[Any]:
    """Normalize a field that may be a string, a list, or absent into a list.

    IAM allows Action/Resource/Principal to be a single string or a list.
    Missing fields become an empty list so callers can iterate uniformly.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _statements(policy: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the policy's statements as a list.

    Handles the single-statement-not-wrapped-in-a-list form and skips any
    non-dict entries defensively.
    """
    raw = policy.get("Statement")
    if raw is None:
        return []
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, list):
        return [s for s in raw if isinstance(s, dict)]
    return []


def _actions_lower(statement: dict[str, Any], key: str = "Action") -> list[str]:
    """Return the statement's actions, lowercased, as strings only."""
    return [a.lower() for a in _as_list(statement.get(key)) if isinstance(a, str)]


def _is_read_only_action(action: str) -> bool:
    """True if an action's verb looks read-only (best-effort, by prefix)."""
    action = action.lower()
    if action == "*":
        return False
    verb = action.split(":", 1)[1] if ":" in action else action
    return verb.startswith(READ_ONLY_VERBS)


def _has_condition(statement: dict[str, Any]) -> bool:
    """True if the statement carries a non-empty Condition block."""
    cond = statement.get("Condition")
    return isinstance(cond, dict) and len(cond) > 0


def _condition_keys_lower(statement: dict[str, Any]) -> set[str]:
    """Collect all condition keys used in a statement, lowercased.

    Condition shape is {operator: {key: value}}. We only care which keys
    appear, regardless of operator.
    """
    keys: set[str] = set()
    cond = statement.get("Condition")
    if not isinstance(cond, dict):
        return keys
    for operand in cond.values():
        if isinstance(operand, dict):
            keys.update(k.lower() for k in operand.keys())
    return keys


def _finding(rule_id: str, severity: str, index: int, detail: str) -> Finding:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "statement_index": index,
        "detail": detail,
    }


# --- Individual rules ------------------------------------------------------
# Each rule takes (statement, index) and returns a list of findings.
# Document-level checks are handled separately in run_checks.


def _rule_wildcard_action(statement: dict[str, Any], index: int) -> list[Finding]:
    """Rule 1: Action "*" (CRITICAL) or service:* (HIGH)."""
    findings: list[Finding] = []
    if statement.get("Effect") != "Allow":
        return findings
    for action in _actions_lower(statement):
        if action == "*":
            findings.append(
                _finding(
                    "WILDCARD_ACTION",
                    "CRITICAL",
                    index,
                    'Action "*" grants every action in every service.',
                )
            )
        elif action.endswith(":*"):
            service = action.split(":", 1)[0]
            findings.append(
                _finding(
                    "WILDCARD_ACTION",
                    "HIGH",
                    index,
                    f'Action "{service}:*" grants every action in {service}.',
                )
            )
    return findings


def _rule_wildcard_resource(statement: dict[str, Any], index: int) -> list[Finding]:
    """Rule 2: Resource "*" on non-read-only actions (HIGH)."""
    if statement.get("Effect") != "Allow":
        return []
    resources = [r for r in _as_list(statement.get("Resource")) if isinstance(r, str)]
    if "*" not in resources:
        return []
    actions = _actions_lower(statement)
    # If every action is clearly read-only, "*" is far less dangerous; skip.
    non_read = [a for a in actions if not _is_read_only_action(a)]
    if actions and not non_read:
        return []
    return [
        _finding(
            "WILDCARD_RESOURCE",
            "HIGH",
            index,
            'Resource "*" lets these actions hit every resource in the account.',
        )
    ]


def _rule_no_condition_sensitive(
    statement: dict[str, Any], index: int
) -> list[Finding]:
    """Rule 3: sensitive actions with no Condition block (HIGH)."""
    if statement.get("Effect") != "Allow":
        return []
    if _has_condition(statement):
        return []
    hits: list[str] = []
    for action in _actions_lower(statement):
        if action in SENSITIVE_ACTIONS:
            hits.append(action)
        elif any(action.startswith(p) for p in SENSITIVE_SERVICE_PREFIXES):
            hits.append(action)
    if not hits:
        return []
    shown = ", ".join(sorted(set(hits)))
    return [
        _finding(
            "NO_CONDITION_SENSITIVE",
            "HIGH",
            index,
            f"Sensitive actions ({shown}) are allowed with no Condition to scope them.",
        )
    ]


def _rule_passrole_unconstrained(
    statement: dict[str, Any], index: int
) -> list[Finding]:
    """Rule 4: iam:PassRole without a scoping Condition or scoped Resource (CRITICAL)."""
    if statement.get("Effect") != "Allow":
        return []
    actions = _actions_lower(statement)
    passes_role = "iam:passrole" in actions or any(
        a in ("iam:*", "*") for a in actions
    )
    if not passes_role:
        return []
    # Constrained if a Condition restricts iam:PassedToService, OR the Resource
    # is scoped to specific role ARNs (not "*").
    cond_keys = _condition_keys_lower(statement)
    has_passedto = "iam:passedtoservice" in cond_keys
    resources = [r for r in _as_list(statement.get("Resource")) if isinstance(r, str)]
    scoped_resource = bool(resources) and "*" not in resources
    if has_passedto or scoped_resource:
        return []
    return [
        _finding(
            "PASSROLE_UNCONSTRAINED",
            "CRITICAL",
            index,
            "iam:PassRole is allowed without restricting which role or which service "
            "it can be passed to, enabling privilege escalation.",
        )
    ]


def _rule_notaction_allow(statement: dict[str, Any], index: int) -> list[Finding]:
    """Rule 5: Allow + NotAction (HIGH)."""
    if statement.get("Effect") == "Allow" and "NotAction" in statement:
        return [
            _finding(
                "NOTACTION_ALLOW",
                "HIGH",
                index,
                "Allow combined with NotAction grants everything except the listed "
                "actions, which is almost always broader than intended.",
            )
        ]
    return []


def _rule_notresource_allow(statement: dict[str, Any], index: int) -> list[Finding]:
    """Rule 6: Allow + NotResource (HIGH)."""
    if statement.get("Effect") == "Allow" and "NotResource" in statement:
        return [
            _finding(
                "NOTRESOURCE_ALLOW",
                "HIGH",
                index,
                "Allow combined with NotResource grants access to every resource "
                "except the listed ones, which is almost always broader than intended.",
            )
        ]
    return []


def _rule_admin_equivalent(statement: dict[str, Any], index: int) -> list[Finding]:
    """Rule 7: privilege-escalation actions on Resource "*" (CRITICAL)."""
    if statement.get("Effect") != "Allow":
        return []
    actions = set(_actions_lower(statement))
    esc = sorted(actions & ADMIN_EQUIVALENT_ACTIONS)
    if not esc:
        return []
    resources = [r for r in _as_list(statement.get("Resource")) if isinstance(r, str)]
    if resources and "*" not in resources:
        # Scoped to specific resources; still risky but not blanket admin.
        return []
    shown = ", ".join(esc)
    return [
        _finding(
            "ADMIN_EQUIVALENT",
            "CRITICAL",
            index,
            f"Privilege-escalation actions ({shown}) on unrestricted resources let a "
            "principal grant itself full administrator access.",
        )
    ]


def _rule_missing_mfa_condition(
    statement: dict[str, Any], index: int
) -> list[Finding]:
    """Rule 8: privileged actions without an MFA condition (MEDIUM).

    Privileged here means a sensitive action or an iam:* action. Only flagged
    when the statement is not already caught by NO_CONDITION_SENSITIVE having
    an MFA key would satisfy both, so we check the MFA key specifically.
    """
    if statement.get("Effect") != "Allow":
        return []
    actions = _actions_lower(statement)
    privileged = [
        a
        for a in actions
        if a in SENSITIVE_ACTIONS
        or any(a.startswith(p) for p in SENSITIVE_SERVICE_PREFIXES)
        or a == "*"
    ]
    if not privileged:
        return []
    cond_keys = _condition_keys_lower(statement)
    if "aws:multifactorauthpresent" in cond_keys:
        return []
    return [
        _finding(
            "MISSING_MFA_CONDITION",
            "MEDIUM",
            index,
            "Privileged actions are allowed without requiring "
            "aws:MultiFactorAuthPresent, so a leaked long-term key alone can use them.",
        )
    ]


def _rule_overbroad_principal(
    statement: dict[str, Any], index: int
) -> list[Finding]:
    """Rule 9: resource-policy Principal "*" with no Condition (CRITICAL)."""
    if statement.get("Effect") != "Allow":
        return []
    principal = statement.get("Principal")
    if principal is None:
        return []
    is_wildcard = principal == "*" or (
        isinstance(principal, dict)
        and any(
            v == "*" or (isinstance(v, list) and "*" in v)
            for v in principal.values()
        )
    )
    if not is_wildcard:
        return []
    if _has_condition(statement):
        return []
    return [
        _finding(
            "OVERBROAD_PRINCIPAL",
            "CRITICAL",
            index,
            'Principal "*" with no Condition exposes this resource to the entire '
            "internet (every AWS account and anonymous callers).",
        )
    ]


# Per-statement rules run in a fixed order for stable output.
_STATEMENT_RULES: tuple[Callable[[dict[str, Any], int], list[Finding]], ...] = (
    _rule_wildcard_action,
    _rule_wildcard_resource,
    _rule_no_condition_sensitive,
    _rule_passrole_unconstrained,
    _rule_notaction_allow,
    _rule_notresource_allow,
    _rule_admin_equivalent,
    _rule_missing_mfa_condition,
    _rule_overbroad_principal,
)


def _rule_stale_sid_or_empty(policy: dict[str, Any]) -> list[Finding]:
    """Rule 10: empty statements and duplicate Sids (LOW, hygiene).

    Document-level because duplicate Sids are only visible across statements.
    """
    findings: list[Finding] = []
    statements = _statements(policy)
    seen_sids: dict[str, int] = {}
    for index, statement in enumerate(statements):
        # Empty statement: no Action/NotAction and no Resource/NotResource.
        has_action = bool(
            _as_list(statement.get("Action")) or _as_list(statement.get("NotAction"))
        )
        has_resource = bool(
            _as_list(statement.get("Resource"))
            or _as_list(statement.get("NotResource"))
            or statement.get("Principal") is not None
        )
        if not has_action and not has_resource:
            findings.append(
                _finding(
                    "STALE_SID_OR_EMPTY",
                    "LOW",
                    index,
                    "Statement has no actions and no resources; it does nothing and "
                    "should be removed.",
                )
            )
        sid = statement.get("Sid")
        if isinstance(sid, str) and sid:
            if sid in seen_sids:
                findings.append(
                    _finding(
                        "STALE_SID_OR_EMPTY",
                        "LOW",
                        index,
                        f'Duplicate Sid "{sid}" (first used at statement '
                        f"{seen_sids[sid]}); Sids should be unique.",
                    )
                )
            else:
                seen_sids[sid] = index
    return findings


class PolicyParseError(ValueError):
    """Raised when input is not a usable IAM policy document."""


def parse_policy(raw: str | bytes | dict[str, Any]) -> dict[str, Any]:
    """Parse and lightly validate an IAM policy document.

    Accepts a JSON string/bytes or an already-parsed dict. Raises
    PolicyParseError with a clean message on malformed JSON or a shape that is
    not a policy document. Never leaks a stack trace to the caller.
    """
    if isinstance(raw, dict):
        policy = raw
    else:
        try:
            policy = json.loads(raw)
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise PolicyParseError(f"Input is not valid JSON: {exc}") from exc
    if not isinstance(policy, dict):
        raise PolicyParseError("Policy must be a JSON object, not a list or scalar.")
    if "Statement" not in policy:
        raise PolicyParseError('Policy is missing the required "Statement" field.')
    if not _statements(policy) and policy.get("Statement") not in ([], {}):
        raise PolicyParseError('"Statement" must be an object or a list of objects.')
    return policy


def rank(findings: list[Finding]) -> list[Finding]:
    """Sort findings most-severe first, then by statement order, stably."""
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(f["severity"], 99),
            f["statement_index"] if f["statement_index"] >= 0 else 1_000_000,
        ),
    )


def run_checks(raw: str | bytes | dict[str, Any]) -> list[Finding]:
    """Run all Layer 1 rules against a policy and return ranked findings.

    `raw` may be a JSON string/bytes or a parsed dict. Raises PolicyParseError
    on malformed input; callers (the Lambda handler) turn that into a clean
    error response.
    """
    policy = parse_policy(raw)
    findings: list[Finding] = []
    for index, statement in enumerate(_statements(policy)):
        for rule in _STATEMENT_RULES:
            findings.extend(rule(statement, index))
    findings.extend(_rule_stale_sid_or_empty(policy))
    return rank(findings)


def run_checks_safe(raw: str | bytes | dict[str, Any]) -> dict[str, Any]:
    """Handler-friendly wrapper: never raises.

    Returns {"ok": True, "findings": [...]} or
    {"ok": False, "error": "clean message"}.
    """
    try:
        return {"ok": True, "findings": run_checks(raw)}
    except PolicyParseError as exc:
        return {"ok": False, "error": str(exc)}
