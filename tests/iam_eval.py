"""Small offline IAM evaluator for the example policies and generated session policies.

It models only what these policies use: Allow/Deny, Action/NotAction wildcards, Resource
wildcards, ``${aws:PrincipalTag/...}`` variables, ``${placeholder}`` substitution and the
condition operators listed below. Any other operator fails the test rather than being
ignored. It is evidence about policy text, not about AWS acceptance.
"""

from __future__ import annotations

import re
from fnmatch import fnmatchcase
from typing import Any

_VARIABLE = re.compile(r"\$\{([^}]+)\}")
SUPPORTED = {
    "StringEquals",
    "StringLike",
    "StringEqualsIfExists",
    "Bool",
    "NumericLessThanEquals",
    "ForAllValues:StringEquals",
}


def _seq(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _substitute(text: str, context: dict[str, str], placeholders: dict[str, str]) -> str | None:
    missing = False

    def repl(match: re.Match[str]) -> str:
        nonlocal missing
        key = match.group(1)
        if key.startswith("aws:"):
            if key not in context:
                missing = True
                return ""
            return context[key]
        return placeholders[key]

    result = _VARIABLE.sub(repl, text)
    return None if missing else result


def _condition_ok(
    conditions: dict[str, dict[str, Any]], context: dict[str, str], placeholders: dict[str, str]
) -> bool:
    for operator, entries in conditions.items():
        if operator not in SUPPORTED:
            raise AssertionError(f"unsupported condition operator {operator}")
        for key, expected in entries.items():
            values = [_substitute(str(v), context, placeholders) for v in _seq(expected)]
            actual = context.get(key)
            if operator == "ForAllValues:StringEquals":
                # Multi-valued keys are given comma-joined. A key absent from the request is
                # vacuously satisfied (AWS semantics): the statement then relies on its other
                # conditions.
                if actual is not None and not all(a in values for a in actual.split(",")):
                    return False
                continue
            if actual is None:
                if operator.endswith("IfExists"):
                    continue
                return False
            if operator.startswith("StringEquals"):
                ok = actual in values
            elif operator == "StringLike":
                ok = any(v is not None and fnmatchcase(actual, v) for v in values)
            elif operator == "Bool":
                ok = actual.lower() in [str(v).lower() for v in values]
            else:  # NumericLessThanEquals
                ok = all(v is not None and float(actual) <= float(v) for v in values)
            if not ok:
                return False
    return True


def _statement_matches(
    statement: dict[str, Any],
    action: str,
    resource: str,
    context: dict[str, str],
    placeholders: dict[str, str],
) -> bool:
    if "Action" in statement:
        acted = any(fnmatchcase(action.lower(), a.lower()) for a in _seq(statement["Action"]))
    else:
        acted = not any(
            fnmatchcase(action.lower(), a.lower()) for a in _seq(statement["NotAction"])
        )
    if not acted:
        return False
    resources = [_substitute(r, context, placeholders) for r in _seq(statement["Resource"])]
    if not any(r is not None and fnmatchcase(resource, r) for r in resources):
        return False
    return _condition_ok(statement.get("Condition", {}), context, placeholders)


def decision(
    policy: dict[str, Any],
    action: str,
    resource: str,
    context: dict[str, str],
    placeholders: dict[str, str],
) -> str:
    effects = [
        s["Effect"]
        for s in policy["Statement"]
        if _statement_matches(s, action, resource, context, placeholders)
    ]
    if "Deny" in effects:
        return "deny"
    return "allow" if "Allow" in effects else "implicit"


def allowed(
    policies: list[dict[str, Any]],
    action: str,
    resource: str,
    context: dict[str, str],
    placeholders: dict[str, str],
) -> bool:
    """Effective permission: every policy (role and session) must allow; any deny wins."""
    results = [decision(p, action, resource, context, placeholders) for p in policies]
    return all(r == "allow" for r in results)
