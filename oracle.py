from typing import Any

from engine.models import TestCase


def score_severity(case: TestCase, canary_found: bool) -> tuple[str, float]:
    if case.vulnerability == "existence_oracle":
        return "LOW", 3.1
    sensitivity_weight = {"high": 4.0, "medium": 2.5, "low": 1.0}
    base_score = 3.8 + sensitivity_weight.get(case.sensitivity, 2.5)
    if case.write:
        base_score += 1.8
    if canary_found:
        base_score += 0.8
    score = min(10.0, round(base_score, 1))
    if score >= 9:
        return "CRITICAL", score
    if score >= 7:
        return "HIGH", score
    if score >= 4:
        return "MEDIUM", score
    return "LOW", score


def evaluate(
    case: TestCase,
    status_code: int | None,
    response_body: Any,
    foreign_canaries: list[str],
    requester_tenant: str | None = None,
) -> tuple[str, dict[str, Any] | None]:
    requester_tenant = requester_tenant or case.tenant_id
    body_text = str(response_body)
    found_canaries = [canary for canary in foreign_canaries if canary in body_text]

    if status_code is None:
        return "INCONCLUSIVE", None

    if case.vulnerability == "existence_oracle" and case.expected == "DENY":
        if status_code == 403:
            return "EXISTENCE ORACLE", {
                "severity": "LOW",
                "score": 3.1,
                "canaries": [],
                "explanation": "A forbidden response distinguishes an existing foreign ID from a missing ID.",
            }

    resource_body = response_body.get("resource", {}) if isinstance(response_body, dict) else {}
    mass_assignment = (
        case.vulnerability == "mass_assignment"
        and isinstance(resource_body, dict)
        and "tenant_id" in resource_body
        and resource_body.get("tenant_id") != case.tenant_id
    )
    foreign_owner_exposed = False

    def contains_foreign_resource(value: Any) -> bool:
        nonlocal foreign_owner_exposed
        if isinstance(value, dict):
            owner = value.get("tenant_id")
            if owner is not None and str(owner) != requester_tenant:
                exposed_fields = set(value) - {"tenant_id", "id"}
                if exposed_fields:
                    foreign_owner_exposed = True
                    return True
            return any(contains_foreign_resource(item) for item in value.values())
        if isinstance(value, list):
            return any(contains_foreign_resource(item) for item in value)
        return False

    contains_foreign_resource(response_body)
    unauthorized_write = (
        case.expected == "DENY"
        and case.write
        and case.vulnerability != "mass_assignment"
        and status_code < 300
    )

    if found_canaries or foreign_owner_exposed or mass_assignment or unauthorized_write:
        verdict = (
            "PROVEN LEAK"
            if found_canaries
            else "WRITE VIOLATION"
            if mass_assignment
            else "LEAK"
            if foreign_owner_exposed
            else "WRITE VIOLATION"
        )
        severity, score = score_severity(case, bool(found_canaries))
        finding = {
            "severity": severity,
            "score": score,
            "canaries": found_canaries,
            "explanation": (
                "The response contains a foreign tenant's exact canary value."
                if found_canaries
                else "The request changed resource ownership despite the policy prohibition."
                if mass_assignment
                else "The response contains a resource object owned by another tenant."
                if foreign_owner_exposed
                else "The API accepted a write operation denied by the role or tenant policy."
            ),
        }
        if mass_assignment:
            finding["ownership_change"] = {
                "field": "tenant_id",
                "expected": case.tenant_id,
                "observed": resource_body["tenant_id"],
            }
        return verdict, finding

    if case.expected == "ALLOW" and status_code in (401, 403, 404):
        return "OVER-RESTRICTED", {
            "severity": "MEDIUM",
            "score": 5.0,
            "canaries": [],
            "explanation": "The policy allows this principal to access the resource, but the API denied it.",
        }

    if 200 <= status_code < 300 and case.expected == "DENY":
        if case.vulnerability == "mass_assignment":
            return "PASS", None
        return "INCONCLUSIVE", None
    if 200 <= status_code < 300:
        return "PASS", None
    if status_code in (401, 403, 404):
        return "PASS", None
    return "INCONCLUSIVE", None
