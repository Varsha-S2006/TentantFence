import json
from pathlib import Path
from typing import Any


def load_policy(path: Path | None = None) -> dict[str, Any]:
    policy_path = path or Path(__file__).resolve().parents[1] / "backend" / "policy.json"
    with policy_path.open(encoding="utf-8") as policy_file:
        policy = json.load(policy_file)
    if "principals" not in policy or "resources" not in policy:
        raise ValueError("policy.json must define principals and resources")
    return policy


def expected_access(
    principal: dict[str, Any],
    resource: dict[str, Any],
    rules: dict[str, str] | None = None,
) -> str:
    rules = rules or {}
    if principal["tenant_id"] == resource["tenant_id"]:
        policy_rule = (
            rules.get("same_tenant_admin", rules.get("same_tenant", "allow"))
            if principal.get("role") == "admin"
            else rules.get("same_tenant", "allow")
        )
    else:
        policy_rule = rules.get("cross_tenant", "deny")
    return policy_rule.upper()
