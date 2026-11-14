from typing import Any

from engine.discovery import Route
from engine.models import TestCase
from engine.policy import expected_access


def build_test_cases(
    policy: dict[str, Any], routes: list[Route]
) -> list[TestCase]:
    route_keys = {(route.path, route.method) for route in routes}
    cases: list[TestCase] = []

    def add(
        principal: dict[str, Any],
        resource: dict[str, Any],
        method: str,
        path: str,
        vulnerability: str,
        *,
        expected: str | None = None,
        headers: dict[str, str] | None = None,
        query: dict[str, str] | None = None,
        payload: dict[str, Any] | None = None,
        write: bool = False,
    ) -> None:
        if (path, method) not in route_keys:
            return
        path = path.format(
            invoice_id=resource["id"],
            project_id=resource["id"],
            user_id=resource["id"],
            document_id=resource["id"],
            record_id=resource["id"],
            tenant_id=resource["tenant_id"],
        )
        cases.append(
            TestCase(
                case_id=f"{principal['user_id']}:{resource['type']}:{resource['id']}:{vulnerability}:{method}",
                principal=principal["user_id"],
                resource_type=resource["type"],
                resource_id=resource["id"],
                tenant_id=resource["tenant_id"],
                sensitivity=resource.get("sensitivity", "medium"),
                method=method,
                path=path,
                expected=expected
                or (
                    "DENY"
                    if write and principal.get("role") == "viewer"
                    else expected_access(principal, resource, policy.get("rules"))
                ),
                vulnerability=vulnerability,
                headers=headers or {},
                query=query or {},
                payload=payload,
                write=write,
            )
        )

    for principal in policy["principals"]:
        for resource in policy["resources"]:
            resource_type = resource["type"]
            if resource_type == "invoice":
                add(
                    principal,
                    resource,
                    "GET",
                    "/invoices/{invoice_id}",
                    "classic_bola",
                )
                if principal["tenant_id"] != resource["tenant_id"]:
                    add(
                        principal,
                        resource,
                        "GET",
                        "/invoices/{invoice_id}",
                        "header_spoofing",
                        headers={"X-Tenant-ID": resource["tenant_id"]},
                    )
                    add(
                        principal,
                        resource,
                        "GET",
                        "/invoices/{invoice_id}",
                        "jwt_claim_trust",
                        headers={"X-Tenant-Claim": resource["tenant_id"]},
                    )
                    add(
                        principal,
                        resource,
                        "GET",
                        "/tenants/{tenant_id}/invoices/{invoice_id}",
                        "nested_bypass",
                    )
                    add(
                        principal,
                        resource,
                        "GET",
                        "/vulnerable/invoices/{invoice_id}/existence",
                        "existence_oracle",
                    )
                    add(
                        principal,
                        resource,
                        "GET",
                        "/invoices",
                        "list_leakage",
                        expected="DENY",
                        query={"tenant_id": resource["tenant_id"]},
                    )

                add(
                    principal,
                    resource,
                    "PUT",
                    "/invoices/{invoice_id}",
                    "write_bola",
                    payload={"description": "TenantFence authorization probe"},
                    write=True,
                )
                add(
                    principal,
                    resource,
                    "DELETE",
                    "/invoices/{invoice_id}",
                    "write_bola",
                    write=True,
                )
                other_tenant = next(
                    tenant["tenant_id"]
                    for tenant in policy["principals"]
                    if tenant["tenant_id"] != resource["tenant_id"]
                )
                add(
                    principal,
                    resource,
                    "PATCH",
                    "/invoices/{invoice_id}",
                    "mass_assignment",
                    expected=policy.get("rules", {}).get(
                        "tenant_mutation", "deny"
                    ).upper(),
                    payload={"tenant_id": other_tenant},
                    write=True,
                )
            elif resource_type == "project":
                add(
                    principal,
                    resource,
                    "GET",
                    "/projects/{project_id}",
                    "classic_bola",
                )
            elif resource_type == "user":
                add(
                    principal,
                    resource,
                    "GET",
                    "/users/{user_id}",
                    "classic_bola",
                )
            elif resource_type == "document":
                add(
                    principal,
                    resource,
                    "GET",
                    "/documents/{document_id}",
                    "classic_bola",
                )
            elif resource_type == "record":
                add(
                    principal,
                    resource,
                    "GET",
                    "/records/{record_id}",
                    "classic_bola",
                )

    viewer = next(
        (principal for principal in policy["principals"] if principal.get("role") == "viewer"),
        None,
    )
    viewer_resource = next(
        (
            resource
            for resource in policy["resources"]
            if viewer and resource["tenant_id"] == viewer["tenant_id"] and resource["type"] == "invoice"
        ),
        None,
    )
    if viewer and viewer_resource:
        add(
            viewer,
            viewer_resource,
            "PUT",
            "/invoices/{invoice_id}",
            "role_access",
            expected="DENY",
            payload={"description": "TenantFence role authorization probe"},
            write=True,
        )

    if policy["principals"] and policy["resources"]:
        principal = policy["principals"][0]
        invoice = next(
            (resource for resource in policy["resources"] if resource["type"] == "invoice"),
            None,
        )
        if invoice:
            add(
                principal,
                invoice,
                "GET",
                "/invoices/{invoice_id}",
                "invalid_auth",
                expected="DENY",
                headers={"X-User-ID": "invalid-demo-user"},
            )
            missing_invoice = {**invoice, "id": "999999"}
            add(
                principal,
                missing_invoice,
                "GET",
                "/invoices/{invoice_id}",
                "nonexistent_resource",
                expected="DENY",
            )
    return cases
