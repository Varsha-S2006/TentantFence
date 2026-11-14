import asyncio
from pathlib import Path

import httpx

from backend import vulnerable_api
from engine.evidence import build_evidence
from engine.executor import execute_scan
from engine.oracle import evaluate
from engine.policy import load_policy
from engine.models import TestCase as EngineTestCase


def run_in_mode(mode: str):
    async def scan():
        transport = httpx.ASGITransport(app=vulnerable_api.app)
        async with httpx.AsyncClient(
            base_url="http://127.0.0.1:8001", transport=transport
        ) as client:
            response = await client.post("/admin/mode", json={"mode": mode})
            assert response.status_code == 200
            legacy = await client.get(
                "/vulnerable/invoices/102", headers={"X-User-ID": "alice"}
            )
            secure_legacy = await client.get(
                "/secure/invoices/102", headers={"X-User-ID": "alice"}
            )
            if mode == "secure":
                assert legacy.status_code == 404
                assert secure_legacy.status_code == 404
            else:
                assert legacy.status_code == 200
                assert "CANARY-B-102-x9f3" in legacy.text
        policy = load_policy(Path(__file__).resolve().parents[1] / "backend" / "policy.json")
        return await execute_scan("test-scan", policy, transport=transport)

    return asyncio.run(scan())


def test_vulnerable_mode_detects_all_seeded_vulnerabilities():
    report = run_in_mode("vulnerable")
    found = {finding["vulnerability"] for finding in report.findings}
    expected = {
        "classic_bola",
        "write_bola",
        "role_access",
        "list_leakage",
        "header_spoofing",
        "jwt_claim_trust",
        "existence_oracle",
        "nested_bypass",
        "mass_assignment",
    }
    assert expected <= found
    assert any("CANARY-B-102-x9f3" in finding["evidence"]["canaries"] for finding in report.findings)
    ownership_finding = next(
        finding
        for finding in report.findings
        if finding["vulnerability"] == "mass_assignment"
    )
    assert ownership_finding["evidence"]["ownership_change"]["observed"] != "tenant_A"
    assert report.mode == "vulnerable"


def test_seed_policy_has_three_isolated_synthetic_tenants():
    policy = load_policy()
    tenant_ids = {tenant["tenant_id"] for tenant in policy["tenants"]}
    assert len(tenant_ids) == 3
    principals = {user["name"]: user["tenant_id"] for user in policy["principals"]}
    assert {principals["Alice"], principals["Bob"], principals["Charlie"]} == tenant_ids
    for tenant_id in tenant_ids:
        tenant_resources = [
            resource for resource in policy["resources"] if resource["tenant_id"] == tenant_id
        ]
        assert {"invoice", "document", "record"} <= {
            resource["type"] for resource in tenant_resources
        }


def test_secure_mode_has_no_findings():
    report = run_in_mode("secure")
    assert report.findings == []
    assert report.mode == "secure"


def test_success_without_foreign_data_is_not_a_confirmed_leak():
    case = EngineTestCase(
        case_id="unproven-200",
        principal="alice",
        resource_type="invoice",
        resource_id="102",
        tenant_id="tenant_B",
        sensitivity="high",
        method="GET",
        path="/invoices/102",
        expected="DENY",
        vulnerability="classic_bola",
    )
    verdict, finding = evaluate(case, 200, {"ok": True}, ["CANARY-B-102-x9f3"])
    assert verdict == "INCONCLUSIVE"
    assert finding is None


def test_evidence_redacts_tokens_secrets_and_keeps_canary():
    evidence = build_evidence(
        "GET",
        "http://127.0.0.1:8001/invoices/102?token=query-secret",
        {
            "X-User-ID": "alice",
            "X-Auth-Token": "header-secret",
            "Authorization": "Bearer authorization-secret",
        },
        {"secret": "body-secret"},
        200,
        '{"token":"response-secret","canary":"CANARY-B-102-x9f3"}',
        ["CANARY-B-102-x9f3"],
    )
    serialized = str(evidence)
    for secret in (
        "query-secret",
        "header-secret",
        "authorization-secret",
        "body-secret",
        "response-secret",
    ):
        assert secret not in serialized
    assert "CANARY-B-102-x9f3" in serialized
    assert "X-User-ID" in evidence["request"]["headers"]


def test_canary_drives_proof_grade_verdict():
    case = EngineTestCase(
        case_id="canary",
        principal="alice",
        resource_type="invoice",
        resource_id="102",
        tenant_id="tenant_B",
        sensitivity="high",
        method="GET",
        path="/invoices/102",
        expected="DENY",
        vulnerability="classic_bola",
    )
    verdict, finding = evaluate(case, 200, {"invoice": "CANARY-B-102-x9f3"}, ["CANARY-B-102-x9f3"])
    assert verdict == "PROVEN LEAK"
    assert finding is not None
