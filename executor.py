import ipaddress
import json
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlsplit

import httpx

from engine.discovery import Route, discover_routes
from engine.evidence import build_evidence
from engine.generator import build_test_cases
from engine.models import ScanReport, TestCase, TestResult
from engine.oracle import evaluate

VULNERABILITIES = (
    "classic_bola",
    "write_bola",
    "role_access",
    "list_leakage",
    "header_spoofing",
    "jwt_claim_trust",
    "existence_oracle",
    "nested_bypass",
    "mass_assignment",
)

FIX_SNIPPET = """def require_same_tenant(principal, resource):
    if principal.tenant_id != resource.tenant_id:
        raise HTTPException(status_code=404, detail=\"Resource not found\")
    return resource
"""


def ensure_local_target(target_url: str) -> None:
    host = urlsplit(target_url).hostname
    if host is None:
        raise ValueError("Target URL must include a hostname")
    if host.lower() == "localhost":
        return
    try:
        if ipaddress.ip_address(host).is_loopback:
            return
    except ValueError:
        pass
    raise ValueError("TenantFence is restricted to localhost/loopback targets")


def _headers(case: TestCase) -> dict[str, str]:
    return {"X-User-ID": case.principal, **case.headers}


async def execute_scan(
    scan_id: str,
    policy: dict[str, Any],
    on_progress: Callable[[dict[str, Any]], None] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> ScanReport:
    target_url = policy["target_url"].rstrip("/")
    ensure_local_target(target_url)
    timeout = httpx.Timeout(6.0, connect=3.0)
    results: list[TestResult] = []
    findings: list[dict[str, Any]] = []

    async with httpx.AsyncClient(
        base_url=target_url, timeout=timeout, transport=transport
    ) as client:
        mode_response = await client.get("/admin/mode")
        mode_response.raise_for_status()
        mode = mode_response.json()["mode"]
        if mode not in ("vulnerable", "secure"):
            raise ValueError("Demo API returned an unsupported target mode")
        routes, used_fallback = await discover_routes(client)
        cases = build_test_cases(policy, routes)
        if not cases:
            raise RuntimeError("OpenAPI discovery found no policy-relevant API routes")

        for index, case in enumerate(cases, start=1):
            def emit_event(stage: str, **details: Any) -> None:
                if on_progress:
                    on_progress(
                        {
                            "type": "scan_event",
                            "stage": stage,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "case_id": case.case_id,
                            "principal": case.principal,
                            "tenant_id": case.tenant_id,
                            "method": case.method,
                            "path": case.path,
                            **details,
                        }
                    )

            reset_response = await client.post("/admin/reset")
            reset_response.raise_for_status()
            flags = {name: False for name in VULNERABILITIES}
            if mode == "vulnerable" and case.vulnerability in flags:
                flags[case.vulnerability] = True
            flags_response = await client.put(
                "/admin/vulnerabilities",
                json={"vulnerabilities": flags},
            )
            flags_response.raise_for_status()
            request_headers = _headers(case)
            response: httpx.Response | None = None
            response_body: Any = {}
            emit_event("authentication_context", detail="Synthetic principal header prepared")
            emit_event("resource_request", detail=f"{case.method} {case.path}")
            try:
                response = await client.request(
                    case.method,
                    case.path,
                    headers=request_headers,
                    params=case.query,
                    json=case.payload,
                )
                try:
                    response_body = response.json()
                except ValueError:
                    response_body = response.text
                status_code: int | None = response.status_code
                error_text = ""
            except httpx.HTTPError as error:
                status_code = None
                error_text = str(error)
                response_body = {"error": error_text}

            emit_event(
                "api_response",
                status_code=status_code,
                detail="HTTP response received" if response is not None else "Request failed",
            )
            principal = next(
                item for item in policy["principals"] if item["user_id"] == case.principal
            )
            foreign_canaries = [
                resource["canary"]
                for resource in policy["resources"]
                if resource["tenant_id"] != principal["tenant_id"]
            ]
            verdict, finding_data = evaluate(
                case,
                status_code,
                response_body,
                foreign_canaries,
                requester_tenant=principal["tenant_id"],
            )
            emit_event(
                "authorization_evaluation",
                expected=case.expected,
                verdict=verdict,
                status_code=status_code,
            )
            differential_confirmed = False
            if (
                mode == "vulnerable"
                and case.vulnerability == "classic_bola"
                and case.expected == "DENY"
                and status_code is not None
                and status_code < 300
                and isinstance(response_body, dict)
            ):
                owner = next(
                    item
                    for item in policy["principals"]
                    if item["tenant_id"] == case.tenant_id
                )
                await client.put(
                    "/admin/vulnerabilities",
                    json={"vulnerabilities": {name: False for name in VULNERABILITIES}},
                )
                owner_response = await client.get(
                    case.path, headers={"X-User-ID": owner["user_id"]}
                )
                if owner_response.status_code < 300:
                    owner_body = owner_response.json()
                    differential_confirmed = (
                        response_body.get("resource") == owner_body.get("resource")
                    )

            response_text = (
                response.text if response is not None else json.dumps(response_body)
            )
            evidence = build_evidence(
                case.method,
                str(response.request.url) if response is not None else f"{target_url}{case.path}",
                request_headers,
                case.payload,
                status_code,
                response_text or error_text,
                finding_data["canaries"] if finding_data else [],
            )
            evidence["differential_confirmed"] = differential_confirmed
            if finding_data and finding_data.get("ownership_change"):
                evidence["ownership_change"] = finding_data["ownership_change"]

            finding = None
            if finding_data:
                finding = {
                    "id": str(uuid.uuid4()),
                    "scan_id": scan_id,
                    "title": f"{finding_data['verdict'] if 'verdict' in finding_data else verdict}: {case.vulnerability}",
                    "verdict": verdict,
                    "vulnerability": case.vulnerability,
                    "severity": finding_data["severity"],
                    "score": finding_data["score"],
                    "principal": case.principal,
                    "principal_tenant": principal["tenant_id"],
                    "resource_type": case.resource_type,
                    "resource_id": case.resource_id,
                    "resource_tenant": case.tenant_id,
                    "expected": case.expected,
                    "status_code": status_code,
                    "differential_confirmed": differential_confirmed,
                    "evidence": evidence,
                    "explanation": finding_data["explanation"],
                    "ownership_change": finding_data.get("ownership_change"),
                    "fix_suggestion": FIX_SNIPPET,
                    "route_fallback_used": used_fallback,
                }
                findings.append(finding)
                emit_event(
                    "vulnerability_confirmation",
                    finding_id=finding["id"],
                    severity=finding["severity"],
                    verdict=verdict,
                )

            result = TestResult(
                case=case,
                status_code=status_code,
                verdict=verdict,
                finding=finding,
                evidence=evidence,
            )
            emit_event(
                "evidence_created",
                finding_id=finding["id"] if finding else None,
                canary_count=len(evidence["canaries"]),
            )
            results.append(result)
            if on_progress:
                on_progress(
                    {
                        "type": "progress",
                        "completed": index,
                        "total": len(cases),
                        "result": result.as_dict(),
                    }
                )

        await client.post("/admin/reset")
        restore_flags = {name: mode == "vulnerable" for name in VULNERABILITIES}
        restore_response = await client.put(
            "/admin/vulnerabilities",
            json={"vulnerabilities": restore_flags},
        )
        restore_response.raise_for_status()

    severity_counts = Counter(finding["severity"] for finding in findings)
    vulnerability_counts = Counter(
        finding["vulnerability"]
        for finding in findings
        if finding["verdict"] in ("PROVEN LEAK", "LEAK")
    )
    risk_score = max(
        0,
        100
        - sum(
            round(finding["score"] * 3)
            for finding in findings
            if finding["verdict"] != "EXISTENCE ORACLE"
        ),
    )
    return ScanReport(
        scan_id=scan_id,
        status="completed",
        mode=mode,
        total_tests=len(results),
        passed_tests=sum(result.verdict == "PASS" for result in results),
        inconclusive_tests=sum(result.verdict == "INCONCLUSIVE" for result in results),
        findings=findings,
        results=results,
        risk_score=risk_score,
        findings_by_severity={
            severity: severity_counts.get(severity, 0)
            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        },
        leaks_by_vulnerability=dict(vulnerability_counts),
    )
