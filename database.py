import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, delete, event, select
from sqlalchemy.orm import Session, sessionmaker

from backend.models import (
    AccessPolicy,
    Base,
    Evidence,
    Finding,
    ImportAuditLog,
    Resource,
    RetestResult,
    Scan,
    ScanTest,
    SecurityEvent,
    Tenant,
    User,
)

DATABASE_PATH = Path(__file__).resolve().parent / "tenantfence.sqlite3"
engine = create_engine(
    f"sqlite:///{DATABASE_PATH.as_posix()}",
    connect_args={"check_same_thread": False, "timeout": 30},
)


@event.listens_for(engine, "connect")
def enable_sqlite_foreign_keys(connection: Any, _record: Any) -> None:
    cursor = connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
Base.metadata.create_all(engine)


def sync_policy_entities(policy: dict[str, Any]) -> None:
    with SessionLocal() as session:
        with session.begin():
            session.execute(delete(AccessPolicy))
            session.execute(delete(Resource))
            session.execute(delete(User))
            session.execute(delete(Tenant))
            tenants = [
                Tenant(
                    tenant_id=item["tenant_id"],
                    name=item["name"],
                    industry=item.get("industry", "General"),
                )
                for item in policy.get("tenants", [])
            ]
            session.add_all(tenants)
            session.flush()
            session.add_all(
                [
                    User(
                        user_id=item["user_id"],
                        tenant_id=item["tenant_id"],
                        name=item["name"],
                        email=item.get("email"),
                        role=item.get("role", "employee"),
                        status=item.get("status", "active"),
                    )
                    for item in policy["principals"]
                ]
            )
            session.flush()
        resources = [
            Resource(
                resource_type=item["type"],
                external_id=item["id"],
                tenant_id=item["tenant_id"],
                sensitivity=item.get("sensitivity", "medium"),
                canary=item["canary"],
                data_json=json.dumps(item.get("data", {})),
            )
            for item in policy["resources"]
        ]
        session.add_all(resources)
        session.flush()
        resource_ids = {
            (resource.resource_type, resource.external_id): resource.id
            for resource in session.scalars(select(Resource)).all()
        }
        rules = policy.get("rules", {})
        access_rows = []
        for principal in policy["principals"]:
            for resource in policy["resources"]:
                same_tenant = principal["tenant_id"] == resource["tenant_id"]
                access_rows.extend(
                    [
                        AccessPolicy(
                            principal_id=principal["user_id"],
                            resource_id=resource_ids[(resource["type"], resource["id"])],
                            action="read",
                            allowed=same_tenant,
                        ),
                        AccessPolicy(
                            principal_id=principal["user_id"],
                            resource_id=resource_ids[(resource["type"], resource["id"])],
                            action="write",
                            allowed=same_tenant
                            and (
                                principal.get("role") != "viewer"
                                or rules.get("viewer_write", "deny") == "allow"
                            ),
                        ),
                    ]
                )
        if access_rows:
            session.bulk_save_objects(access_rows)


def record_completed_scan(report: dict[str, Any]) -> None:
    with SessionLocal.begin() as session:
        scan = session.get(Scan, report["scan_id"])
        if scan is None:
            scan = Scan(
                scan_id=report["scan_id"],
                status="completed",
                mode=report["mode"],
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            session.add(scan)
        scan.status = "completed"
        scan.mode = report["mode"]
        scan.report_json = json.dumps(report)
        session.flush()

        session.execute(delete(ScanTest).where(ScanTest.scan_id == scan.scan_id))
        session.execute(
            delete(SecurityEvent).where(SecurityEvent.scan_id == scan.scan_id)
        )
        session.execute(delete(Evidence).where(Evidence.scan_id == scan.scan_id))
        session.add_all(
            [
                ScanTest(
                    test_id=str(uuid.uuid4()),
                    scan_id=scan.scan_id,
                    case_id=result["case"]["case_id"],
                    principal_id=result["case"]["principal"],
                    resource_type=result["case"]["resource_type"],
                    resource_id=result["case"]["resource_id"],
                    method=result["case"]["method"],
                    path=result["case"]["path"],
                    expected=result["case"]["expected"],
                    verdict=result["verdict"],
                    status_code=result["status_code"],
                )
                for result in report["results"]
            ]
        )
        findings_by_id = {item["id"]: item for item in report["findings"]}
        for finding in report["findings"]:
            session.merge(
                Finding(
                    finding_id=finding["id"],
                    scan_id=scan.scan_id,
                    severity=finding["severity"],
                    vulnerability=finding["vulnerability"],
                    verdict=finding["verdict"],
                    finding_json=json.dumps(finding),
                )
            )
        session.flush()
        session.add_all(
            [
                Evidence(
                    evidence_id=str(uuid.uuid4()),
                    scan_id=scan.scan_id,
                    finding_id=(
                        result["finding"]["id"] if result.get("finding") else None
                    ),
                    evidence_json=json.dumps(result["evidence"]),
                )
                for result in report["results"]
            ]
        )
        session.add_all(
            [
                SecurityEvent(
                    event_id=str(uuid.uuid4()),
                    scan_id=scan.scan_id,
                    stage=item["stage"],
                    occurred_at=item["timestamp"],
                    event_json=json.dumps(item),
                )
                for item in report.get("events", [])
            ]
        )


def record_retest_result(
    baseline_scan_id: str,
    retest_report: dict[str, Any],
) -> dict[str, Any]:
    baseline = load_scan_report(baseline_scan_id)
    if baseline is None:
        raise ValueError("Completed baseline scan not found")
    baseline_keys = {
        (item["vulnerability"], item["principal"], item["resource_type"], item["resource_id"])
        for item in baseline["findings"]
    }
    retest_keys = {
        (item["vulnerability"], item["principal"], item["resource_type"], item["resource_id"])
        for item in retest_report["findings"]
    }
    resolved_count = len(baseline_keys - retest_keys)
    unresolved_count = len(baseline_keys & retest_keys)
    verified = (
        baseline["mode"] == "vulnerable"
        and retest_report["mode"] == "secure"
        and baseline["total_tests"] == retest_report["total_tests"]
        and unresolved_count == 0
    )
    result = {
        "baseline_scan_id": baseline_scan_id,
        "retest_scan_id": retest_report["scan_id"],
        "resolved_count": resolved_count,
        "unresolved_count": unresolved_count,
        "verified": verified,
    }
    with SessionLocal.begin() as session:
        session.add(
            RetestResult(
                retest_id=str(uuid.uuid4()),
                **result,
            )
        )
    return result


def load_scan_report(scan_id: str) -> dict[str, Any] | None:
    with SessionLocal() as session:
        row = session.get(Scan, scan_id)
        if row is None or row.report_json is None:
            return None
        return json.loads(row.report_json)


def list_retest_results(baseline_scan_id: str | None = None) -> list[dict[str, Any]]:
    with SessionLocal() as session:
        statement = select(RetestResult).order_by(RetestResult.retest_id.desc())
        if baseline_scan_id:
            statement = statement.where(
                RetestResult.baseline_scan_id == baseline_scan_id
            )
        return [
            {
                "baseline_scan_id": row.baseline_scan_id,
                "retest_scan_id": row.retest_scan_id,
                "resolved_count": row.resolved_count,
                "unresolved_count": row.unresolved_count,
                "verified": row.verified,
            }
            for row in session.scalars(statement).all()
        ]


def record_audit_log(
    action: str,
    details: str,
    tenant_id: str | None = None,
    total_records: int = 0,
    success_count: int = 0,
    failed_count: int = 0,
    performed_by: str = "admin",
    error_report: list[dict[str, Any]] | None = None,
) -> str:
    log_id = str(uuid.uuid4())
    with SessionLocal() as session:
        with session.begin():
            session.add(
                ImportAuditLog(
                    id=log_id,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    action=action,
                    tenant_id=tenant_id,
                    performed_by=performed_by,
                    total_records=total_records,
                    success_count=success_count,
                    failed_count=failed_count,
                    details=details,
                    error_report_json=json.dumps(error_report) if error_report else None,
                )
            )
    return log_id


def list_audit_logs(
    tenant_id: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    with SessionLocal() as session:
        stmt = select(ImportAuditLog).order_by(ImportAuditLog.timestamp.desc()).limit(limit)
        if tenant_id:
            stmt = select(ImportAuditLog).where(
                (ImportAuditLog.tenant_id == tenant_id) | (ImportAuditLog.tenant_id.is_(None))
            ).order_by(ImportAuditLog.timestamp.desc()).limit(limit)
        rows = session.scalars(stmt).all()
        return [
            {
                "id": r.id,
                "timestamp": r.timestamp,
                "action": r.action,
                "tenant_id": r.tenant_id,
                "performed_by": r.performed_by,
                "total_records": r.total_records,
                "success_count": r.success_count,
                "failed_count": r.failed_count,
                "details": r.details,
                "has_error_report": r.error_report_json is not None,
            }
            for r in rows
        ]


def get_audit_log_error_report(audit_id: str) -> list[dict[str, Any]] | None:
    with SessionLocal() as session:
        log = session.get(ImportAuditLog, audit_id)
        if log is None or log.error_report_json is None:
            return None
        return json.loads(log.error_report_json)
