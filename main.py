import asyncio
import base64
import csv
import io
import json
import math
import os
import re
import uuid
from pathlib import Path
from typing import Any, Literal

import httpx
from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, Field

from backend.reports import (
    html_report,
    markdown_report,
    pdf_report,
    regression_archive,
    sarif_report,
)
from backend.database import (
    get_audit_log_error_report,
    list_audit_logs,
    list_retest_results,
    record_audit_log,
    record_completed_scan,
    record_retest_result,
    sync_policy_entities,
)
from backend.storage import ScanStore
from engine.executor import ensure_local_target, execute_scan
from engine.policy import load_policy

app = FastAPI(
    title="TenantFence Security Engine",
    description="Policy-derived cross-tenant API authorization testing",
    version="2.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

store = ScanStore()
active_scans: dict[str, dict[str, Any]] = {}
scan_lock = asyncio.Lock()
initial_policy = load_policy()
vulnerable_target_url = os.environ.get(
    "TENANTFENCE_VULNERABLE_URL", initial_policy["target_url"]
).rstrip("/")
secure_target_url = os.environ.get(
    "TENANTFENCE_SECURE_URL", initial_policy["secure_target_url"]
).rstrip("/")
active_target_url = os.environ.get(
    "TENANTFENCE_TARGET_URL", vulnerable_target_url
).rstrip("/")
policy_path = Path(__file__).with_name("policy.json")
admin_token = os.environ.get("TENANTFENCE_ADMIN_TOKEN", "local-demo-admin-token")
sync_policy_entities(initial_policy)


class ScanRequest(BaseModel):
    target_url: str | None = None
    baseline_scan_id: str | None = None
    tenant_ids: list[str] | None = None
    resource_types: list[Literal["invoice", "project", "document", "record"]] | None = None


class TargetModeRequest(BaseModel):
    mode: Literal["vulnerable", "secure"]


class TenantInput(BaseModel):
    tenant_id: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    name: str = Field(min_length=2, max_length=80)
    industry: str = Field(default="General", max_length=60)


class UserInput(BaseModel):
    user_id: str = Field(pattern=r"^[A-Za-z0-9_.-]+$")
    name: str = Field(min_length=2, max_length=80)
    email: str | None = None
    tenant_id: str
    role: Literal["admin", "employee", "viewer"]
    status: Literal["active", "inactive"] = "active"


class UserUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=80)
    email: str | None = None
    tenant_id: str | None = None
    role: Literal["admin", "employee", "viewer"] | None = None
    status: Literal["active", "inactive"] | None = None


class BulkRoleUpdateRequest(BaseModel):
    user_ids: list[str] = Field(min_length=1)
    role: Literal["admin", "employee", "viewer"]


class BulkStatusUpdateRequest(BaseModel):
    user_ids: list[str] = Field(min_length=1)
    status: Literal["active", "inactive"]


class BulkDeleteRequest(BaseModel):
    user_ids: list[str] = Field(min_length=1)


class ImportValidateRequest(BaseModel):
    file_content: str | None = None
    filename: str = "import.csv"
    target_tenant_id: str | None = None
    default_role: str = "employee"
    records: list[dict[str, Any]] | None = None


class ImportCommitRequest(BaseModel):
    records: list[dict[str, Any]] = Field(min_length=1)
    target_tenant_id: str | None = None
    file_name: str | None = None
    skip_errors: bool = True


class ResourceInput(BaseModel):
    type: Literal["invoice", "project", "document", "record"]
    id: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    tenant_id: str
    sensitivity: Literal["low", "medium", "high"] = "medium"
    canary: str = Field(pattern=r"^CANARY-[A-Za-z0-9_-]+$")
    data: dict[str, Any] = Field(default_factory=dict)


def require_admin(x_admin_token: str | None = Header(default=None)) -> None:
    if x_admin_token != admin_token:
        raise HTTPException(status_code=401, detail="Valid X-Admin-Token required")


def save_policy(policy: dict[str, Any]) -> None:
    policy_path.write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")
    sync_policy_entities(policy)


def reload_demo_apis() -> None:
    pass


@app.get("/")
def home() -> dict[str, str]:
    return {"message": "TenantFence Testing Engine", "status": "Running"}


@app.get("/policy")
def get_policy() -> dict[str, Any]:
    return load_policy()


@app.get("/settings")
def get_settings() -> dict[str, Any]:
    policy = load_policy()
    return {
        "vulnerable_api_url": vulnerable_target_url,
        "secure_api_url": secure_target_url,
        "active_target_url": active_target_url,
        "rules": policy.get("rules", {}),
    }


@app.get("/tenants")
def list_tenants() -> dict[str, Any]:
    policy = load_policy()
    tenants = []
    for tenant in policy.get("tenants", []):
        tenant_id = tenant["tenant_id"]
        tenants.append(
            {
                **tenant,
                "user_count": sum(
                    user["tenant_id"] == tenant_id for user in policy["principals"]
                ),
                "resource_count": sum(
                    resource["tenant_id"] == tenant_id
                    for resource in policy["resources"]
                ),
            }
        )
    return {"tenants": tenants}


@app.post("/tenants", status_code=201, dependencies=[Depends(require_admin)])
async def create_tenant(tenant: TenantInput) -> dict[str, Any]:
    policy = load_policy()
    if any(item["tenant_id"] == tenant.tenant_id for item in policy["tenants"]):
        raise HTTPException(status_code=409, detail="Tenant ID already exists")
    record = tenant.model_dump()
    policy["tenants"].append(record)
    save_policy(policy)
    reload_demo_apis()
    return record


@app.put("/tenants/{tenant_id}", dependencies=[Depends(require_admin)])
async def update_tenant(tenant_id: str, tenant: TenantInput) -> dict[str, Any]:
    policy = load_policy()
    existing = next(
        (item for item in policy["tenants"] if item["tenant_id"] == tenant_id), None
    )
    if existing is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    if tenant.tenant_id != tenant_id and any(
        item["tenant_id"] == tenant.tenant_id for item in policy["tenants"]
    ):
        raise HTTPException(status_code=409, detail="Tenant ID already exists")
    old_id = existing["tenant_id"]
    existing.update(tenant.model_dump())
    if tenant.tenant_id != old_id:
        for user in policy["principals"]:
            if user["tenant_id"] == old_id:
                user["tenant_id"] = tenant.tenant_id
        for resource in policy["resources"]:
            if resource["tenant_id"] == old_id:
                resource["tenant_id"] = tenant.tenant_id
    save_policy(policy)
    reload_demo_apis()
    return existing


@app.delete(
    "/tenants/{tenant_id}",
    status_code=204,
    dependencies=[Depends(require_admin)],
)
async def delete_tenant(tenant_id: str) -> Response:
    policy = load_policy()
    if not any(item["tenant_id"] == tenant_id for item in policy["tenants"]):
        raise HTTPException(status_code=404, detail="Tenant not found")
    if len(policy["tenants"]) < 2:
        raise HTTPException(status_code=409, detail="At least one tenant must remain")
    policy["tenants"] = [
        item for item in policy["tenants"] if item["tenant_id"] != tenant_id
    ]
    removed_users = {
        user["user_id"]
        for user in policy["principals"]
        if user["tenant_id"] == tenant_id
    }
    policy["principals"] = [
        user for user in policy["principals"] if user["tenant_id"] != tenant_id
    ]
    policy["resources"] = [
        resource
        for resource in policy["resources"]
        if resource["tenant_id"] != tenant_id
        and not (
            resource["type"] == "user" and resource["id"] in removed_users
        )
    ]
    save_policy(policy)
    reload_demo_apis()
    return Response(status_code=204)


EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
USER_ID_CLEAN_REGEX = re.compile(r"[^a-zA-Z0-9_.-]")


def extract_rows_from_file(file_bytes: bytes, filename: str) -> list[dict[str, Any]]:
    lower_name = filename.lower()
    raw_rows: list[dict[str, Any]] = []

    if lower_name.endswith(".xlsx") or lower_name.endswith(".xls"):
        import openpyxl

        wb = openpyxl.load_workbook(io.BytesIO(file_bytes), data_only=True)
        sheet = wb.active
        rows = list(sheet.iter_rows(values_only=True))
        if not rows:
            return []
        headers = [
            str(h).strip() if h is not None else f"col_{i}"
            for i, h in enumerate(rows[0])
        ]
        for row in rows[1:]:
            if not any(row):
                continue
            row_dict = {}
            for h, cell in zip(headers, row):
                row_dict[h] = str(cell).strip() if cell is not None else ""
            raw_rows.append(row_dict)
    else:
        text = None
        for encoding in ("utf-8-sig", "utf-8", "latin-1", "cp1252"):
            try:
                text = file_bytes.decode(encoding)
                break
            except UnicodeDecodeError:
                continue
        if text is None:
            text = file_bytes.decode("utf-8", errors="replace")

        reader = csv.DictReader(io.StringIO(text))
        for r in reader:
            if not any(r.values()):
                continue
            raw_rows.append(
                {
                    (k.strip() if k else f"col_{i}"): (v.strip() if v else "")
                    for i, (k, v) in enumerate(r.items())
                }
            )

    return raw_rows


def normalize_row_keys(row: dict[str, Any]) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key, val in row.items():
        k = key.lower().replace("-", " ").replace("_", " ").strip()
        v = str(val).strip()
        if k in ("name", "full name", "fullname", "employee name", "employee", "user"):
            normalized["name"] = v
        elif k in ("email", "e mail", "email address", "work email", "mail"):
            normalized["email"] = v
        elif k in ("user id", "userid", "user_id", "id", "username"):
            normalized["user_id"] = v
        elif k in (
            "tenant id",
            "tenant",
            "tenant_id",
            "company id",
            "company",
            "company name",
            "organization",
            "org",
        ):
            normalized["tenant_id"] = v
        elif k in ("role", "user role", "permission", "access level", "access"):
            normalized["role"] = v
        elif k in ("status", "account status", "state", "active"):
            normalized["status"] = v
    return normalized


def validate_user_records(
    raw_records: list[dict[str, Any]],
    policy: dict[str, Any],
    target_tenant_id: str | None = None,
    default_role: str = "employee",
) -> dict[str, Any]:
    tenants = policy.get("tenants", [])
    valid_tenants = {t["tenant_id"]: t["name"] for t in tenants}
    name_to_tenant_id = {t["name"].lower(): t["tenant_id"] for t in tenants}
    principals = policy.get("principals", [])

    existing_emails = {
        p.get("email", "").lower(): p["user_id"]
        for p in principals
        if p.get("email")
    }
    existing_user_ids = {p["user_id"] for p in principals}

    file_emails: dict[str, int] = {}
    file_user_ids: dict[str, int] = {}

    parsed_records = []
    errors_summary = []

    for idx, raw in enumerate(raw_records, start=2):
        row = normalize_row_keys(raw)
        row_errors: list[str] = []

        name = row.get("name", "").strip()
        email = row.get("email", "").strip()
        user_id = row.get("user_id", "").strip()
        raw_tenant = row.get("tenant_id", "").strip()
        raw_role = row.get("role", "").strip()
        raw_status = row.get("status", "").strip()

        # 1. Validate Name
        if not name:
            row_errors.append("Missing required field: Name")
        elif len(name) < 2 or len(name) > 80:
            row_errors.append(f"Name must be between 2 and 80 characters (got {len(name)})")

        # 2. Validate Email
        if not email:
            row_errors.append("Missing required field: Email")
        elif not EMAIL_REGEX.match(email):
            row_errors.append(f"Invalid email format: '{email}'")
        else:
            lower_email = email.lower()
            if lower_email in file_emails:
                row_errors.append(
                    f"Duplicate email in import file (also on row {file_emails[lower_email]})"
                )
            else:
                file_emails[lower_email] = idx

            if lower_email in existing_emails:
                row_errors.append(
                    f"Duplicate email: already registered to user '{existing_emails[lower_email]}'"
                )

        # 3. Resolve & Validate Tenant
        resolved_tenant_id = None
        if target_tenant_id:
            resolved_tenant_id = target_tenant_id
            if raw_tenant and raw_tenant != target_tenant_id:
                if name_to_tenant_id.get(raw_tenant.lower()) == target_tenant_id:
                    pass
                else:
                    row_errors.append(
                        f"Tenant mismatch: record specifies '{raw_tenant}', but import is scoped to '{target_tenant_id}'"
                    )
        elif raw_tenant:
            if raw_tenant in valid_tenants:
                resolved_tenant_id = raw_tenant
            elif raw_tenant.lower() in name_to_tenant_id:
                resolved_tenant_id = name_to_tenant_id[raw_tenant.lower()]
            else:
                row_errors.append(
                    f"Unknown tenant '{raw_tenant}'. Known tenants: {', '.join(valid_tenants.keys())}"
                )
        else:
            if len(valid_tenants) == 1:
                resolved_tenant_id = list(valid_tenants.keys())[0]
            else:
                row_errors.append("Missing tenant assignment and no default company selected")

        # 4. Resolve & Validate User ID
        if not user_id:
            if email:
                base = email.split("@")[0].lower()
            else:
                base = name.lower().replace(" ", "_")
            cleaned_id = USER_ID_CLEAN_REGEX.sub("_", base)[:40].strip("_") or "user"
            candidate_id = cleaned_id
            suffix = 2
            while candidate_id in file_user_ids or candidate_id in existing_user_ids:
                candidate_id = f"{cleaned_id}_{suffix}"
                suffix += 1
            user_id = candidate_id
        else:
            cleaned_user_id = USER_ID_CLEAN_REGEX.sub("_", user_id)
            if cleaned_user_id != user_id:
                row_errors.append(
                    f"User ID contains invalid characters: '{user_id}'. Only alphanumeric, underscores, dots, hyphens allowed."
                )
            if user_id in file_user_ids:
                row_errors.append(
                    f"Duplicate User ID in file (also on row {file_user_ids[user_id]})"
                )
            if user_id in existing_user_ids:
                row_errors.append(f"User ID '{user_id}' already exists in system")
        file_user_ids[user_id] = idx

        # 5. Validate Role
        role = raw_role.lower() if raw_role else default_role.lower()
        if role not in ("admin", "employee", "viewer"):
            row_errors.append(f"Invalid role: '{raw_role}'. Must be admin, employee, or viewer.")
            role = "employee"

        # 6. Validate Status
        status = raw_status.lower() if raw_status else "active"
        if status not in ("active", "inactive"):
            status = "active"

        is_valid = len(row_errors) == 0
        if not is_valid:
            errors_summary.append(f"Row {idx} ({name or 'Unnamed'}): {'; '.join(row_errors)}")

        parsed_records.append(
            {
                "row_number": idx,
                "name": name,
                "email": email,
                "user_id": user_id,
                "tenant_id": resolved_tenant_id or (target_tenant_id or "unassigned"),
                "tenant_name": valid_tenants.get(resolved_tenant_id, "Unknown"),
                "role": role,
                "status": status,
                "is_valid": is_valid,
                "errors": row_errors,
            }
        )

    valid_count = sum(1 for r in parsed_records if r["is_valid"])
    error_count = len(parsed_records) - valid_count

    return {
        "total_records": len(parsed_records),
        "valid_count": valid_count,
        "error_count": error_count,
        "records": parsed_records,
        "errors_summary": errors_summary[:50],
    }


@app.get("/users")
def list_users(
    tenant_id: str | None = None,
    role: str | None = None,
    status: str | None = None,
    search: str | None = None,
    page: int = 1,
    page_size: int = 25,
) -> dict[str, Any]:
    policy = load_policy()
    principals = policy.get("principals", [])

    tenant_counts: dict[str, int] = {}
    for u in principals:
        tid = u.get("tenant_id", "unassigned")
        tenant_counts[tid] = tenant_counts.get(tid, 0) + 1

    filtered = principals
    if tenant_id:
        filtered = [u for u in filtered if u.get("tenant_id") == tenant_id]
    if role:
        filtered = [u for u in filtered if u.get("role") == role]
    if status:
        filtered = [u for u in filtered if u.get("status", "active") == status]
    if search:
        s = search.lower()
        filtered = [
            u
            for u in filtered
            if s in u.get("name", "").lower()
            or s in u.get("email", "").lower()
            or s in u.get("user_id", "").lower()
        ]

    total = len(filtered)
    total_pages = max(1, math.ceil(total / page_size))
    start_idx = (page - 1) * page_size
    paged = filtered[start_idx : start_idx + page_size]

    return {
        "users": paged,
        "total": total,
        "total_all": len(principals),
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "tenant_counts": tenant_counts,
    }


@app.post("/users", status_code=201, dependencies=[Depends(require_admin)])
def create_user(user: UserInput) -> dict[str, Any]:
    policy = load_policy()
    if not any(item["tenant_id"] == user.tenant_id for item in policy["tenants"]):
        raise HTTPException(status_code=422, detail="Unknown tenant")
    if any(item["user_id"] == user.user_id for item in policy["principals"]):
        raise HTTPException(status_code=409, detail="User ID already exists")

    user_email = user.email or f"{user.user_id}@{user.tenant_id}.com"
    if user.email and any(
        item.get("email", "").lower() == user.email.lower()
        for item in policy["principals"]
    ):
        raise HTTPException(status_code=409, detail="Email already registered")

    record = {
        "user_id": user.user_id,
        "name": user.name,
        "email": user_email,
        "tenant_id": user.tenant_id,
        "role": user.role,
        "status": user.status,
    }
    policy["principals"].append(record)

    # Ensure a canary user resource exists for this user
    policy["resources"].append(
        {
            "type": "user",
            "id": user.user_id,
            "tenant_id": user.tenant_id,
            "sensitivity": "low",
            "canary": f"CANARY-{user.tenant_id}-USER-{user.user_id}",
            "data": {"name": user.name, "role": user.role},
        }
    )
    save_policy(policy)
    reload_demo_apis()

    record_audit_log(
        action="user_create",
        details=f"Created user {user.name} ({user.user_id}) with role {user.role} in {user.tenant_id}",
        tenant_id=user.tenant_id,
        total_records=1,
        success_count=1,
        failed_count=0,
    )
    return record


@app.patch("/users/{user_id}", dependencies=[Depends(require_admin)])
def update_user(user_id: str, changes: UserUpdate) -> dict[str, Any]:
    policy = load_policy()
    user = next(
        (item for item in policy["principals"] if item["user_id"] == user_id), None
    )
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    updates = changes.model_dump(exclude_unset=True)
    if "tenant_id" in updates and not any(
        item["tenant_id"] == updates["tenant_id"] for item in policy["tenants"]
    ):
        raise HTTPException(status_code=422, detail="Unknown tenant")

    if "email" in updates and updates["email"]:
        new_email = updates["email"].lower()
        if any(
            item["user_id"] != user_id
            and item.get("email", "").lower() == new_email
            for item in policy["principals"]
        ):
            raise HTTPException(status_code=409, detail="Email already taken by another user")

    user.update(updates)
    for resource in policy["resources"]:
        if resource["type"] == "user" and resource["id"] == user_id:
            resource["tenant_id"] = user["tenant_id"]
            resource["data"] = {"name": user["name"], "role": user["role"]}
    save_policy(policy)
    reload_demo_apis()

    record_audit_log(
        action="user_update",
        details=f"Updated user {user['name']} ({user_id}): {', '.join(f'{k}={v}' for k, v in updates.items())}",
        tenant_id=user["tenant_id"],
        total_records=1,
        success_count=1,
        failed_count=0,
    )
    return user


@app.delete("/users/{user_id}", status_code=204, dependencies=[Depends(require_admin)])
def delete_user(user_id: str) -> Response:
    policy = load_policy()
    user = next(
        (item for item in policy["principals"] if item["user_id"] == user_id), None
    )
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if len(policy["principals"]) <= 1:
        raise HTTPException(status_code=400, detail="Cannot delete the last remaining user")

    policy["principals"] = [
        item for item in policy["principals"] if item["user_id"] != user_id
    ]
    policy["resources"] = [
        item
        for item in policy["resources"]
        if not (item["type"] == "user" and item["id"] == user_id)
    ]
    save_policy(policy)
    reload_demo_apis()

    record_audit_log(
        action="user_delete",
        details=f"Deleted user {user.get('name', user_id)} ({user_id}) from {user.get('tenant_id')}",
        tenant_id=user.get("tenant_id"),
        total_records=1,
        success_count=1,
        failed_count=0,
    )
    return Response(status_code=204)


@app.post("/users/bulk-update-role", dependencies=[Depends(require_admin)])
def bulk_update_role(payload: BulkRoleUpdateRequest) -> dict[str, Any]:
    policy = load_policy()
    target_ids = set(payload.user_ids)
    updated = 0
    tenants_affected: set[str] = set()

    for user in policy["principals"]:
        if user["user_id"] in target_ids:
            user["role"] = payload.role
            tenants_affected.add(user["tenant_id"])
            updated += 1
            for resource in policy["resources"]:
                if resource["type"] == "user" and resource["id"] == user["user_id"]:
                    resource.setdefault("data", {})["role"] = payload.role

    if updated > 0:
        save_policy(policy)
        reload_demo_apis()
        record_audit_log(
            action="bulk_role_update",
            details=f"Updated role to '{payload.role}' for {updated} user(s)",
            tenant_id=list(tenants_affected)[0] if len(tenants_affected) == 1 else None,
            total_records=len(payload.user_ids),
            success_count=updated,
            failed_count=len(payload.user_ids) - updated,
        )

    return {"updated_count": updated, "role": payload.role}


@app.post("/users/bulk-update-status", dependencies=[Depends(require_admin)])
def bulk_update_status(payload: BulkStatusUpdateRequest) -> dict[str, Any]:
    policy = load_policy()
    target_ids = set(payload.user_ids)
    updated = 0
    tenants_affected: set[str] = set()

    for user in policy["principals"]:
        if user["user_id"] in target_ids:
            user["status"] = payload.status
            tenants_affected.add(user["tenant_id"])
            updated += 1

    if updated > 0:
        save_policy(policy)
        reload_demo_apis()
        record_audit_log(
            action="bulk_status_update",
            details=f"Set status to '{payload.status}' for {updated} user(s)",
            tenant_id=list(tenants_affected)[0] if len(tenants_affected) == 1 else None,
            total_records=len(payload.user_ids),
            success_count=updated,
            failed_count=len(payload.user_ids) - updated,
        )

    return {"updated_count": updated, "status": payload.status}


@app.post("/users/bulk-delete", dependencies=[Depends(require_admin)])
def bulk_delete_users(payload: BulkDeleteRequest) -> dict[str, Any]:
    policy = load_policy()
    to_delete = set(payload.user_ids)
    remaining = [u for u in policy["principals"] if u["user_id"] not in to_delete]
    if not remaining:
        raise HTTPException(
            status_code=400,
            detail="Cannot delete all users. At least one user must remain in the system.",
        )

    deleted_count = len(policy["principals"]) - len(remaining)
    tenants_affected = {u["tenant_id"] for u in policy["principals"] if u["user_id"] in to_delete}
    policy["principals"] = remaining
    policy["resources"] = [
        r
        for r in policy["resources"]
        if not (r["type"] == "user" and r["id"] in to_delete)
    ]
    save_policy(policy)
    reload_demo_apis()

    record_audit_log(
        action="bulk_delete",
        details=f"Bulk deleted {deleted_count} user(s)",
        tenant_id=list(tenants_affected)[0] if len(tenants_affected) == 1 else None,
        total_records=len(payload.user_ids),
        success_count=deleted_count,
        failed_count=len(payload.user_ids) - deleted_count,
    )
    return {"deleted_count": deleted_count}


@app.post("/users/import/validate", dependencies=[Depends(require_admin)])
def validate_user_import(
    payload: ImportValidateRequest,
) -> dict[str, Any]:
    policy = load_policy()
    if payload.target_tenant_id and not any(
        t["tenant_id"] == payload.target_tenant_id for t in policy.get("tenants", [])
    ):
        raise HTTPException(status_code=422, detail="Invalid target tenant ID")

    raw_records: list[dict[str, Any]] = []
    if payload.records:
        raw_records = payload.records
    elif payload.file_content:
        content = payload.file_content
        # Handle data URL prefix if present e.g. data:text/csv;base64,...
        if "," in content and content.startswith("data:"):
            content = content.split(",", 1)[1]
        try:
            file_bytes = base64.b64decode(content)
        except Exception:
            file_bytes = content.encode("utf-8")
        raw_records = extract_rows_from_file(file_bytes, payload.filename)
    else:
        raise HTTPException(status_code=400, detail="Either file_content or records must be provided")

    if not raw_records:
        raise HTTPException(status_code=400, detail="No valid data rows found in file or payload")

    return validate_user_records(
        raw_records=raw_records,
        policy=policy,
        target_tenant_id=payload.target_tenant_id if payload.target_tenant_id else None,
        default_role=payload.default_role,
    )


@app.post("/users/import/commit", dependencies=[Depends(require_admin)])
def commit_user_import(payload: ImportCommitRequest) -> dict[str, Any]:
    policy = load_policy()
    existing_principals = {p["user_id"]: p for p in policy.get("principals", [])}
    valid_tenants = {t["tenant_id"] for t in policy.get("tenants", [])}

    to_import = [r for r in payload.records if r.get("is_valid", True)]
    failed_records = [r for r in payload.records if not r.get("is_valid", True)]

    imported_users = []
    for r in to_import:
        tid = r.get("tenant_id")
        if payload.target_tenant_id:
            tid = payload.target_tenant_id
        if not tid or tid not in valid_tenants:
            failed_records.append(
                {**r, "is_valid": False, "errors": ["Tenant unauthorized or not found"]}
            )
            continue

        uid = r.get("user_id") or re.sub(r"[^a-zA-Z0-9_.-]", "_", r.get("email", "u").split("@")[0])
        user_record = {
            "user_id": uid,
            "name": r.get("name", "Unnamed"),
            "email": r.get("email", f"{uid}@{tid}.com"),
            "tenant_id": tid,
            "role": r.get("role", "employee"),
            "status": r.get("status", "active"),
        }

        if uid in existing_principals:
            existing_principals[uid].update(user_record)
        else:
            policy["principals"].append(user_record)
            existing_principals[uid] = user_record

        imported_users.append(user_record)

    save_policy(policy)
    reload_demo_apis()

    audit_id = record_audit_log(
        action="bulk_import",
        details=f"Imported {len(imported_users)} user(s) from {payload.file_name or 'file'} into {payload.target_tenant_id or 'all companies'} ({len(failed_records)} skipped)",
        tenant_id=payload.target_tenant_id,
        total_records=len(payload.records),
        success_count=len(imported_users),
        failed_count=len(failed_records),
        error_report=failed_records if failed_records else None,
    )

    return {
        "success": True,
        "imported_count": len(imported_users),
        "failed_count": len(failed_records),
        "total_processed": len(payload.records),
        "failed_records": failed_records,
        "audit_id": audit_id,
    }


@app.get("/users/audit-logs")
def get_user_audit_logs(
    tenant_id: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    return {"logs": list_audit_logs(tenant_id=tenant_id, limit=limit)}


@app.get("/users/audit-logs/{audit_id}/errors")
def get_audit_errors(audit_id: str) -> dict[str, Any]:
    errors = get_audit_log_error_report(audit_id)
    if errors is None:
        raise HTTPException(status_code=404, detail="Error report not found for this audit log")
    return {"errors": errors}


@app.get("/users/template")
def download_user_template() -> Response:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Name", "Email", "User ID", "Tenant ID", "Role", "Status"])
    writer.writerow(["Sarah Jenkins", "sarah.jenkins@companya.com", "sarah_j", "tenant_A", "admin", "active"])
    writer.writerow(["Michael Chen", "michael.chen@companya.com", "mchen", "tenant_A", "employee", "active"])
    writer.writerow(["Emma Watson", "emma.watson@companyb.com", "emma_w", "tenant_B", "employee", "active"])
    writer.writerow(["David Miller", "david.miller@companyc.com", "dmiller", "tenant_C", "viewer", "active"])
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=tenantfence_users_template.csv"},
    )


@app.get("/resources")
def list_resources() -> dict[str, Any]:
    return {"resources": load_policy()["resources"]}


@app.post("/resources", status_code=201, dependencies=[Depends(require_admin)])
async def create_resource(resource: ResourceInput) -> dict[str, Any]:
    policy = load_policy()
    if not any(item["tenant_id"] == resource.tenant_id for item in policy["tenants"]):
        raise HTTPException(status_code=422, detail="Unknown tenant")
    if any(
        item["type"] == resource.type and item["id"] == resource.id
        for item in policy["resources"]
    ):
        raise HTTPException(status_code=409, detail="Resource ID already exists")
    record = resource.model_dump()
    policy["resources"].append(record)
    save_policy(policy)
    reload_demo_apis()
    return record


@app.delete(
    "/resources/{resource_type}/{resource_id}",
    status_code=204,
    dependencies=[Depends(require_admin)],
)
async def delete_resource(resource_type: str, resource_id: str) -> Response:
    policy = load_policy()
    if resource_type == "user":
        raise HTTPException(
            status_code=409, detail="Manage user resources through user management"
        )
    existing = next(
        (
            item
            for item in policy["resources"]
            if item["type"] == resource_type and item["id"] == resource_id
        ),
        None,
    )
    if existing is None:
        raise HTTPException(status_code=404, detail="Resource not found")
    policy["resources"] = [
        item
        for item in policy["resources"]
        if not (item["type"] == resource_type and item["id"] == resource_id)
    ]
    save_policy(policy)
    reload_demo_apis()
    return Response(status_code=204)


async def _run_scan(scan_id: str, policy: dict[str, Any]) -> None:
    state = active_scans[scan_id]

    def publish(event: dict[str, Any]) -> None:
        state["events"].append(event)
        if event["type"] == "progress":
            state["completed"] = event["completed"]
            state["total"] = event["total"]

    async with scan_lock:
        try:
            report = await execute_scan(scan_id, policy, on_progress=publish)
            report_data = report.as_dict()
            report_data["scope"] = state["scope"]
            report_data["events"] = [
                event
                for event in state["events"]
                if event.get("type") == "scan_event"
            ]
            baseline_scan_id = state.get("baseline_scan_id")
            if baseline_scan_id:
                report_data["baseline_scan_id"] = baseline_scan_id
            store.complete_scan(report_data)
            record_completed_scan(report_data)
            if baseline_scan_id:
                report_data["retest"] = record_retest_result(
                    baseline_scan_id, report_data
                )
                store.complete_scan(report_data)
                record_completed_scan(report_data)
            state.update(status="completed", report=report_data)
            state["events"].append({"type": "complete", "report": report_data})
        except Exception as error:
            message = f"{type(error).__name__}: {error}"
            store.fail_scan(scan_id, message)
            state.update(status="failed", error=message)
            state["events"].append({"type": "error", "error": message})
        except asyncio.CancelledError:
            store.fail_scan(scan_id, "Scan stopped by operator")
            state.update(status="cancelled", error="Scan stopped by operator")
            state["events"].append({"type": "cancelled"})
            raise


@app.post("/scan", status_code=202, dependencies=[Depends(require_admin)])
async def run_security_scan(request: ScanRequest | None = None) -> dict[str, Any]:
    policy = load_policy()
    if request and request.target_url:
        policy["target_url"] = request.target_url.rstrip("/")
    else:
        policy["target_url"] = active_target_url
    try:
        ensure_local_target(policy["target_url"])
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    async with httpx.AsyncClient(
        base_url=policy["target_url"], timeout=httpx.Timeout(5.0, connect=3.0)
    ) as client:
        try:
            response = await client.get("/admin/mode")
            response.raise_for_status()
            target_mode = response.json()["mode"]
        except (httpx.HTTPError, ValueError, KeyError) as error:
            raise HTTPException(
                status_code=502, detail=f"Unable to read demo API mode: {error}"
            ) from error
    all_tenant_ids = [tenant["tenant_id"] for tenant in policy["tenants"]]
    all_resource_types = ["invoice", "project", "document", "record"]
    tenant_ids = request.tenant_ids if request and request.tenant_ids is not None else all_tenant_ids
    resource_types = (
        request.resource_types
        if request and request.resource_types is not None
        else all_resource_types
    )
    if not tenant_ids or not resource_types:
        raise HTTPException(status_code=422, detail="Select at least one tenant and resource type")
    if len(set(tenant_ids)) != len(tenant_ids) or any(
        tenant_id not in all_tenant_ids for tenant_id in tenant_ids
    ):
        raise HTTPException(status_code=422, detail="Scan scope contains an unknown or duplicate tenant")
    if len(set(resource_types)) != len(resource_types):
        raise HTTPException(status_code=422, detail="Scan scope contains duplicate resource types")

    baseline_scan_id = request.baseline_scan_id if request else None
    if baseline_scan_id:
        baseline = store.get_scan(baseline_scan_id)
        if baseline is None or baseline.get("status") != "completed":
            raise HTTPException(status_code=404, detail="Completed baseline scan not found")
        if baseline.get("mode") != "vulnerable":
            raise HTTPException(status_code=409, detail="Retest baseline must be vulnerable")
        if target_mode != "secure":
            raise HTTPException(status_code=409, detail="Retests must target the secure demo API")
        baseline_scope = baseline.get(
            "scope",
            {"tenant_ids": all_tenant_ids, "resource_types": all_resource_types},
        )
        if request and (
            (
                request.tenant_ids is not None
                and set(tenant_ids) != set(baseline_scope["tenant_ids"])
            )
            or (
                request.resource_types is not None
                and set(resource_types) != set(baseline_scope["resource_types"])
            )
        ):
            raise HTTPException(
                status_code=409,
                detail="Retests must use the exact tenant and resource scope of the baseline",
            )
        tenant_ids = baseline_scope["tenant_ids"]
        resource_types = baseline_scope["resource_types"]

    policy["principals"] = [
        principal for principal in policy["principals"]
        if principal["tenant_id"] in tenant_ids
    ]
    policy["resources"] = [
        resource for resource in policy["resources"]
        if resource["tenant_id"] in tenant_ids and resource["type"] in resource_types
    ]

    if any(state["status"] == "running" for state in active_scans.values()):
        raise HTTPException(status_code=409, detail="A scan is already running")
    scan_id = str(uuid.uuid4())
    store.start_scan(scan_id, target_mode)
    state = {
        "status": "running",
        "mode": target_mode,
        "completed": 0,
        "total": 0,
        "events": [],
        "baseline_scan_id": baseline_scan_id,
        "scope": {"tenant_ids": tenant_ids, "resource_types": resource_types},
    }
    active_scans[scan_id] = state
    state["task"] = asyncio.create_task(_run_scan(scan_id, policy))
    return {"scan_id": scan_id, "status": "running", "mode": target_mode}


@app.get("/scan/{scan_id}")
def get_scan(scan_id: str) -> dict[str, Any]:
    state = active_scans.get(scan_id)
    if state:
        if state["status"] == "running":
            return {
                "scan_id": scan_id,
                "status": "running",
                "mode": state["mode"],
                "completed": state["completed"],
                "total": state["total"],
            }
        if state["status"] in ("failed", "cancelled"):
            return {
                "scan_id": scan_id,
                "status": state["status"],
                "error": state["error"],
            }
        return state["report"]
    report = store.get_scan(scan_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return report


@app.get("/scan/{scan_id}/stream")
async def stream_scan(scan_id: str) -> StreamingResponse:
    if scan_id not in active_scans and store.get_scan(scan_id) is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    async def events():
        index = 0
        while True:
            state = active_scans.get(scan_id)
            if state is None:
                report = store.get_scan(scan_id)
                yield f"event: complete\ndata: {json.dumps(report)}\n\n"
                return
            while index < len(state["events"]):
                event = state["events"][index]
                index += 1
                yield f"event: {event['type']}\ndata: {json.dumps(event)}\n\n"
            if state["status"] != "running":
                return
            yield ": keep-alive\n\n"
            await asyncio.sleep(0.25)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.websocket("/ws/scans/{scan_id}")
async def websocket_scan(websocket: WebSocket, scan_id: str, after: int = 0) -> None:
    state = active_scans.get(scan_id)
    if state is None and store.get_scan(scan_id) is None:
        await websocket.close(code=4404, reason="Scan not found")
        return
    await websocket.accept()
    index = max(0, after)
    try:
        while True:
            state = active_scans.get(scan_id)
            if state is None:
                await websocket.send_json(
                    {"type": "complete", "report": store.get_scan(scan_id)}
                )
                return
            while index < len(state["events"]):
                await websocket.send_json(state["events"][index])
                index += 1
            if state["status"] != "running":
                return
            await asyncio.sleep(0.2)
    except WebSocketDisconnect:
        return


@app.post("/scan/{scan_id}/stop", dependencies=[Depends(require_admin)])
async def stop_scan(scan_id: str) -> dict[str, str]:
    state = active_scans.get(scan_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if state["status"] != "running":
        raise HTTPException(status_code=409, detail="Scan is not running")
    task = state.get("task")
    if task is None:
        raise HTTPException(status_code=409, detail="Scan task is not available")
    task.cancel()
    return {"scan_id": scan_id, "status": "stopping"}


@app.get("/findings")
def get_findings(scan_id: str | None = None) -> dict[str, Any]:
    return {"findings": store.list_findings(scan_id)}


@app.get("/explain/{finding_id}")
def explain_finding(finding_id: str) -> dict[str, Any]:
    finding = next(
        (item for item in store.list_findings() if item["id"] == finding_id), None
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    vulnerability = finding["vulnerability"]
    explanations = {
        "classic_bola": (
            "The API looked up an object by its ID but did not enforce the caller's tenant boundary.",
            "An attacker could change an object ID and read another company's data.",
            "Derive tenant identity from the authenticated principal and include ownership in the database query. Deny by default.",
        ),
        "write_bola": (
            "The API accepted a write to an object owned by a different tenant.",
            "An attacker could modify or delete another company's records.",
            "Authorize ownership and role before every mutation; scope the update/delete query to the principal's tenant.",
        ),
        "role_access": (
            "The API allowed a viewer role to perform a write operation.",
            "Read-only users could change tenant data beyond their assigned permissions.",
            "Enforce action permissions server-side for every method and deny writes to viewer roles.",
        ),
        "list_leakage": (
            "A caller-controlled tenant filter returned data outside the caller's tenant.",
            "A list endpoint can expose many customer records in one request.",
            "Ignore caller-supplied tenant ownership and scope list queries to the authenticated tenant.",
        ),
        "mass_assignment": (
            "The API accepted an ownership field in a request body and changed resource ownership.",
            "A record could be transferred into an attacker's tenant or evade later checks.",
            "Use explicit request schemas and immutable server-controlled ownership fields.",
        ),
    }
    simple, impact, remediation = explanations.get(
        vulnerability,
        (
            finding["explanation"],
            "The observed behavior differs from the tenant authorization policy.",
            finding["fix_suggestion"],
        ),
    )
    return {
        "finding_id": finding_id,
        "source": "rule-based",
        "llm_invoked": False,
        "simple_explanation": simple,
        "impact": impact,
        "root_cause": finding["explanation"],
        "remediation": remediation,
    }


@app.get("/history")
def get_history(limit: int = Query(default=20, ge=1, le=100)) -> dict[str, Any]:
    return {"scans": store.list_scans(limit)}


@app.get("/overview")
def get_overview() -> dict[str, Any]:
    policy = load_policy()
    scans = store.list_scans(1000)
    reports = [
        store.get_scan(scan["scan_id"])
        for scan in scans
        if scan["status"] == "completed"
    ]
    reports = [report for report in reports if report is not None]
    latest = reports[0] if reports else None
    return {
        "total_tenants": len(policy.get("tenants", [])),
        "total_users": len(policy["principals"]),
        "total_resources": len(policy["resources"]),
        "total_scans": len(scans),
        "requests_tested": sum(report["total_tests"] for report in reports),
        "confirmed_leaks": sum(report["leak_count"] for report in reports),
        "blocked_requests": sum(
            1
            for report in reports
            for result in report["results"]
            if result["case"]["expected"] == "DENY"
            and result["status_code"] in (401, 403, 404)
        ),
        "security_score": latest["risk_score"] if latest else None,
        "recent_scans": scans[:8],
    }


@app.get("/retest")
def get_retest_results(baseline_scan_id: str | None = None) -> dict[str, Any]:
    return {"retests": list_retest_results(baseline_scan_id)}


@app.get("/target/mode")
async def get_target_mode() -> dict[str, Any]:
    target_url = active_target_url
    try:
        ensure_local_target(target_url)
        async with httpx.AsyncClient(
            base_url=target_url, timeout=httpx.Timeout(5.0, connect=3.0)
        ) as client:
            response = await client.get("/admin/mode")
            response.raise_for_status()
            return {**response.json(), "target_url": target_url}
    except (ValueError, httpx.HTTPError) as error:
        raise HTTPException(
            status_code=502, detail=f"Unable to read demo API mode: {error}"
        ) from error


@app.post("/target/mode", dependencies=[Depends(require_admin)])
async def set_target_mode(request: TargetModeRequest) -> dict[str, Any]:
    global active_target_url
    if any(state["status"] == "running" for state in active_scans.values()):
        raise HTTPException(status_code=409, detail="Cannot change mode during a scan")
    target_url = secure_target_url if request.mode == "secure" else vulnerable_target_url
    try:
        ensure_local_target(target_url)
        async with httpx.AsyncClient(
            base_url=target_url, timeout=httpx.Timeout(5.0, connect=3.0)
        ) as client:
            response = await client.get("/admin/mode")
            response.raise_for_status()
            target = response.json()
            if target.get("mode") != request.mode:
                raise HTTPException(
                    status_code=409,
                    detail=f"Configured {request.mode} API reports {target.get('mode')} mode",
                )
            active_target_url = target_url
            return {**target, "target_url": target_url}
    except (ValueError, httpx.HTTPError) as error:
        raise HTTPException(
            status_code=502, detail=f"Unable to change demo API mode: {error}"
        ) from error


@app.get("/report/{scan_id}")
def get_report(
    scan_id: str,
    format: Literal["markdown", "html", "sarif", "pdf"] = Query(default="markdown"),
) -> Response:
    report = store.get_scan(scan_id)
    if report is None or report.get("status") != "completed":
        raise HTTPException(status_code=404, detail="Completed scan not found")
    if format == "html":
        return Response(html_report(report), media_type="text/html")
    if format == "sarif":
        return Response(
            json.dumps(sarif_report(report), indent=2),
            media_type="application/sarif+json",
        )
    if format == "pdf":
        return Response(
            pdf_report(report),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="tenantfence-{scan_id[:8]}.pdf"'
            },
        )
    return Response(markdown_report(report), media_type="text/markdown")


@app.get("/regression/export")
def export_regression(scan_id: str | None = None) -> Response:
    if scan_id is None:
        completed = next(
            (
                scan
                for scan in store.list_scans(100)
                if scan["status"] == "completed"
            ),
            None,
        )
        scan_id = completed["scan_id"] if completed else None
    report = store.get_scan(scan_id) if scan_id else None
    if report is None or report.get("status") != "completed":
        raise HTTPException(status_code=404, detail="No completed scan is available")
    return Response(
        regression_archive(report),
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="tenantfence-regression.zip"'},
    )
