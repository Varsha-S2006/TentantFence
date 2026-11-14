import asyncio
import base64
import pytest
from backend.main import (
    BulkDeleteRequest,
    BulkRoleUpdateRequest,
    BulkStatusUpdateRequest,
    ImportCommitRequest,
    ImportValidateRequest,
    UserInput,
    UserUpdate,
    bulk_delete_users,
    bulk_update_role,
    bulk_update_status,
    commit_user_import,
    create_user,
    delete_user,
    download_user_template,
    get_user_audit_logs,
    list_users,
    load_policy,
    update_user,
    validate_user_import,
    validate_user_records,
)


def test_list_users_pagination_and_search():
    res = list_users(page=1, page_size=2)
    assert res["page"] == 1
    assert res["page_size"] == 2
    assert len(res["users"]) <= 2
    assert res["total"] >= 3
    assert "tenant_counts" in res

    # Test search
    search_res = list_users(search="alice")
    assert any(u["user_id"] == "alice" for u in search_res["users"])


def test_validate_user_records_detects_errors_and_duplicates():
    policy = load_policy()
    raw_data = [
        # Valid row
        {
            "Name": "Valid Employee",
            "Email": "valid.emp@companya.com",
            "Tenant ID": "tenant_A",
            "Role": "employee",
        },
        # Missing name
        {
            "Name": "",
            "Email": "noname@companya.com",
            "Tenant ID": "tenant_A",
            "Role": "viewer",
        },
        # Invalid email
        {
            "Name": "Bad Email",
            "Email": "not-an-email",
            "Tenant ID": "tenant_A",
            "Role": "viewer",
        },
        # Duplicate email in file
        {
            "Name": "Duplicate Emp",
            "Email": "valid.emp@companya.com",
            "Tenant ID": "tenant_A",
            "Role": "employee",
        },
        # Invalid role
        {
            "Name": "Bad Role",
            "Email": "badrole@companya.com",
            "Tenant ID": "tenant_A",
            "Role": "superadmin",
        },
        # Unknown tenant
        {
            "Name": "Wrong Tenant",
            "Email": "wrongtenant@unknown.com",
            "Tenant ID": "tenant_NONEXISTENT",
            "Role": "employee",
        },
    ]
    val = validate_user_records(raw_data, policy)
    assert val["total_records"] == 6
    assert val["valid_count"] == 1
    assert val["error_count"] == 5

    # Check error reasons
    records = val["records"]
    assert records[0]["is_valid"] is True
    assert any("Name" in err for err in records[1]["errors"])
    assert any("email" in err.lower() for err in records[2]["errors"])
    assert any("Duplicate email" in err for err in records[3]["errors"])
    assert any("role" in err.lower() for err in records[4]["errors"])
    assert any("tenant" in err.lower() for err in records[5]["errors"])


def test_automatic_tenant_mapping():
    policy = load_policy()
    # Company A name mapping
    raw = [
        {
            "Name": "Mapped User",
            "Email": "mapped@companya.com",
            "Company": "Company A",
            "Role": "employee",
        }
    ]
    val = validate_user_records(raw, policy)
    assert val["valid_count"] == 1
    assert val["records"][0]["tenant_id"] == "tenant_A"
    assert val["records"][0]["tenant_name"] == "Company A"


def test_tenant_isolation_in_import():
    policy = load_policy()
    # Scoped to tenant_A, but row specifies tenant_B -> violation
    raw = [
        {
            "Name": "Tenant B User",
            "Email": "user@b.com",
            "Tenant ID": "tenant_B",
            "Role": "employee",
        }
    ]
    val = validate_user_records(raw, policy, target_tenant_id="tenant_A")
    assert val["valid_count"] == 0
    assert any("mismatch" in err.lower() for err in val["records"][0]["errors"])


def test_bulk_operations_and_audit_logging():
    new_user = UserInput(
        user_id="test_bulk_user",
        name="Test Bulk User",
        email="test_bulk_user@companya.com",
        tenant_id="tenant_A",
        role="employee",
        status="active",
    )
    created = create_user(new_user)
    assert created["user_id"] == "test_bulk_user"

    res_role = bulk_update_role(
        BulkRoleUpdateRequest(user_ids=["test_bulk_user"], role="admin")
    )
    assert res_role["updated_count"] == 1
    assert res_role["role"] == "admin"

    res_status = bulk_update_status(
        BulkStatusUpdateRequest(user_ids=["test_bulk_user"], status="inactive")
    )
    assert res_status["updated_count"] == 1
    assert res_status["status"] == "inactive"

    res_del = bulk_delete_users(BulkDeleteRequest(user_ids=["test_bulk_user"]))
    assert res_del["deleted_count"] == 1

    logs_res = get_user_audit_logs()
    actions = [log["action"] for log in logs_res["logs"]]
    assert "user_create" in actions
    assert "bulk_role_update" in actions
    assert "bulk_status_update" in actions
    assert "bulk_delete" in actions


def test_download_user_template():
    resp = download_user_template()
    assert resp.status_code == 200
    assert "text/csv" in resp.media_type
    assert "Name,Email,User ID,Tenant ID,Role,Status" in resp.body.decode("utf-8")


def test_bulk_import_csv_workflow():
    csv_text = "Name,Email,Role,Tenant ID\nBulk One,bulk1@companya.com,employee,tenant_A\nBulk Two,bulk2@companya.com,viewer,tenant_A\n"
    b64 = base64.b64encode(csv_text.encode("utf-8")).decode("ascii")
    val = validate_user_import(ImportValidateRequest(file_content=b64, filename="bulk.csv"))
    assert val["valid_count"] == 2
    assert val["error_count"] == 0

    commit_res = commit_user_import(
        ImportCommitRequest(
            records=val["records"],
            target_tenant_id="tenant_A",
            file_name="bulk.csv",
            skip_errors=True,
        )
    )
    assert commit_res["imported_count"] == 2

    # Verify they appear in list_users
    users_data = list_users(tenant_id="tenant_A", search="Bulk")
    assert users_data["total"] >= 2

    # Clean up
    bulk_delete_users(BulkDeleteRequest(user_ids=["bulk1", "bulk2"]))
