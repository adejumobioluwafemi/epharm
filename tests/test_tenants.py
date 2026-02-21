"""
FILE: tests/test_tenants.py
Tenant management tests for the E-Pharmacy multi-tenant API.
All tenant endpoints are SUPER_ADMIN-only.

Covers:
  POST /api/v1/tenants
  GET  /api/v1/tenants
  GET  /api/v1/tenants/{tenant_id}
"""

import pytest
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from src.shared.models import Tenant


# ============================================================================
# CREATE TENANT — POST /api/v1/tenants
# ============================================================================

@pytest.mark.tenants
class TestCreateTenant:
    """POST /api/v1/tenants — SUPER_ADMIN only."""

    def test_super_admin_can_create_tenant(
        self,
        client: TestClient,
        super_admin_headers: dict,
        session: Session,
    ):
        """SUPER_ADMIN must be able to create a new pharmacy tenant."""
        response = client.post(
            "/api/v1/tenants",
            headers=super_admin_headers,
            json={
                "name": "New Pharmacy Ltd.",
                "slug": "new-pharmacy",
                "registration_number": "PHRM-2024-NEW",
                "email": "admin@newpharmacy.com",
                "phone": "+2348099900000",
                "address": "99 New Street, Abuja",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["data"]["name"] == "New Pharmacy Ltd."
        assert data["data"]["slug"] == "new-pharmacy"
        assert "id" in data["data"]

    def test_create_tenant_persisted_in_database(
        self,
        client: TestClient,
        super_admin_headers: dict,
        session: Session,
    ):
        """A successfully created tenant must exist in the tenants table."""
        from uuid import UUID

        response = client.post(
            "/api/v1/tenants",
            headers=super_admin_headers,
            json={
                "name": "DB Pharmacy",
                "slug": "db-pharmacy",
            },
        )

        assert response.status_code == 200
        tenant_id = UUID(response.json()["data"]["id"])
        record = session.get(Tenant, tenant_id)
        assert record is not None
        assert record.name == "DB Pharmacy"

    def test_create_tenant_is_active_by_default(
        self,
        client: TestClient,
        super_admin_headers: dict,
    ):
        """Newly created tenants must be active by default."""
        response = client.post(
            "/api/v1/tenants",
            headers=super_admin_headers,
            json={"name": "Active Tenant", "slug": "active-tenant"},
        )

        assert response.status_code == 200
        assert response.json()["data"]["is_active"] is True

    def test_create_tenant_duplicate_slug_returns_400(
        self,
        client: TestClient,
        super_admin_headers: dict,
        demo_tenant: Tenant,
    ):
        """Slug must be unique; a duplicate must return 400."""
        response = client.post(
            "/api/v1/tenants",
            headers=super_admin_headers,
            json={
                "name": "Another Demo",
                "slug": demo_tenant.slug,  # already taken
            },
        )

        assert response.status_code == 400
        assert "slug" in response.json()["detail"].lower()

    def test_create_tenant_invalid_slug_characters_returns_422(
        self,
        client: TestClient,
        super_admin_headers: dict,
    ):
        """Slug must match ^[a-z0-9\\-]+$; uppercase or special chars must fail."""
        response = client.post(
            "/api/v1/tenants",
            headers=super_admin_headers,
            json={"name": "Bad Slug Tenant", "slug": "Bad_Slug!"},
        )

        assert response.status_code == 422

    def test_create_tenant_slug_too_short_returns_422(
        self,
        client: TestClient,
        super_admin_headers: dict,
    ):
        """Slug min_length=2; single character slug must fail."""
        response = client.post(
            "/api/v1/tenants",
            headers=super_admin_headers,
            json={"name": "Tiny", "slug": "x"},
        )

        assert response.status_code == 422

    def test_tenant_admin_cannot_create_tenant(
        self,
        client: TestClient,
        tenant_admin_headers: dict,
    ):
        """TENANT_ADMIN is scoped to their own tenant and must receive 403."""
        response = client.post(
            "/api/v1/tenants",
            headers=tenant_admin_headers,
            json={"name": "Forbidden Tenant", "slug": "forbidden-tenant"},
        )

        assert response.status_code == 403

    def test_store_manager_cannot_create_tenant(
        self,
        client: TestClient,
        store_manager_headers: dict,
    ):
        """STORE_MANAGER must receive 403."""
        response = client.post(
            "/api/v1/tenants",
            headers=store_manager_headers,
            json={"name": "Forbidden", "slug": "forbidden-store"},
        )

        assert response.status_code == 403

    def test_create_tenant_unauthenticated_returns_401(self, client: TestClient):
        response = client.post(
            "/api/v1/tenants",
            json={"name": "NoAuth Tenant", "slug": "noauth-tenant"},
        )

        assert response.status_code == 401

    def test_create_tenant_missing_required_fields_returns_422(
        self, client: TestClient, super_admin_headers: dict
    ):
        """Both name and slug are required; omitting either must fail validation."""
        response = client.post(
            "/api/v1/tenants",
            headers=super_admin_headers,
            json={"name": "Missing Slug Only"},
        )

        assert response.status_code == 422


# ============================================================================
# LIST TENANTS — GET /api/v1/tenants
# ============================================================================

@pytest.mark.tenants
class TestListTenants:
    """GET /api/v1/tenants — SUPER_ADMIN only, paginated."""

    def test_super_admin_can_list_all_tenants(
        self,
        client: TestClient,
        super_admin_headers: dict,
        demo_tenant: Tenant,
        second_tenant: Tenant,
    ):
        """SUPER_ADMIN must receive a paginated list of all tenants."""
        response = client.get("/api/v1/tenants", headers=super_admin_headers)

        assert response.status_code == 200
        body = response.json()
        assert body["success"] is True
        assert isinstance(body["data"], list)
        assert body["total"] >= 2

    def test_list_tenants_default_pagination(
        self, client: TestClient, super_admin_headers: dict
    ):
        """Default pagination must be page=1, page_size=20."""
        response = client.get("/api/v1/tenants", headers=super_admin_headers)

        body = response.json()
        assert body["page"] == 1
        assert body["page_size"] == 20

    def test_list_tenants_custom_page_size(
        self,
        client: TestClient,
        super_admin_headers: dict,
        demo_tenant: Tenant,
    ):
        """Custom page_size must be honoured."""
        response = client.get(
            "/api/v1/tenants",
            headers=super_admin_headers,
            params={"page": 1, "page_size": 2},
        )

        body = response.json()
        assert body["page_size"] == 2
        assert len(body["data"]) <= 2

    def test_list_tenants_response_contains_required_fields(
        self,
        client: TestClient,
        super_admin_headers: dict,
        demo_tenant: Tenant,
    ):
        """Each TenantOut item must include id, name, slug, is_active, created_at."""
        response = client.get("/api/v1/tenants", headers=super_admin_headers)

        for tenant in response.json()["data"]:
            for field in ["id", "name", "slug", "is_active", "created_at"]:
                assert field in tenant, f"Missing field: {field}"

    def test_tenant_admin_cannot_list_tenants(
        self, client: TestClient, tenant_admin_headers: dict
    ):
        """TENANT_ADMIN must receive 403."""
        response = client.get("/api/v1/tenants", headers=tenant_admin_headers)

        assert response.status_code == 403

    def test_store_manager_cannot_list_tenants(
        self, client: TestClient, store_manager_headers: dict
    ):
        """STORE_MANAGER must receive 403."""
        response = client.get("/api/v1/tenants", headers=store_manager_headers)

        assert response.status_code == 403

    def test_list_tenants_unauthenticated_returns_401(self, client: TestClient):
        response = client.get("/api/v1/tenants")

        assert response.status_code == 401

    def test_list_tenants_page_zero_returns_400(
        self, client: TestClient, super_admin_headers: dict
    ):
        response = client.get(
            "/api/v1/tenants",
            headers=super_admin_headers,
            params={"page": 0},
        )

        assert response.status_code == 400


# ============================================================================
# GET TENANT BY ID — GET /api/v1/tenants/{tenant_id}
# ============================================================================

@pytest.mark.tenants
class TestGetTenantById:
    """GET /api/v1/tenants/{tenant_id} — SUPER_ADMIN only."""

    def test_super_admin_can_get_tenant_by_id(
        self,
        client: TestClient,
        super_admin_headers: dict,
        demo_tenant: Tenant,
    ):
        """SUPER_ADMIN must be able to retrieve a tenant by its UUID."""
        response = client.get(
            f"/api/v1/tenants/{demo_tenant.id}",
            headers=super_admin_headers,
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["id"] == str(demo_tenant.id)
        assert data["name"] == demo_tenant.name
        assert data["slug"] == demo_tenant.slug

    def test_get_second_tenant_by_id(
        self,
        client: TestClient,
        super_admin_headers: dict,
        second_tenant: Tenant,
    ):
        """SUPER_ADMIN can access any tenant, not just the demo one."""
        response = client.get(
            f"/api/v1/tenants/{second_tenant.id}",
            headers=super_admin_headers,
        )

        assert response.status_code == 200
        assert response.json()["data"]["id"] == str(second_tenant.id)

    def test_get_nonexistent_tenant_returns_404(
        self, client: TestClient, super_admin_headers: dict
    ):
        """A UUID that doesn't correspond to any tenant must return 404."""
        response = client.get(
            f"/api/v1/tenants/{uuid4()}",
            headers=super_admin_headers,
        )

        assert response.status_code == 404

    def test_tenant_admin_cannot_get_tenant_by_id(
        self,
        client: TestClient,
        tenant_admin_headers: dict,
        demo_tenant: Tenant,
    ):
        """Even their own tenant is off-limits via this endpoint for TENANT_ADMIN."""
        response = client.get(
            f"/api/v1/tenants/{demo_tenant.id}",
            headers=tenant_admin_headers,
        )

        assert response.status_code == 403

    def test_store_manager_cannot_get_tenant_by_id(
        self,
        client: TestClient,
        store_manager_headers: dict,
        demo_tenant: Tenant,
    ):
        """STORE_MANAGER must receive 403."""
        response = client.get(
            f"/api/v1/tenants/{demo_tenant.id}",
            headers=store_manager_headers,
        )

        assert response.status_code == 403

    def test_get_tenant_unauthenticated_returns_401(
        self, client: TestClient, demo_tenant: Tenant
    ):
        response = client.get(f"/api/v1/tenants/{demo_tenant.id}")

        assert response.status_code == 401


# ============================================================================
# RUN
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])