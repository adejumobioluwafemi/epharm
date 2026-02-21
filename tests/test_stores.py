"""
FILE: tests/test_stores.py
Pharmacy store management tests for the E-Pharmacy multi-tenant API.

Covers:
  POST  /api/v1/stores
  GET   /api/v1/stores
  GET   /api/v1/stores/{store_id}
  PATCH /api/v1/stores/{store_id}/deactivate
"""

import pytest
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlmodel import Session

from src.shared.models import PharmacyStore, Tenant


# ============================================================================
# CREATE STORE — POST /api/v1/stores
# ============================================================================

@pytest.mark.stores
class TestCreateStore:
    """POST /api/v1/stores — tenant admin+"""

    def _store_payload(self, suffix: str = "") -> dict:
        """Return a valid CreateStoreRequest payload."""
        return {
            "name": f"Test Branch{suffix}",
            "address": "456 Test Road, Lagos",
            "city": "Lagos",
            "state": "Lagos",
            "postal_code": "100001",
            "phone": "+2348091111111",
            "email": f"branch{suffix}@demopharmacy.com",
            "latitude": 6.5244,
            "longitude": 3.3792,
        }

    def test_tenant_admin_can_create_store(
        self,
        client: TestClient,
        tenant_admin_headers: dict,
        demo_tenant: Tenant,
        session: Session,
    ):
        """TENANT_ADMIN must be able to create a store within their tenant."""
        response = client.post(
            "/api/v1/stores",
            headers=tenant_admin_headers,
            json=self._store_payload(),
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["data"]["name"] == "Test Branch"
        assert data["data"]["tenant_id"] == str(demo_tenant.id)
        assert "id" in data["data"]

    def test_super_admin_can_create_store(
        self,
        client: TestClient,
        super_admin_headers: dict,
    ):
        """SUPER_ADMIN must also be able to create a store."""
        response = client.post(
            "/api/v1/stores",
            headers=super_admin_headers,
            json=self._store_payload("_sa"),
        )

        assert response.status_code == 200

    def test_create_store_is_active_by_default(
        self,
        client: TestClient,
        tenant_admin_headers: dict,
    ):
        """Newly created stores must be active."""
        response = client.post(
            "/api/v1/stores",
            headers=tenant_admin_headers,
            json=self._store_payload("_active"),
        )

        assert response.status_code == 200
        assert response.json()["data"]["is_active"] is True

    def test_store_manager_cannot_create_store(
        self,
        client: TestClient,
        store_manager_headers: dict,
    ):
        """STORE_MANAGER is below TENANT_ADMIN; must receive 403."""
        response = client.post(
            "/api/v1/stores",
            headers=store_manager_headers,
            json=self._store_payload("_mgr"),
        )

        assert response.status_code == 403

    def test_plain_pharmacist_cannot_create_store(
        self,
        client: TestClient,
        pharmacist_headers: dict,
    ):
        """PHARMACIST must receive 403."""
        response = client.post(
            "/api/v1/stores",
            headers=pharmacist_headers,
            json=self._store_payload("_pharm"),
        )

        assert response.status_code == 403

    def test_create_store_unauthenticated_returns_401(self, client: TestClient):
        response = client.post("/api/v1/stores", json=self._store_payload("_noauth"))

        assert response.status_code == 401

    def test_create_store_missing_required_name_returns_422(
        self, client: TestClient, tenant_admin_headers: dict
    ):
        """name is required; omitting it must fail validation."""
        payload = self._store_payload()
        del payload["name"]
        response = client.post(
            "/api/v1/stores",
            headers=tenant_admin_headers,
            json=payload,
        )

        assert response.status_code == 422

    def test_create_store_missing_required_address_returns_422(
        self, client: TestClient, tenant_admin_headers: dict
    ):
        """address is required; omitting it must fail validation."""
        payload = self._store_payload()
        del payload["address"]
        response = client.post(
            "/api/v1/stores",
            headers=tenant_admin_headers,
            json=payload,
        )

        assert response.status_code == 422

    def test_create_store_invalid_latitude_returns_422(
        self, client: TestClient, tenant_admin_headers: dict
    ):
        """latitude must be in [-90, 90]; out-of-range values must fail."""
        payload = self._store_payload("_lat")
        payload["latitude"] = 999.0
        response = client.post(
            "/api/v1/stores",
            headers=tenant_admin_headers,
            json=payload,
        )

        assert response.status_code == 422

    def test_create_store_invalid_longitude_returns_422(
        self, client: TestClient, tenant_admin_headers: dict
    ):
        """longitude must be in [-180, 180]; out-of-range values must fail."""
        payload = self._store_payload("_lng")
        payload["longitude"] = -999.0
        response = client.post(
            "/api/v1/stores",
            headers=tenant_admin_headers,
            json=payload,
        )

        assert response.status_code == 422

    def test_create_store_optional_fields_are_nullable(
        self,
        client: TestClient,
        tenant_admin_headers: dict,
    ):
        """Only name and address are required; all other fields are optional."""
        response = client.post(
            "/api/v1/stores",
            headers=tenant_admin_headers,
            json={"name": "Minimal Store", "address": "1 Minimal Road"},
        )

        assert response.status_code == 200


# ============================================================================
# LIST STORES — GET /api/v1/stores
# ============================================================================

@pytest.mark.stores
class TestListStores:
    """GET /api/v1/stores — store manager+, tenant-scoped, paginated."""

    def test_store_manager_can_list_stores(
        self,
        client: TestClient,
        store_manager_headers: dict,
        demo_store: PharmacyStore,
    ):
        """STORE_MANAGER must be able to list stores in their tenant."""
        response = client.get("/api/v1/stores", headers=store_manager_headers)

        assert response.status_code == 200
        body = response.json()
        assert body["success"] is True
        assert isinstance(body["data"], list)
        assert body["total"] >= 1

    def test_tenant_admin_can_list_stores(
        self,
        client: TestClient,
        tenant_admin_headers: dict,
        demo_store: PharmacyStore,
    ):
        """TENANT_ADMIN must also be able to list stores."""
        response = client.get("/api/v1/stores", headers=tenant_admin_headers)

        assert response.status_code == 200

    def test_plain_pharmacist_cannot_list_stores(
        self, client: TestClient, pharmacist_headers: dict
    ):
        """PHARMACIST is below STORE_MANAGER; must receive 403."""
        response = client.get("/api/v1/stores", headers=pharmacist_headers)

        assert response.status_code == 403

    def test_list_stores_unauthenticated_returns_401(self, client: TestClient):
        response = client.get("/api/v1/stores")

        assert response.status_code == 401

    def test_list_stores_default_pagination(
        self, client: TestClient, store_manager_headers: dict
    ):
        """Default pagination must be page=1, page_size=20."""
        response = client.get("/api/v1/stores", headers=store_manager_headers)

        body = response.json()
        assert body["page"] == 1
        assert body["page_size"] == 20

    def test_list_stores_custom_page_size(
        self,
        client: TestClient,
        store_manager_headers: dict,
        demo_store: PharmacyStore,
    ):
        """Custom page_size must be honoured."""
        response = client.get(
            "/api/v1/stores",
            headers=store_manager_headers,
            params={"page": 1, "page_size": 1},
        )

        body = response.json()
        assert body["page_size"] == 1
        assert len(body["data"]) <= 1

    def test_list_stores_response_contains_required_fields(
        self,
        client: TestClient,
        store_manager_headers: dict,
        demo_store: PharmacyStore,
    ):
        """Each StoreOut item must include id, tenant_id, name, address, is_active, created_at."""
        response = client.get("/api/v1/stores", headers=store_manager_headers)

        for store in response.json()["data"]:
            for field in ["id", "tenant_id", "name", "address", "is_active", "created_at"]:
                assert field in store, f"Missing field: {field}"

    def test_list_stores_only_returns_own_tenant_stores(
        self,
        client: TestClient,
        store_manager_headers: dict,
        other_tenant_store: PharmacyStore,
    ):
        """Stores from a different tenant must not appear in the response."""
        response = client.get("/api/v1/stores", headers=store_manager_headers)

        returned_ids = {s["id"] for s in response.json()["data"]}
        assert str(other_tenant_store.id) not in returned_ids

    def test_list_stores_page_zero_returns_400(
        self, client: TestClient, store_manager_headers: dict
    ):
        response = client.get(
            "/api/v1/stores",
            headers=store_manager_headers,
            params={"page": 0},
        )

        assert response.status_code == 400


# ============================================================================
# GET STORE BY ID — GET /api/v1/stores/{store_id}
# ============================================================================

@pytest.mark.stores
class TestGetStoreById:
    """GET /api/v1/stores/{store_id} — store manager+, tenant-scoped."""

    def test_store_manager_can_get_store_in_same_tenant(
        self,
        client: TestClient,
        store_manager_headers: dict,
        demo_store: PharmacyStore,
    ):
        """STORE_MANAGER must be able to retrieve a store within their tenant."""
        response = client.get(
            f"/api/v1/stores/{demo_store.id}",
            headers=store_manager_headers,
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["id"] == str(demo_store.id)
        assert data["name"] == demo_store.name

    def test_tenant_admin_can_get_any_store_in_tenant(
        self,
        client: TestClient,
        tenant_admin_headers: dict,
        second_store: PharmacyStore,
    ):
        """TENANT_ADMIN must be able to get any store in their tenant."""
        response = client.get(
            f"/api/v1/stores/{second_store.id}",
            headers=tenant_admin_headers,
        )

        assert response.status_code == 200

    def test_plain_pharmacist_cannot_get_store(
        self,
        client: TestClient,
        pharmacist_headers: dict,
        demo_store: PharmacyStore,
    ):
        """PHARMACIST must receive 403."""
        response = client.get(
            f"/api/v1/stores/{demo_store.id}",
            headers=pharmacist_headers,
        )

        assert response.status_code == 403

    def test_store_manager_cannot_get_store_from_other_tenant(
        self,
        client: TestClient,
        store_manager_headers: dict,
        other_tenant_store: PharmacyStore,
    ):
        """Cross-tenant store lookup must return 403."""
        response = client.get(
            f"/api/v1/stores/{other_tenant_store.id}",
            headers=store_manager_headers,
        )

        assert response.status_code == 403

    def test_get_nonexistent_store_returns_404(
        self, client: TestClient, store_manager_headers: dict
    ):
        """A UUID that doesn't correspond to any store must return 404."""
        response = client.get(
            f"/api/v1/stores/{uuid4()}",
            headers=store_manager_headers,
        )

        assert response.status_code == 404

    def test_get_store_unauthenticated_returns_401(
        self, client: TestClient, demo_store: PharmacyStore
    ):
        response = client.get(f"/api/v1/stores/{demo_store.id}")

        assert response.status_code == 401


# ============================================================================
# DEACTIVATE STORE — PATCH /api/v1/stores/{store_id}/deactivate
# ============================================================================

@pytest.mark.stores
class TestDeactivateStore:
    """PATCH /api/v1/stores/{store_id}/deactivate — tenant admin+"""

    def test_tenant_admin_can_deactivate_store(
        self,
        client: TestClient,
        tenant_admin_headers: dict,
        second_store: PharmacyStore,
        session: Session,
    ):
        """TENANT_ADMIN must be able to deactivate a store in their tenant."""
        response = client.patch(
            f"/api/v1/stores/{second_store.id}/deactivate",
            headers=tenant_admin_headers,
        )

        assert response.status_code == 200
        assert response.json()["success"] is True

        session.refresh(second_store)
        assert second_store.is_active is False

    def test_super_admin_can_deactivate_any_store(
        self,
        client: TestClient,
        super_admin_headers: dict,
        second_store: PharmacyStore,
        session: Session,
    ):
        """SUPER_ADMIN must also be able to deactivate a store."""
        response = client.patch(
            f"/api/v1/stores/{second_store.id}/deactivate",
            headers=super_admin_headers,
        )

        assert response.status_code == 200

    def test_store_manager_cannot_deactivate_store(
        self,
        client: TestClient,
        store_manager_headers: dict,
        second_store: PharmacyStore,
    ):
        """STORE_MANAGER is below TENANT_ADMIN; must receive 403."""
        response = client.patch(
            f"/api/v1/stores/{second_store.id}/deactivate",
            headers=store_manager_headers,
        )

        assert response.status_code == 403

    def test_plain_pharmacist_cannot_deactivate_store(
        self,
        client: TestClient,
        pharmacist_headers: dict,
        demo_store: PharmacyStore,
    ):
        """PHARMACIST must receive 403."""
        response = client.patch(
            f"/api/v1/stores/{demo_store.id}/deactivate",
            headers=pharmacist_headers,
        )

        assert response.status_code == 403

    def test_cannot_deactivate_store_from_other_tenant(
        self,
        client: TestClient,
        tenant_admin_headers: dict,
        other_tenant_store: PharmacyStore,
    ):
        """Cross-tenant deactivation must return 403."""
        response = client.patch(
            f"/api/v1/stores/{other_tenant_store.id}/deactivate",
            headers=tenant_admin_headers,
        )

        assert response.status_code == 403

    def test_deactivate_nonexistent_store_returns_404(
        self, client: TestClient, tenant_admin_headers: dict
    ):
        response = client.patch(
            f"/api/v1/stores/{uuid4()}/deactivate",
            headers=tenant_admin_headers,
        )

        assert response.status_code == 404

    def test_deactivate_store_unauthenticated_returns_401(
        self, client: TestClient, second_store: PharmacyStore
    ):
        response = client.patch(f"/api/v1/stores/{second_store.id}/deactivate")

        assert response.status_code == 401


# ============================================================================
# STORE TENANT ISOLATION — cross-cutting
# ============================================================================

@pytest.mark.tenant_isolation
class TestStoreTenantIsolation:
    """Verifies that store endpoints enforce strict tenant boundaries."""

    def test_list_never_exposes_other_tenant_stores(
        self,
        client: TestClient,
        store_manager_headers: dict,
        other_tenant_store: PharmacyStore,
    ):
        """GET /stores must not return stores from a different tenant."""
        response = client.get("/api/v1/stores", headers=store_manager_headers)

        returned_ids = {s["id"] for s in response.json()["data"]}
        assert str(other_tenant_store.id) not in returned_ids

    def test_other_tenant_token_cannot_list_demo_tenant_stores(
        self,
        client: TestClient,
        other_tenant_headers: dict,
        demo_store: PharmacyStore,
    ):
        """Token from tenant B must not expose tenant A stores."""
        response = client.get("/api/v1/stores", headers=other_tenant_headers)

        returned_ids = {s["id"] for s in response.json()["data"]}
        assert str(demo_store.id) not in returned_ids

    def test_other_tenant_token_cannot_get_demo_store(
        self,
        client: TestClient,
        other_tenant_headers: dict,
        demo_store: PharmacyStore,
    ):
        """Direct GET /stores/{id} with cross-tenant store must return 403."""
        response = client.get(
            f"/api/v1/stores/{demo_store.id}",
            headers=other_tenant_headers,
        )

        assert response.status_code == 403

    def test_other_tenant_admin_cannot_deactivate_demo_store(
        self,
        client: TestClient,
        other_tenant_headers: dict,
        demo_store: PharmacyStore,
    ):
        """Deactivation from a different tenant must return 403."""
        response = client.patch(
            f"/api/v1/stores/{demo_store.id}/deactivate",
            headers=other_tenant_headers,
        )

        assert response.status_code == 403


# ============================================================================
# RUN
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])