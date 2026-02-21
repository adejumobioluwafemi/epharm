"""
FILE: tests/test_users.py
Comprehensive user-management tests for the E-Pharmacy multi-tenant API.
Follows the same class-per-endpoint, fixture-per-scenario pattern as the reference codebase.

Covers:
  GET    /api/v1/users           (list, paginated)
  GET    /api/v1/users/me
  GET    /api/v1/users/{id}
  PATCH  /api/v1/users/{id}
  PATCH  /api/v1/users/{id}/deactivate
  PATCH  /api/v1/users/{id}/lock
  PATCH  /api/v1/users/{id}/unlock
"""

import pytest
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlmodel import Session

from src.shared.models import (
    PharmacyStore,
    RoleName,
    Tenant,
    User,
    UserRole,
)


# ============================================================================
# LIST USERS — GET /api/v1/users
# ============================================================================

@pytest.mark.users
class TestListUsers:
    """GET /api/v1/users — paginated, tenant-scoped."""

    def test_store_manager_can_list_users(
        self,
        client: TestClient,
        store_manager_headers: dict,
        pharmacist_user: dict,
    ):
        """STORE_MANAGER must be able to retrieve the tenant user list."""
        response = client.get("/api/v1/users", headers=store_manager_headers)

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert isinstance(data["data"], list)
        assert data["total"] >= 1
        assert "page" in data
        assert "page_size" in data
        assert "total_pages" in data

    def test_tenant_admin_can_list_users(
        self,
        client: TestClient,
        tenant_admin_headers: dict,
        pharmacist_user: dict,
    ):
        """TENANT_ADMIN must also be able to list users."""
        response = client.get("/api/v1/users", headers=tenant_admin_headers)

        assert response.status_code == 200
        assert response.json()["success"] is True

    def test_super_admin_can_list_users(
        self,
        client: TestClient,
        super_admin_headers: dict,
    ):
        """SUPER_ADMIN has the highest privilege and must be able to list users."""
        response = client.get("/api/v1/users", headers=super_admin_headers)

        assert response.status_code == 200

    def test_plain_pharmacist_cannot_list_users(
        self, client: TestClient, pharmacist_headers: dict
    ):
        """PHARMACIST role is below STORE_MANAGER; must receive 403."""
        response = client.get("/api/v1/users", headers=pharmacist_headers)

        assert response.status_code == 403

    def test_unauthenticated_cannot_list_users(self, client: TestClient):
        """Request without a token must return 401."""
        response = client.get("/api/v1/users")

        assert response.status_code == 401

    def test_list_users_default_pagination_values(
        self, client: TestClient, store_manager_headers: dict
    ):
        """Default page=1 and page_size=20 must be reflected in the response."""
        response = client.get("/api/v1/users", headers=store_manager_headers)

        body = response.json()
        assert body["page"] == 1
        assert body["page_size"] == 20

    def test_list_users_custom_pagination(
        self, client: TestClient, store_manager_headers: dict
    ):
        """Custom page/page_size params must be honoured."""
        response = client.get(
            "/api/v1/users",
            headers=store_manager_headers,
            params={"page": 1, "page_size": 5},
        )

        body = response.json()
        assert body["page"] == 1
        assert body["page_size"] == 5
        assert len(body["data"]) <= 5

    def test_list_users_page_zero_returns_400(
        self, client: TestClient, store_manager_headers: dict
    ):
        """page=0 is invalid and must return 400."""
        response = client.get(
            "/api/v1/users",
            headers=store_manager_headers,
            params={"page": 0},
        )

        assert response.status_code == 400

    def test_list_users_page_size_exceeds_limit_returns_400(
        self, client: TestClient, store_manager_headers: dict
    ):
        """page_size > 200 must return 400."""
        response = client.get(
            "/api/v1/users",
            headers=store_manager_headers,
            params={"page_size": 500},
        )

        assert response.status_code == 400

    def test_list_users_excludes_other_tenant_users(
        self,
        client: TestClient,
        store_manager_headers: dict,
        other_tenant_user: dict,
    ):
        """Users from a different tenant must NOT appear in the response."""
        response = client.get("/api/v1/users", headers=store_manager_headers)

        returned_ids = {u["id"] for u in response.json()["data"]}
        assert str(other_tenant_user["user"].id) not in returned_ids

    def test_list_users_response_includes_roles_field(
        self,
        client: TestClient,
        store_manager_headers: dict,
        pharmacist_user: dict,
    ):
        """Each UserWithRoles item must include a roles list."""
        response = client.get("/api/v1/users", headers=store_manager_headers)

        users = response.json()["data"]
        users_with_roles = [u for u in users if len(u.get("roles", [])) > 0]
        assert len(users_with_roles) > 0

    def test_list_users_response_includes_store_ids_field(
        self,
        client: TestClient,
        store_manager_headers: dict,
        pharmacist_user: dict,
    ):
        """Each UserWithRoles item must include a store_ids list."""
        response = client.get("/api/v1/users", headers=store_manager_headers)

        users = response.json()["data"]
        for user in users:
            assert "store_ids" in user


# ============================================================================
# GET MY PROFILE — GET /api/v1/users/me
# ============================================================================

@pytest.mark.users
class TestGetMyProfile:
    """GET /api/v1/users/me — any authenticated user."""

    def test_get_my_profile_success(
        self,
        client: TestClient,
        pharmacist_headers: dict,
        pharmacist_user: dict,
    ):
        """Authenticated user must receive their own profile data."""
        response = client.get("/api/v1/users/me", headers=pharmacist_headers)

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["email"] == pharmacist_user["user"].email
        assert data["first_name"] == pharmacist_user["user"].first_name
        assert data["last_name"] == pharmacist_user["user"].last_name

    def test_get_my_profile_contains_expected_fields(
        self, client: TestClient, pharmacist_headers: dict
    ):
        """Profile response must include all UserOut schema fields."""
        response = client.get("/api/v1/users/me", headers=pharmacist_headers)

        data = response.json()["data"]
        required_fields = [
            "id", "email", "first_name", "last_name",
            "user_type", "is_active", "is_locked", "login_count", "created_at",
        ]
        for field in required_fields:
            assert field in data, f"Missing expected field: {field}"

    def test_store_manager_gets_own_profile(
        self,
        client: TestClient,
        store_manager_headers: dict,
        store_manager_user: dict,
    ):
        """STORE_MANAGER must see their own profile, not someone else's."""
        response = client.get("/api/v1/users/me", headers=store_manager_headers)

        assert response.status_code == 200
        assert response.json()["data"]["email"] == store_manager_user["user"].email

    def test_get_my_profile_unauthenticated_returns_401(self, client: TestClient):
        """Request without token must return 401."""
        response = client.get("/api/v1/users/me")

        assert response.status_code == 401


# ============================================================================
# GET USER BY ID — GET /api/v1/users/{user_id}
# ============================================================================

@pytest.mark.users
class TestGetUserById:
    """GET /api/v1/users/{user_id} — store manager+"""

    def test_store_manager_can_get_user_in_same_tenant(
        self,
        client: TestClient,
        store_manager_headers: dict,
        pharmacist_user: dict,
    ):
        """STORE_MANAGER must be able to retrieve any user within their tenant."""
        response = client.get(
            f"/api/v1/users/{pharmacist_user['user'].id}",
            headers=store_manager_headers,
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["id"] == str(pharmacist_user["user"].id)
        assert "roles" in data

    def test_tenant_admin_can_get_any_tenant_user(
        self,
        client: TestClient,
        tenant_admin_headers: dict,
        pharmacist_user: dict,
    ):
        """TENANT_ADMIN must be able to retrieve any user in their tenant."""
        response = client.get(
            f"/api/v1/users/{pharmacist_user['user'].id}",
            headers=tenant_admin_headers,
        )

        assert response.status_code == 200

    def test_plain_pharmacist_cannot_get_other_users(
        self,
        client: TestClient,
        pharmacist_headers: dict,
        store_manager_user: dict,
    ):
        """PHARMACIST is below STORE_MANAGER and must receive 403."""
        response = client.get(
            f"/api/v1/users/{store_manager_user['user'].id}",
            headers=pharmacist_headers,
        )

        assert response.status_code == 403

    def test_store_manager_cannot_get_user_from_other_tenant(
        self,
        client: TestClient,
        store_manager_headers: dict,
        other_tenant_user: dict,
    ):
        """Cross-tenant user lookup must return 403."""
        response = client.get(
            f"/api/v1/users/{other_tenant_user['user'].id}",
            headers=store_manager_headers,
        )

        assert response.status_code == 403

    def test_get_nonexistent_user_returns_404(
        self, client: TestClient, store_manager_headers: dict
    ):
        """A UUID that doesn't match any user must return 404."""
        response = client.get(
            f"/api/v1/users/{uuid4()}",
            headers=store_manager_headers,
        )

        assert response.status_code == 404

    def test_get_user_unauthenticated_returns_401(
        self, client: TestClient, pharmacist_user: dict
    ):
        response = client.get(f"/api/v1/users/{pharmacist_user['user'].id}")

        assert response.status_code == 401


# ============================================================================
# UPDATE USER — PATCH /api/v1/users/{user_id}
# ============================================================================

@pytest.mark.users
class TestUpdateUser:
    """PATCH /api/v1/users/{user_id} — store manager+"""

    def test_store_manager_can_update_user_profile(
        self,
        client: TestClient,
        store_manager_headers: dict,
        pharmacist_user: dict,
    ):
        """STORE_MANAGER must be able to update name fields of a tenant user."""
        response = client.patch(
            f"/api/v1/users/{pharmacist_user['user'].id}",
            headers=store_manager_headers,
            json={"first_name": "Updated", "last_name": "Name"},
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["first_name"] == "Updated"
        assert data["last_name"] == "Name"

    def test_partial_update_only_changes_provided_fields(
        self,
        client: TestClient,
        store_manager_headers: dict,
        pharmacist_user: dict,
    ):
        """Fields not included in the request body must remain unchanged."""
        original_last_name = pharmacist_user["user"].last_name

        response = client.patch(
            f"/api/v1/users/{pharmacist_user['user'].id}",
            headers=store_manager_headers,
            json={"first_name": "OnlyFirstChanged"},
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["first_name"] == "OnlyFirstChanged"
        assert data["last_name"] == original_last_name

    def test_update_user_phone_number(
        self,
        client: TestClient,
        store_manager_headers: dict,
        pharmacist_user: dict,
    ):
        """Phone number update must be persisted."""
        response = client.patch(
            f"/api/v1/users/{pharmacist_user['user'].id}",
            headers=store_manager_headers,
            json={"phone": "+2349099999999"},
        )

        assert response.status_code == 200
        assert response.json()["data"]["phone"] == "+2349099999999"

    def test_update_user_middle_name(
        self,
        client: TestClient,
        store_manager_headers: dict,
        pharmacist_user: dict,
    ):
        """Middle name field update must be persisted."""
        response = client.patch(
            f"/api/v1/users/{pharmacist_user['user'].id}",
            headers=store_manager_headers,
            json={"middle_name": "Adebimpe"},
        )

        assert response.status_code == 200
        assert response.json()["data"]["middle_name"] == "Adebimpe"

    def test_plain_pharmacist_cannot_update_other_users(
        self,
        client: TestClient,
        pharmacist_headers: dict,
        store_manager_user: dict,
    ):
        """PHARMACIST must receive 403 when trying to update someone else."""
        response = client.patch(
            f"/api/v1/users/{store_manager_user['user'].id}",
            headers=pharmacist_headers,
            json={"first_name": "HackerName"},
        )

        assert response.status_code == 403

    def test_cannot_update_user_from_other_tenant(
        self,
        client: TestClient,
        store_manager_headers: dict,
        other_tenant_user: dict,
    ):
        """Cross-tenant update attempt must return 403."""
        response = client.patch(
            f"/api/v1/users/{other_tenant_user['user'].id}",
            headers=store_manager_headers,
            json={"first_name": "CrossTenantHack"},
        )

        assert response.status_code == 403

    def test_update_nonexistent_user_returns_404(
        self, client: TestClient, store_manager_headers: dict
    ):
        """Updating a UUID that doesn't exist must return 404."""
        response = client.patch(
            f"/api/v1/users/{uuid4()}",
            headers=store_manager_headers,
            json={"first_name": "Ghost"},
        )

        assert response.status_code == 404

    def test_update_user_unauthenticated_returns_401(
        self, client: TestClient, pharmacist_user: dict
    ):
        response = client.patch(
            f"/api/v1/users/{pharmacist_user['user'].id}",
            json={"first_name": "NoAuth"},
        )

        assert response.status_code == 401

    def test_first_name_exceeds_max_length_returns_422(
        self,
        client: TestClient,
        store_manager_headers: dict,
        pharmacist_user: dict,
    ):
        """first_name max_length=100; longer strings must fail validation."""
        response = client.patch(
            f"/api/v1/users/{pharmacist_user['user'].id}",
            headers=store_manager_headers,
            json={"first_name": "A" * 101},
        )

        assert response.status_code == 422


# ============================================================================
# DEACTIVATE USER — PATCH /api/v1/users/{user_id}/deactivate
# ============================================================================

@pytest.mark.users
class TestDeactivateUser:
    """PATCH /api/v1/users/{user_id}/deactivate — tenant admin+"""

    def test_tenant_admin_can_deactivate_user(
        self,
        client: TestClient,
        tenant_admin_headers: dict,
        pharmacist_user: dict,
        session: Session,
    ):
        """TENANT_ADMIN must be able to deactivate a user in their tenant."""
        response = client.patch(
            f"/api/v1/users/{pharmacist_user['user'].id}/deactivate",
            headers=tenant_admin_headers,
        )

        assert response.status_code == 200
        assert response.json()["success"] is True

        session.refresh(pharmacist_user["user"])
        assert pharmacist_user["user"].is_active is False

    def test_super_admin_can_deactivate_user(
        self,
        client: TestClient,
        super_admin_headers: dict,
        pharmacist_user: dict,
        session: Session,
    ):
        """SUPER_ADMIN must also be able to deactivate any user."""
        response = client.patch(
            f"/api/v1/users/{pharmacist_user['user'].id}/deactivate",
            headers=super_admin_headers,
        )

        assert response.status_code == 200

    def test_store_manager_cannot_deactivate_users(
        self,
        client: TestClient,
        store_manager_headers: dict,
        pharmacist_user: dict,
    ):
        """STORE_MANAGER is below TENANT_ADMIN and must receive 403."""
        response = client.patch(
            f"/api/v1/users/{pharmacist_user['user'].id}/deactivate",
            headers=store_manager_headers,
        )

        assert response.status_code == 403

    def test_plain_pharmacist_cannot_deactivate_users(
        self,
        client: TestClient,
        pharmacist_headers: dict,
        store_manager_user: dict,
    ):
        """PHARMACIST must receive 403."""
        response = client.patch(
            f"/api/v1/users/{store_manager_user['user'].id}/deactivate",
            headers=pharmacist_headers,
        )

        assert response.status_code == 403

    def test_cannot_deactivate_user_from_other_tenant(
        self,
        client: TestClient,
        tenant_admin_headers: dict,
        other_tenant_user: dict,
    ):
        """Cross-tenant deactivation must return 403."""
        response = client.patch(
            f"/api/v1/users/{other_tenant_user['user'].id}/deactivate",
            headers=tenant_admin_headers,
        )

        assert response.status_code == 403

    def test_deactivate_nonexistent_user_returns_404(
        self, client: TestClient, tenant_admin_headers: dict
    ):
        response = client.patch(
            f"/api/v1/users/{uuid4()}/deactivate",
            headers=tenant_admin_headers,
        )

        assert response.status_code == 404

    def test_deactivate_user_unauthenticated_returns_401(
        self, client: TestClient, pharmacist_user: dict
    ):
        response = client.patch(
            f"/api/v1/users/{pharmacist_user['user'].id}/deactivate"
        )

        assert response.status_code == 401


# ============================================================================
# LOCK USER — PATCH /api/v1/users/{user_id}/lock
# ============================================================================

@pytest.mark.users
class TestLockUser:
    """PATCH /api/v1/users/{user_id}/lock — tenant admin+"""

    def test_tenant_admin_can_lock_user(
        self,
        client: TestClient,
        tenant_admin_headers: dict,
        pharmacist_user: dict,
        session: Session,
    ):
        """TENANT_ADMIN must be able to lock a user account."""
        response = client.patch(
            f"/api/v1/users/{pharmacist_user['user'].id}/lock",
            headers=tenant_admin_headers,
        )

        assert response.status_code == 200
        assert response.json()["success"] is True

        session.refresh(pharmacist_user["user"])
        assert pharmacist_user["user"].is_locked is True

    def test_lock_user_clears_api_token(
        self,
        client: TestClient,
        tenant_admin_headers: dict,
        pharmacist_user: dict,
        pharmacist_token: str,
        session: Session,
    ):
        """Locking must clear the user's api_token to revoke any active session."""
        client.patch(
            f"/api/v1/users/{pharmacist_user['user'].id}/lock",
            headers=tenant_admin_headers,
        )

        session.refresh(pharmacist_user["user"])
        assert pharmacist_user["user"].api_token is None

    def test_store_manager_cannot_lock_users(
        self,
        client: TestClient,
        store_manager_headers: dict,
        pharmacist_user: dict,
    ):
        """STORE_MANAGER must receive 403."""
        response = client.patch(
            f"/api/v1/users/{pharmacist_user['user'].id}/lock",
            headers=store_manager_headers,
        )

        assert response.status_code == 403

    def test_cannot_lock_user_from_other_tenant(
        self,
        client: TestClient,
        tenant_admin_headers: dict,
        other_tenant_user: dict,
    ):
        """Cross-tenant lock attempt must return 403."""
        response = client.patch(
            f"/api/v1/users/{other_tenant_user['user'].id}/lock",
            headers=tenant_admin_headers,
        )

        assert response.status_code == 403

    def test_lock_nonexistent_user_returns_404(
        self, client: TestClient, tenant_admin_headers: dict
    ):
        response = client.patch(
            f"/api/v1/users/{uuid4()}/lock",
            headers=tenant_admin_headers,
        )

        assert response.status_code == 404

    def test_lock_user_unauthenticated_returns_401(
        self, client: TestClient, pharmacist_user: dict
    ):
        response = client.patch(f"/api/v1/users/{pharmacist_user['user'].id}/lock")

        assert response.status_code == 401


# ============================================================================
# UNLOCK USER — PATCH /api/v1/users/{user_id}/unlock
# ============================================================================

@pytest.mark.users
class TestUnlockUser:
    """PATCH /api/v1/users/{user_id}/unlock — tenant admin+"""

    def test_tenant_admin_can_unlock_user(
        self,
        client: TestClient,
        tenant_admin_headers: dict,
        locked_user: dict,
        session: Session,
    ):
        """TENANT_ADMIN must be able to unlock a locked account."""
        response = client.patch(
            f"/api/v1/users/{locked_user['user'].id}/unlock",
            headers=tenant_admin_headers,
        )

        assert response.status_code == 200
        assert response.json()["success"] is True

        session.refresh(locked_user["user"])
        assert locked_user["user"].is_locked is False

    def test_unlock_resets_failed_login_attempts(
        self,
        client: TestClient,
        tenant_admin_headers: dict,
        locked_user: dict,
        session: Session,
    ):
        """Unlocking must also zero out failed_login_attempts."""
        client.patch(
            f"/api/v1/users/{locked_user['user'].id}/unlock",
            headers=tenant_admin_headers,
        )

        session.refresh(locked_user["user"])
        assert locked_user["user"].failed_login_attempts == 0

    def test_super_admin_can_unlock_user(
        self,
        client: TestClient,
        super_admin_headers: dict,
        locked_user: dict,
        session: Session,
    ):
        """SUPER_ADMIN must also be able to unlock a user."""
        response = client.patch(
            f"/api/v1/users/{locked_user['user'].id}/unlock",
            headers=super_admin_headers,
        )

        assert response.status_code == 200

    def test_store_manager_cannot_unlock_users(
        self,
        client: TestClient,
        store_manager_headers: dict,
        locked_user: dict,
    ):
        """STORE_MANAGER must receive 403."""
        response = client.patch(
            f"/api/v1/users/{locked_user['user'].id}/unlock",
            headers=store_manager_headers,
        )

        assert response.status_code == 403

    def test_plain_pharmacist_cannot_unlock_users(
        self,
        client: TestClient,
        pharmacist_headers: dict,
        locked_user: dict,
    ):
        """PHARMACIST must receive 403."""
        response = client.patch(
            f"/api/v1/users/{locked_user['user'].id}/unlock",
            headers=pharmacist_headers,
        )

        assert response.status_code == 403

    def test_cannot_unlock_user_from_other_tenant(
        self,
        client: TestClient,
        tenant_admin_headers: dict,
        other_tenant_user: dict,
    ):
        """Cross-tenant unlock attempt must return 403."""
        response = client.patch(
            f"/api/v1/users/{other_tenant_user['user'].id}/unlock",
            headers=tenant_admin_headers,
        )

        assert response.status_code == 403

    def test_unlock_nonexistent_user_returns_404(
        self, client: TestClient, tenant_admin_headers: dict
    ):
        response = client.patch(
            f"/api/v1/users/{uuid4()}/unlock",
            headers=tenant_admin_headers,
        )

        assert response.status_code == 404

    def test_unlock_user_unauthenticated_returns_401(
        self, client: TestClient, locked_user: dict
    ):
        response = client.patch(f"/api/v1/users/{locked_user['user'].id}/unlock")

        assert response.status_code == 401


# ============================================================================
# TENANT ISOLATION — cross-cutting
# ============================================================================

@pytest.mark.tenant_isolation
class TestUserTenantIsolation:
    """
    Verifies that tenant boundaries are strictly enforced across every
    user-management endpoint.
    """

    def test_list_never_exposes_other_tenant_users(
        self,
        client: TestClient,
        store_manager_headers: dict,
        other_tenant_user: dict,
    ):
        """GET /users must not return users from a different tenant."""
        response = client.get("/api/v1/users", headers=store_manager_headers)

        returned_ids = {u["id"] for u in response.json()["data"]}
        assert str(other_tenant_user["user"].id) not in returned_ids

    def test_cannot_view_user_belonging_to_other_tenant(
        self,
        client: TestClient,
        store_manager_headers: dict,
        other_tenant_user: dict,
    ):
        """GET /users/{id} with a cross-tenant user must return 403."""
        response = client.get(
            f"/api/v1/users/{other_tenant_user['user'].id}",
            headers=store_manager_headers,
        )

        assert response.status_code == 403

    def test_cannot_update_user_belonging_to_other_tenant(
        self,
        client: TestClient,
        store_manager_headers: dict,
        other_tenant_user: dict,
    ):
        """PATCH /users/{id} with a cross-tenant user must return 403."""
        response = client.patch(
            f"/api/v1/users/{other_tenant_user['user'].id}",
            headers=store_manager_headers,
            json={"first_name": "CrossTenantAttack"},
        )

        assert response.status_code == 403

    def test_cannot_deactivate_user_belonging_to_other_tenant(
        self,
        client: TestClient,
        tenant_admin_headers: dict,
        other_tenant_user: dict,
    ):
        """PATCH /users/{id}/deactivate with cross-tenant user must return 403."""
        response = client.patch(
            f"/api/v1/users/{other_tenant_user['user'].id}/deactivate",
            headers=tenant_admin_headers,
        )

        assert response.status_code == 403

    def test_other_tenant_token_cannot_see_demo_tenant_users(
        self,
        client: TestClient,
        other_tenant_headers: dict,
        pharmacist_user: dict,
    ):
        """A token from tenant B must not be able to read tenant A users."""
        response = client.get(
            f"/api/v1/users/{pharmacist_user['user'].id}",
            headers=other_tenant_headers,
        )

        assert response.status_code == 403

    def test_other_tenant_list_does_not_include_demo_tenant_users(
        self,
        client: TestClient,
        other_tenant_headers: dict,
        pharmacist_user: dict,
    ):
        """User list for tenant B must not contain any tenant A user IDs."""
        response = client.get("/api/v1/users", headers=other_tenant_headers)

        returned_ids = {u["id"] for u in response.json()["data"]}
        assert str(pharmacist_user["user"].id) not in returned_ids


# ============================================================================
# RUN
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])