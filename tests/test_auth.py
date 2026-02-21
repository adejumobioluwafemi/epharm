"""
FILE: tests/test_auth.py
Comprehensive authentication tests for the E-Pharmacy multi-tenant API.
Follows the same class-per-endpoint, fixture-per-scenario pattern as the reference codebase.

Covers:
  POST   /api/v1/auth/login
  POST   /api/v1/auth/logout
  POST   /api/v1/auth/refresh
  POST   /api/v1/auth/register
  POST   /api/v1/auth/forgot-password
  GET    /api/v1/auth/validate-reset-token
  POST   /api/v1/auth/reset-password
  POST   /api/v1/auth/change-password
  GET    /api/v1/auth/me
  POST   /api/v1/auth/roles/assign
  DELETE /api/v1/auth/roles/revoke
"""

import hashlib
import pytest
from datetime import timedelta
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from src.core.security import create_refresh_token_jwt, generate_reset_token, generate_salt, hash_password
from src.shared.models import (
    PasswordResetToken,
    PharmacyStore,
    RefreshToken,
    Role,
    RoleName,
    StaffProfile,
    Tenant,
    User,
    UserRole,
    UserType,
    utcnow,
)


# ============================================================================
# MODULE-LEVEL FIXTURES  (local to this file, per the reference pattern)
# ============================================================================

@pytest.fixture(name="new_staff_payload")
def new_staff_payload_fixture(demo_store: PharmacyStore) -> dict:
    """A valid RegisterStaffRequest payload. Use store_id from demo_store."""
    return {
        "email": "newstaff@demopharmacy.com",
        "phone": "+2348099988800",
        "first_name": "New",
        "last_name": "Staff",
        "user_type": "STAFF",
        "store_id": str(demo_store.id),
        "role_name": RoleName.PHARMACIST,
        "license_number": "PCN-TEST-001",
    }


# ============================================================================
# LOGIN TESTS
# ============================================================================

@pytest.mark.auth
class TestLogin:
    """POST /api/v1/auth/login"""

    def test_login_with_email_success(self, client: TestClient, pharmacist_user: dict):
        """Successful login using email as the identifier."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "identifier": pharmacist_user["user"].email,
                "password": pharmacist_user["password"],
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Login successful"
        assert "token" in data["data"]
        assert "user" in data["data"]
        assert data["data"]["token"]["token_type"] == "bearer"
        assert data["data"]["token"]["expires_in"] > 0
        assert data["data"]["user"]["email"] == pharmacist_user["user"].email

    def test_login_with_phone_success(self, client: TestClient, pharmacist_user: dict):
        """Successful login using phone number as the identifier."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "identifier": pharmacist_user["user"].phone,
                "password": pharmacist_user["password"],
            },
        )

        assert response.status_code == 200
        assert response.json()["success"] is True

    def test_login_response_contains_tenant_and_role_context(
        self, client: TestClient, pharmacist_user: dict
    ):
        """JWT context — tenant_id, store_ids, roles — must appear in the user payload."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "identifier": pharmacist_user["user"].email,
                "password": pharmacist_user["password"],
            },
        )

        user_data = response.json()["data"]["user"]
        assert "tenant_id" in user_data
        assert "store_ids" in user_data
        assert "roles" in user_data
        assert RoleName.PHARMACIST in user_data["roles"]

    def test_login_response_contains_both_tokens(
        self, client: TestClient, pharmacist_user: dict
    ):
        """Response must include both access_token and refresh_token."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "identifier": pharmacist_user["user"].email,
                "password": pharmacist_user["password"],
            },
        )

        token_data = response.json()["data"]["token"]
        assert "access_token" in token_data
        assert "refresh_token" in token_data
        assert len(token_data["access_token"]) > 10
        assert len(token_data["refresh_token"]) > 10

    def test_login_persists_api_token_in_database(
        self, client: TestClient, pharmacist_user: dict, session: Session
    ):
        """The access token returned must be stored in users.api_token."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "identifier": pharmacist_user["user"].email,
                "password": pharmacist_user["password"],
            },
        )

        access_token = response.json()["data"]["token"]["access_token"]
        session.refresh(pharmacist_user["user"])
        assert pharmacist_user["user"].api_token == access_token

    def test_login_increments_login_count(
        self, client: TestClient, pharmacist_user: dict, session: Session
    ):
        """login_count must be incremented by exactly 1 on success."""
        initial_count = pharmacist_user["user"].login_count

        client.post(
            "/api/v1/auth/login",
            json={
                "identifier": pharmacist_user["user"].email,
                "password": pharmacist_user["password"],
            },
        )

        session.refresh(pharmacist_user["user"])
        assert pharmacist_user["user"].login_count == initial_count + 1

    def test_login_resets_failed_attempts_on_success(
        self, client: TestClient, pharmacist_user: dict, session: Session
    ):
        """Successful login must zero out any previous failed_login_attempts."""
        pharmacist_user["user"].failed_login_attempts = 3
        session.add(pharmacist_user["user"])
        session.commit()

        client.post(
            "/api/v1/auth/login",
            json={
                "identifier": pharmacist_user["user"].email,
                "password": pharmacist_user["password"],
            },
        )

        session.refresh(pharmacist_user["user"])
        assert pharmacist_user["user"].failed_login_attempts == 0

    def test_login_invalid_password_returns_401(
        self, client: TestClient, pharmacist_user: dict
    ):
        """Wrong password must return 401 with an informative error."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "identifier": pharmacist_user["user"].email,
                "password": "WrongPassword!",
            },
        )

        assert response.status_code == 401
        assert "Invalid credentials" in response.json()["detail"]

    def test_login_nonexistent_email_returns_401(self, client: TestClient):
        """Login with an email that does not exist must return 401."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "identifier": "nobody@doesnotexist.com",
                "password": "Password123!",
            },
        )

        assert response.status_code == 401

    def test_login_increments_failed_attempts_on_wrong_password(
        self, client: TestClient, pharmacist_user: dict, session: Session
    ):
        """Each wrong-password attempt must increment failed_login_attempts."""
        client.post(
            "/api/v1/auth/login",
            json={
                "identifier": pharmacist_user["user"].email,
                "password": "WrongPassword!",
            },
        )

        session.refresh(pharmacist_user["user"])
        assert pharmacist_user["user"].failed_login_attempts == 1

    def test_login_locks_account_after_five_failed_attempts(
        self, client: TestClient, pharmacist_user: dict, session: Session
    ):
        """Account must be locked after exactly 5 consecutive failed attempts."""
        for _ in range(5):
            client.post(
                "/api/v1/auth/login",
                json={
                    "identifier": pharmacist_user["user"].email,
                    "password": "BadPassword!",
                },
            )

        response = client.post(
            "/api/v1/auth/login",
            json={
                "identifier": pharmacist_user["user"].email,
                "password": "BadPassword!",
            },
        )

        assert response.status_code == 403
        assert "locked" in response.json()["detail"].lower()

        session.refresh(pharmacist_user["user"])
        assert pharmacist_user["user"].is_locked is True

    def test_login_locked_account_returns_403(
        self, client: TestClient, locked_user: dict
    ):
        """Logging into a pre-locked account must return 403."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "identifier": locked_user["user"].email,
                "password": locked_user["password"],
            },
        )

        assert response.status_code == 403
        assert "locked" in response.json()["detail"].lower()

    def test_login_inactive_account_returns_403(
        self, client: TestClient, inactive_user: dict
    ):
        """Logging into a deactivated account must return 403."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "identifier": inactive_user["user"].email,
                "password": inactive_user["password"],
            },
        )

        assert response.status_code == 403
        assert "deactivated" in response.json()["detail"].lower()

    def test_login_missing_identifier_returns_422(self, client: TestClient):
        """Request body without 'identifier' must fail validation."""
        response = client.post(
            "/api/v1/auth/login",
            json={"password": "Password123!"},
        )

        assert response.status_code == 422

    def test_login_missing_password_returns_422(self, client: TestClient):
        """Request body without 'password' must fail validation."""
        response = client.post(
            "/api/v1/auth/login",
            json={"identifier": "someone@test.com"},
        )

        assert response.status_code == 422

    def test_login_password_too_short_returns_422(self, client: TestClient):
        """Password field has min_length=6; shorter values must be rejected."""
        response = client.post(
            "/api/v1/auth/login",
            json={"identifier": "x@x.com", "password": "abc"},
        )

        assert response.status_code == 422


# ============================================================================
# LOGOUT TESTS
# ============================================================================

@pytest.mark.auth
class TestLogout:
    """POST /api/v1/auth/logout"""

    def test_logout_success(
        self,
        client: TestClient,
        pharmacist_headers: dict,
        pharmacist_user: dict,
        session: Session,
    ):
        """Successful logout clears api_token from the database."""
        response = client.post("/api/v1/auth/logout", headers=pharmacist_headers)

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "Logged out" in data["message"]

        session.refresh(pharmacist_user["user"])
        assert pharmacist_user["user"].api_token is None

    def test_logout_revokes_all_refresh_tokens(
        self,
        client: TestClient,
        pharmacist_headers: dict,
        pharmacist_user: dict,
        session: Session,
    ):
        """All active RefreshToken rows for the user must be revoked on logout."""
        raw_jwt = create_refresh_token_jwt(user_id=pharmacist_user["user"].id)
        token_hash = hashlib.sha256(raw_jwt.encode()).hexdigest()
        rt = RefreshToken(
            user_id=pharmacist_user["user"].id,
            token_hash=token_hash,
            expires_at=utcnow() + timedelta(days=7),
        )
        session.add(rt)
        session.commit()

        client.post("/api/v1/auth/logout", headers=pharmacist_headers)

        session.refresh(rt)
        assert rt.is_revoked is True

    def test_logout_without_token_returns_401(self, client: TestClient):
        """Request with no Authorization header must return 401."""
        response = client.post("/api/v1/auth/logout")

        assert response.status_code == 401
        assert "Not authenticated" in response.json()["detail"]

    def test_logout_with_invalid_token_returns_401(self, client: TestClient):
        """Malformed / garbage JWT must return 401."""
        response = client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": "Bearer totally.invalid.token"},
        )

        assert response.status_code == 401

    def test_reusing_token_after_logout_returns_401(
        self,
        client: TestClient,
        pharmacist_headers: dict,
    ):
        """The same token must be rejected on any subsequent request after logout."""
        client.post("/api/v1/auth/logout", headers=pharmacist_headers)

        response = client.post("/api/v1/auth/logout", headers=pharmacist_headers)
        assert response.status_code == 401


# ============================================================================
# REFRESH TOKEN TESTS
# ============================================================================

@pytest.mark.auth
class TestRefreshTokens:
    """POST /api/v1/auth/refresh"""

    def test_refresh_returns_new_token_pair(
        self,
        client: TestClient,
        pharmacist_user: dict,
        valid_refresh_token,
        session: Session,
    ):
        """Valid refresh token must return a fresh access + refresh token pair."""
        raw_jwt, _ = valid_refresh_token
        # Ensure user has an api_token set (mimic post-login state)
        pharmacist_user["user"].api_token = "some_old_token"
        session.add(pharmacist_user["user"])
        session.commit()

        response = client.post("/api/v1/auth/refresh", json={"refresh_token": raw_jwt})

        assert response.status_code == 200
        data = response.json()["data"]
        assert "access_token" in data
        assert "refresh_token" in data

    def test_refresh_issues_new_access_token_different_from_old(
        self,
        client: TestClient,
        pharmacist_user: dict,
        valid_refresh_token,
        session: Session,
    ):
        """The new access token must differ from the previous one."""
        raw_jwt, _ = valid_refresh_token
        old_token = "old_access_token_value"
        pharmacist_user["user"].api_token = old_token
        session.add(pharmacist_user["user"])
        session.commit()

        response = client.post("/api/v1/auth/refresh", json={"refresh_token": raw_jwt})

        new_access = response.json()["data"]["access_token"]
        assert new_access != old_token

    def test_refresh_rotates_old_refresh_token(
        self,
        client: TestClient,
        pharmacist_user: dict,
        valid_refresh_token,
        session: Session,
    ):
        """The consumed refresh token must be marked revoked after rotation."""
        raw_jwt, record = valid_refresh_token
        pharmacist_user["user"].api_token = "any_token"
        session.add(pharmacist_user["user"])
        session.commit()

        client.post("/api/v1/auth/refresh", json={"refresh_token": raw_jwt})

        session.refresh(record)
        assert record.is_revoked is True

    def test_refresh_with_invalid_jwt_returns_401(self, client: TestClient):
        """Garbage string must return 401."""
        response = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "not.a.real.jwt"},
        )

        assert response.status_code == 401

    def test_refresh_with_revoked_token_returns_401(
        self,
        client: TestClient,
        pharmacist_user: dict,
        valid_refresh_token,
        session: Session,
    ):
        """A previously revoked refresh token must be rejected."""
        raw_jwt, record = valid_refresh_token
        record.is_revoked = True
        session.add(record)
        session.commit()

        response = client.post("/api/v1/auth/refresh", json={"refresh_token": raw_jwt})

        assert response.status_code == 401

    def test_refresh_missing_field_returns_422(self, client: TestClient):
        """Empty body must fail schema validation."""
        response = client.post("/api/v1/auth/refresh", json={})

        assert response.status_code == 422


# ============================================================================
# STAFF REGISTRATION TESTS
# ============================================================================

@pytest.mark.auth
class TestRegisterStaff:
    """POST /api/v1/auth/register"""

    def test_store_manager_can_register_new_staff(
        self,
        client: TestClient,
        store_manager_headers: dict,
        new_staff_payload: dict,
        role_pharmacist: Role,
        mock_email_settings,
    ):
        """A STORE_MANAGER must be able to register a new staff member."""
        response = client.post(
            "/api/v1/auth/register",
            headers=store_manager_headers,
            json=new_staff_payload,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["data"]["email"] == new_staff_payload["email"]
        assert "user_id" in data["data"]

    def test_tenant_admin_can_register_new_staff(
        self,
        client: TestClient,
        tenant_admin_headers: dict,
        new_staff_payload: dict,
        role_pharmacist: Role,
        mock_email_settings,
    ):
        """A TENANT_ADMIN must also be able to register staff."""
        new_staff_payload["email"] = "newstaff2@demopharmacy.com"
        response = client.post(
            "/api/v1/auth/register",
            headers=tenant_admin_headers,
            json=new_staff_payload,
        )

        assert response.status_code == 200
        assert response.json()["success"] is True

    def test_super_admin_can_register_staff(
        self,
        client: TestClient,
        super_admin_headers: dict,
        new_staff_payload: dict,
        role_pharmacist: Role,
        mock_email_settings,
    ):
        """SUPER_ADMIN must be able to register staff in any tenant."""
        new_staff_payload["email"] = "newstaff3@demopharmacy.com"
        response = client.post(
            "/api/v1/auth/register",
            headers=super_admin_headers,
            json=new_staff_payload,
        )

        assert response.status_code == 200

    def test_plain_pharmacist_cannot_register_staff(
        self,
        client: TestClient,
        pharmacist_headers: dict,
        new_staff_payload: dict,
        mock_email_settings,
    ):
        """PHARMACIST role is below STORE_MANAGER and must receive 403."""
        response = client.post(
            "/api/v1/auth/register",
            headers=pharmacist_headers,
            json=new_staff_payload,
        )

        assert response.status_code == 403

    def test_unauthenticated_register_returns_401(
        self,
        client: TestClient,
        new_staff_payload: dict,
    ):
        """Request without a token must be rejected with 401."""
        response = client.post("/api/v1/auth/register", json=new_staff_payload)

        assert response.status_code == 401

    def test_register_duplicate_email_returns_400(
        self,
        client: TestClient,
        store_manager_headers: dict,
        pharmacist_user: dict,
        demo_store: PharmacyStore,
        role_pharmacist: Role,
        mock_email_settings,
    ):
        """Registering with an already-used email must return 400."""
        payload = {
            "email": pharmacist_user["user"].email,  # already exists
            "phone": "+2348099988801",
            "first_name": "Dup",
            "last_name": "Email",
            "user_type": "STAFF",
            "store_id": str(demo_store.id),
            "role_name": RoleName.PHARMACIST,
        }
        response = client.post(
            "/api/v1/auth/register",
            headers=store_manager_headers,
            json=payload,
        )

        assert response.status_code == 400
        assert "already registered" in response.json()["detail"]

    def test_register_duplicate_phone_returns_400(
        self,
        client: TestClient,
        store_manager_headers: dict,
        pharmacist_user: dict,
        demo_store: PharmacyStore,
        role_pharmacist: Role,
        mock_email_settings,
    ):
        """Registering with an already-used phone number must return 400."""
        payload = {
            "email": "uniqueemail@demopharmacy.com",
            "phone": pharmacist_user["user"].phone,  # already exists
            "first_name": "Dup",
            "last_name": "Phone",
            "user_type": "STAFF",
            "store_id": str(demo_store.id),
            "role_name": RoleName.PHARMACIST,
        }
        response = client.post(
            "/api/v1/auth/register",
            headers=store_manager_headers,
            json=payload,
        )

        assert response.status_code == 400
        assert "already registered" in response.json()["detail"]

    def test_register_with_nonexistent_store_returns_404(
        self,
        client: TestClient,
        store_manager_headers: dict,
        new_staff_payload: dict,
        mock_email_settings,
    ):
        """Providing a store_id that does not exist must return 404."""
        new_staff_payload["store_id"] = str(uuid4())
        response = client.post(
            "/api/v1/auth/register",
            headers=store_manager_headers,
            json=new_staff_payload,
        )

        assert response.status_code == 404

    def test_register_with_store_from_other_tenant_returns_404(
        self,
        client: TestClient,
        store_manager_headers: dict,
        new_staff_payload: dict,
        other_tenant_store: PharmacyStore,
        mock_email_settings,
    ):
        """A store belonging to a different tenant must not be accessible."""
        new_staff_payload["store_id"] = str(other_tenant_store.id)
        response = client.post(
            "/api/v1/auth/register",
            headers=store_manager_headers,
            json=new_staff_payload,
        )

        assert response.status_code == 404

    def test_register_with_invalid_role_returns_404(
        self,
        client: TestClient,
        store_manager_headers: dict,
        new_staff_payload: dict,
        mock_email_settings,
    ):
        """An unknown role_name string must return 404."""
        new_staff_payload["role_name"] = "MADE_UP_ROLE"
        response = client.post(
            "/api/v1/auth/register",
            headers=store_manager_headers,
            json=new_staff_payload,
        )

        assert response.status_code == 404

    def test_register_creates_staff_profile_record(
        self,
        client: TestClient,
        store_manager_headers: dict,
        new_staff_payload: dict,
        role_pharmacist: Role,
        session: Session,
        mock_email_settings,
    ):
        """A StaffProfile row must exist after successful registration."""
        from uuid import UUID

        response = client.post(
            "/api/v1/auth/register",
            headers=store_manager_headers,
            json=new_staff_payload,
        )

        assert response.status_code == 200
        user_id = UUID(response.json()["data"]["user_id"])
        profile = session.exec(
            select(StaffProfile).where(StaffProfile.user_id == user_id)
        ).first()
        assert profile is not None

    def test_register_in_development_mode_returns_temp_password(
        self,
        client: TestClient,
        store_manager_headers: dict,
        new_staff_payload: dict,
        role_pharmacist: Role,
        mock_email_settings,
    ):
        """ENVIRONMENT=development → temp_password appears in the response body."""
        response = client.post(
            "/api/v1/auth/register",
            headers=store_manager_headers,
            json=new_staff_payload,
        )

        assert response.status_code == 200
        # Default ENVIRONMENT is "development" when running tests
        assert "temp_password" in response.json()["data"]

    def test_register_new_user_can_login_with_temp_password(
        self,
        client: TestClient,
        store_manager_headers: dict,
        new_staff_payload: dict,
        role_pharmacist: Role,
        mock_email_settings,
    ):
        """The temp_password returned in dev mode must work for login."""
        register_response = client.post(
            "/api/v1/auth/register",
            headers=store_manager_headers,
            json=new_staff_payload,
        )
        assert register_response.status_code == 200
        temp_password = register_response.json()["data"]["temp_password"]

        login_response = client.post(
            "/api/v1/auth/login",
            json={
                "identifier": new_staff_payload["email"],
                "password": temp_password,
            },
        )

        assert login_response.status_code == 200


# ============================================================================
# FORGOT PASSWORD TESTS
# ============================================================================

@pytest.mark.auth
class TestForgotPassword:
    """POST /api/v1/auth/forgot-password"""

    def test_forgot_password_creates_reset_token_in_database(
        self,
        client: TestClient,
        pharmacist_user: dict,
        session: Session,
        mock_email_settings,
    ):
        """A valid email must cause a PasswordResetToken row to be created."""
        response = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": pharmacist_user["user"].email},
        )

        assert response.status_code == 200
        assert response.json()["success"] is True

        record = session.exec(
            select(PasswordResetToken).where(
                PasswordResetToken.user_id == pharmacist_user["user"].id,
                PasswordResetToken.is_used == False,
            )
        ).first()
        assert record is not None
        assert record.expires_at > utcnow()

    def test_forgot_password_nonexistent_email_still_returns_200(
        self, client: TestClient, mock_email_settings
    ):
        """Non-existent emails must still return 200 — no user enumeration."""
        response = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "nobody@doesnotexist.com"},
        )

        assert response.status_code == 200
        assert response.json()["success"] is True

    def test_forgot_password_inactive_user_does_not_create_token(
        self,
        client: TestClient,
        inactive_user: dict,
        session: Session,
        mock_email_settings,
    ):
        """Inactive users should not receive a reset token."""
        client.post(
            "/api/v1/auth/forgot-password",
            json={"email": inactive_user["user"].email},
        )

        record = session.exec(
            select(PasswordResetToken).where(
                PasswordResetToken.user_id == inactive_user["user"].id
            )
        ).first()
        assert record is None

    def test_second_forgot_password_request_invalidates_first_token(
        self,
        client: TestClient,
        pharmacist_user: dict,
        session: Session,
        mock_email_settings,
    ):
        """A second reset request must mark the first token as used."""
        client.post(
            "/api/v1/auth/forgot-password",
            json={"email": pharmacist_user["user"].email},
        )
        first_token = session.exec(
            select(PasswordResetToken).where(
                PasswordResetToken.user_id == pharmacist_user["user"].id,
                PasswordResetToken.is_used == False,
            )
        ).first()
        assert first_token is not None

        session.expire_all()
        client.post(
            "/api/v1/auth/forgot-password",
            json={"email": pharmacist_user["user"].email},
        )

        session.refresh(first_token)
        assert first_token.is_used is True

    def test_forgot_password_development_mode_returns_token_in_response(
        self,
        client: TestClient,
        pharmacist_user: dict,
        mock_email_settings,
    ):
        """In development mode the reset_token must appear in the response data."""
        response = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": pharmacist_user["user"].email},
        )

        assert response.json()["data"] is not None
        assert "reset_token" in response.json()["data"]

    def test_forgot_password_invalid_email_format_returns_422(self, client: TestClient):
        """A non-email string must fail schema validation."""
        response = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "not-an-email-address"},
        )

        assert response.status_code == 422


# ============================================================================
# VALIDATE RESET TOKEN TESTS
# ============================================================================

@pytest.mark.auth
class TestValidateResetToken:
    """GET /api/v1/auth/validate-reset-token"""

    def test_valid_token_returns_success_true(
        self, client: TestClient, valid_reset_token
    ):
        """A fresh, unused token must return success=True and valid=True."""
        raw_token, _ = valid_reset_token

        response = client.get(
            "/api/v1/auth/validate-reset-token",
            params={"token": raw_token},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["data"]["valid"] is True

    def test_expired_token_returns_success_false(
        self, client: TestClient, expired_reset_token
    ):
        """An expired token must return success=False and valid=False."""
        raw_token, _ = expired_reset_token

        response = client.get(
            "/api/v1/auth/validate-reset-token",
            params={"token": raw_token},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert data["data"]["valid"] is False

    def test_used_token_returns_success_false(
        self, client: TestClient, used_reset_token
    ):
        """An already-used token must return success=False."""
        raw_token, _ = used_reset_token

        response = client.get(
            "/api/v1/auth/validate-reset-token",
            params={"token": raw_token},
        )

        assert response.status_code == 200
        assert response.json()["data"]["valid"] is False

    def test_random_garbage_token_returns_false(self, client: TestClient):
        """A completely unknown token string must return valid=False."""
        response = client.get(
            "/api/v1/auth/validate-reset-token",
            params={"token": "garbage_random_token_that_does_not_exist"},
        )

        assert response.status_code == 200
        assert response.json()["data"]["valid"] is False


# ============================================================================
# RESET PASSWORD TESTS
# ============================================================================

@pytest.mark.auth
class TestResetPassword:
    """POST /api/v1/auth/reset-password"""

    def test_reset_password_success(
        self,
        client: TestClient,
        pharmacist_user: dict,
        valid_reset_token,
        session: Session,
        mock_email_settings,
    ):
        """Valid token + matching passwords must return success and mark token used."""
        raw_token, record = valid_reset_token
        new_password = "SuperNewPassword!8"

        response = client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": raw_token,
                "new_password": new_password,
                "confirm_password": new_password,
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "reset successfully" in data["message"]

        session.refresh(record)
        assert record.is_used is True
        assert record.used_at is not None

    def test_reset_password_unlocks_locked_account(
        self,
        client: TestClient,
        locked_user: dict,
        session: Session,
        mock_email_settings,
    ):
        """Password reset must set is_locked=False and zero failed_login_attempts."""
        raw_token = generate_reset_token()
        prt = PasswordResetToken(
            user_id=locked_user["user"].id,
            token=raw_token,
            expires_at=utcnow() + timedelta(hours=24),
            is_used=False,
        )
        session.add(prt)
        session.commit()

        new_password = "UnlockMyAccount!8"
        response = client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": raw_token,
                "new_password": new_password,
                "confirm_password": new_password,
            },
        )

        assert response.status_code == 200
        session.refresh(locked_user["user"])
        assert locked_user["user"].is_locked is False
        assert locked_user["user"].failed_login_attempts == 0

    def test_reset_password_clears_api_token(
        self,
        client: TestClient,
        pharmacist_user: dict,
        pharmacist_token: str,
        valid_reset_token,
        session: Session,
        mock_email_settings,
    ):
        """After reset the user is forced to re-login — api_token must be None."""
        raw_token, _ = valid_reset_token

        client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": raw_token,
                "new_password": "FreshPassword!8",
                "confirm_password": "FreshPassword!8",
            },
        )

        session.refresh(pharmacist_user["user"])
        assert pharmacist_user["user"].api_token is None

    def test_reset_password_allows_login_with_new_password(
        self,
        client: TestClient,
        pharmacist_user: dict,
        valid_reset_token,
        mock_email_settings,
    ):
        """After reset the user must be able to log in using the new password."""
        raw_token, _ = valid_reset_token
        new_password = "FreshLogin!8"

        client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": raw_token,
                "new_password": new_password,
                "confirm_password": new_password,
            },
        )

        login_response = client.post(
            "/api/v1/auth/login",
            json={
                "identifier": pharmacist_user["user"].email,
                "password": new_password,
            },
        )

        assert login_response.status_code == 200

    def test_reset_with_expired_token_returns_400(
        self, client: TestClient, expired_reset_token, mock_email_settings
    ):
        """Expired token must return 400 with an informative message."""
        raw_token, _ = expired_reset_token

        response = client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": raw_token,
                "new_password": "NewPassword!8",
                "confirm_password": "NewPassword!8",
            },
        )

        assert response.status_code == 400
        assert "Invalid or expired" in response.json()["detail"]

    def test_reset_with_used_token_returns_400(
        self, client: TestClient, used_reset_token, mock_email_settings
    ):
        """An already-used token must return 400."""
        raw_token, _ = used_reset_token

        response = client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": raw_token,
                "new_password": "NewPassword!8",
                "confirm_password": "NewPassword!8",
            },
        )

        assert response.status_code == 400

    def test_reset_password_mismatch_returns_422(
        self, client: TestClient, valid_reset_token
    ):
        """Mismatched new_password / confirm_password must fail schema validation."""
        raw_token, _ = valid_reset_token

        response = client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": raw_token,
                "new_password": "NewPassword!8",
                "confirm_password": "DifferentPassword!8",
            },
        )

        assert response.status_code == 422

    def test_reset_password_too_short_returns_422(
        self, client: TestClient, valid_reset_token
    ):
        """new_password min_length=8; shorter values must be rejected."""
        raw_token, _ = valid_reset_token

        response = client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": raw_token,
                "new_password": "short",
                "confirm_password": "short",
            },
        )

        assert response.status_code == 422


# ============================================================================
# CHANGE PASSWORD TESTS
# ============================================================================

@pytest.mark.auth
class TestChangePassword:
    """POST /api/v1/auth/change-password"""

    def test_change_password_success(
        self,
        client: TestClient,
        pharmacist_headers: dict,
        pharmacist_user: dict,
        mock_email_settings,
    ):
        """Authenticated user with correct current_password must succeed."""
        response = client.post(
            "/api/v1/auth/change-password",
            headers=pharmacist_headers,
            json={
                "current_password": pharmacist_user["password"],
                "new_password": "ChangedPassword!8",
                "confirm_password": "ChangedPassword!8",
            },
        )

        assert response.status_code == 200
        assert response.json()["success"] is True

    def test_change_password_wrong_current_returns_401(
        self,
        client: TestClient,
        pharmacist_headers: dict,
        mock_email_settings,
    ):
        """Providing the wrong current_password must return 401."""
        response = client.post(
            "/api/v1/auth/change-password",
            headers=pharmacist_headers,
            json={
                "current_password": "WrongCurrentPassword!",
                "new_password": "ChangedPassword!8",
                "confirm_password": "ChangedPassword!8",
            },
        )

        assert response.status_code == 401

    def test_change_password_mismatch_returns_422(
        self,
        client: TestClient,
        pharmacist_headers: dict,
        pharmacist_user: dict,
    ):
        """confirm_password ≠ new_password must fail schema validation."""
        response = client.post(
            "/api/v1/auth/change-password",
            headers=pharmacist_headers,
            json={
                "current_password": pharmacist_user["password"],
                "new_password": "ChangedPassword!8",
                "confirm_password": "DifferentPassword!8",
            },
        )

        assert response.status_code == 422

    def test_change_password_clears_api_token(
        self,
        client: TestClient,
        pharmacist_headers: dict,
        pharmacist_user: dict,
        session: Session,
        mock_email_settings,
    ):
        """After a successful change the api_token must be cleared (force re-login)."""
        client.post(
            "/api/v1/auth/change-password",
            headers=pharmacist_headers,
            json={
                "current_password": pharmacist_user["password"],
                "new_password": "ChangedPassword!8",
                "confirm_password": "ChangedPassword!8",
            },
        )

        session.refresh(pharmacist_user["user"])
        assert pharmacist_user["user"].api_token is None

    def test_change_password_unauthenticated_returns_401(self, client: TestClient):
        """Request without token must return 401."""
        response = client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "old",
                "new_password": "NewPass!8",
                "confirm_password": "NewPass!8",
            },
        )

        assert response.status_code == 401

    def test_change_password_new_password_too_short_returns_422(
        self,
        client: TestClient,
        pharmacist_headers: dict,
        pharmacist_user: dict,
    ):
        """new_password min_length=8; shorter values must fail validation."""
        response = client.post(
            "/api/v1/auth/change-password",
            headers=pharmacist_headers,
            json={
                "current_password": pharmacist_user["password"],
                "new_password": "short",
                "confirm_password": "short",
            },
        )

        assert response.status_code == 422


# ============================================================================
# GET /me TESTS
# ============================================================================

@pytest.mark.auth
class TestGetMe:
    """GET /api/v1/auth/me"""

    def test_me_returns_authenticated_user_info(
        self,
        client: TestClient,
        pharmacist_headers: dict,
        pharmacist_user: dict,
    ):
        """Response must contain the current user's email, roles, and tenant context."""
        response = client.get("/api/v1/auth/me", headers=pharmacist_headers)

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["email"] == pharmacist_user["user"].email
        assert "roles" in data
        assert "store_ids" in data
        assert "tenant_id" in data

    def test_me_reflects_correct_role_for_pharmacist(
        self, client: TestClient, pharmacist_headers: dict
    ):
        """The roles list must include PHARMACIST for the pharmacist user."""
        response = client.get("/api/v1/auth/me", headers=pharmacist_headers)

        roles = response.json()["data"]["roles"]
        assert RoleName.PHARMACIST in roles

    def test_me_reflects_correct_role_for_tenant_admin(
        self,
        client: TestClient,
        tenant_admin_headers: dict,
        demo_tenant: Tenant,
    ):
        """TENANT_ADMIN user's /me must show the correct tenant_id and role."""
        response = client.get("/api/v1/auth/me", headers=tenant_admin_headers)

        data = response.json()["data"]
        assert data["tenant_id"] == str(demo_tenant.id)
        assert RoleName.TENANT_ADMIN in data["roles"]

    def test_me_unauthenticated_returns_401(self, client: TestClient):
        """Request without token must return 401."""
        response = client.get("/api/v1/auth/me")

        assert response.status_code == 401


# ============================================================================
# ROLE ASSIGNMENT TESTS
# ============================================================================

@pytest.mark.rbac
class TestAssignRole:
    """POST /api/v1/auth/roles/assign"""

    def test_tenant_admin_can_assign_store_scoped_role(
        self,
        client: TestClient,
        tenant_admin_headers: dict,
        pharmacist_user: dict,
        demo_store: PharmacyStore,
        role_cashier: Role,
    ):
        """TENANT_ADMIN must be able to assign a store-scoped role."""
        response = client.post(
            "/api/v1/auth/roles/assign",
            headers=tenant_admin_headers,
            json={
                "user_id": str(pharmacist_user["user"].id),
                "role_name": RoleName.CASHIER,
                "store_id": str(demo_store.id),
            },
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["user_id"] == str(pharmacist_user["user"].id)
        assert data["store_id"] == str(demo_store.id)

    def test_tenant_admin_can_assign_tenant_wide_role(
        self,
        client: TestClient,
        tenant_admin_headers: dict,
        pharmacist_user: dict,
        role_cashier: Role,
    ):
        """Assigning without store_id must create a tenant-wide role (store_id=None)."""
        response = client.post(
            "/api/v1/auth/roles/assign",
            headers=tenant_admin_headers,
            json={
                "user_id": str(pharmacist_user["user"].id),
                "role_name": RoleName.CASHIER,
            },
        )

        assert response.status_code == 200
        assert response.json()["data"]["store_id"] is None

    def test_super_admin_can_assign_roles(
        self,
        client: TestClient,
        super_admin_headers: dict,
        pharmacist_user: dict,
        demo_store: PharmacyStore,
        role_cashier: Role,
    ):
        """SUPER_ADMIN must also have role-assignment permission."""
        response = client.post(
            "/api/v1/auth/roles/assign",
            headers=super_admin_headers,
            json={
                "user_id": str(pharmacist_user["user"].id),
                "role_name": RoleName.CASHIER,
                "store_id": str(demo_store.id),
            },
        )

        assert response.status_code == 200

    def test_store_manager_cannot_assign_roles(
        self,
        client: TestClient,
        store_manager_headers: dict,
        pharmacist_user: dict,
        role_cashier: Role,
    ):
        """STORE_MANAGER is below TENANT_ADMIN — must receive 403."""
        response = client.post(
            "/api/v1/auth/roles/assign",
            headers=store_manager_headers,
            json={
                "user_id": str(pharmacist_user["user"].id),
                "role_name": RoleName.CASHIER,
            },
        )

        assert response.status_code == 403

    def test_assign_role_to_nonexistent_user_returns_404(
        self,
        client: TestClient,
        tenant_admin_headers: dict,
        role_cashier: Role,
    ):
        """Assigning a role to a UUID that doesn't correspond to any user must 404."""
        response = client.post(
            "/api/v1/auth/roles/assign",
            headers=tenant_admin_headers,
            json={
                "user_id": str(uuid4()),
                "role_name": RoleName.CASHIER,
            },
        )

        assert response.status_code == 404

    def test_assign_nonexistent_role_returns_404(
        self,
        client: TestClient,
        tenant_admin_headers: dict,
        pharmacist_user: dict,
    ):
        """A role_name that hasn't been seeded must return 404."""
        response = client.post(
            "/api/v1/auth/roles/assign",
            headers=tenant_admin_headers,
            json={
                "user_id": str(pharmacist_user["user"].id),
                "role_name": "COMPLETELY_FAKE_ROLE",
            },
        )

        assert response.status_code == 404

    def test_assign_role_unauthenticated_returns_401(
        self,
        client: TestClient,
        pharmacist_user: dict,
    ):
        response = client.post(
            "/api/v1/auth/roles/assign",
            json={
                "user_id": str(pharmacist_user["user"].id),
                "role_name": RoleName.CASHIER,
            },
        )

        assert response.status_code == 401


# ============================================================================
# ROLE REVOCATION TESTS
# ============================================================================

@pytest.mark.rbac
class TestRevokeRole:
    """DELETE /api/v1/auth/roles/revoke"""

    def test_tenant_admin_can_revoke_role(
        self,
        client: TestClient,
        tenant_admin_headers: dict,
        pharmacist_user: dict,
        demo_store: PharmacyStore,
        demo_tenant: Tenant,
        role_cashier: Role,
        session: Session,
    ):
        """TENANT_ADMIN must be able to revoke an existing role assignment."""
        ur = UserRole(
            user_id=pharmacist_user["user"].id,
            role_id=role_cashier.id,
            tenant_id=demo_tenant.id,
            store_id=demo_store.id,
        )
        session.add(ur)
        session.commit()

        response = client.delete(
            "/api/v1/auth/roles/revoke",
            headers=tenant_admin_headers,
            params={
                "user_id": str(pharmacist_user["user"].id),
                "role_name": RoleName.CASHIER,
                "store_id": str(demo_store.id),
            },
        )

        assert response.status_code == 200
        assert response.json()["success"] is True

    def test_revoke_tenant_wide_role(
        self,
        client: TestClient,
        tenant_admin_headers: dict,
        pharmacist_user: dict,
        demo_tenant: Tenant,
        role_cashier: Role,
        session: Session,
    ):
        """Revoking a role without store_id must remove the tenant-wide assignment."""
        ur = UserRole(
            user_id=pharmacist_user["user"].id,
            role_id=role_cashier.id,
            tenant_id=demo_tenant.id,
            store_id=None,
        )
        session.add(ur)
        session.commit()

        response = client.delete(
            "/api/v1/auth/roles/revoke",
            headers=tenant_admin_headers,
            params={
                "user_id": str(pharmacist_user["user"].id),
                "role_name": RoleName.CASHIER,
            },
        )

        assert response.status_code == 200

    def test_revoke_nonexistent_assignment_returns_404(
        self,
        client: TestClient,
        tenant_admin_headers: dict,
        pharmacist_user: dict,
    ):
        """Revoking a role that was never assigned must return 404."""
        response = client.delete(
            "/api/v1/auth/roles/revoke",
            headers=tenant_admin_headers,
            params={
                "user_id": str(pharmacist_user["user"].id),
                "role_name": RoleName.CASHIER,
            },
        )

        assert response.status_code == 404

    def test_store_manager_cannot_revoke_roles(
        self,
        client: TestClient,
        store_manager_headers: dict,
        pharmacist_user: dict,
    ):
        """STORE_MANAGER must receive 403 when attempting to revoke a role."""
        response = client.delete(
            "/api/v1/auth/roles/revoke",
            headers=store_manager_headers,
            params={
                "user_id": str(pharmacist_user["user"].id),
                "role_name": RoleName.PHARMACIST,
            },
        )

        assert response.status_code == 403

    def test_revoke_role_unauthenticated_returns_401(
        self,
        client: TestClient,
        pharmacist_user: dict,
    ):
        response = client.delete(
            "/api/v1/auth/roles/revoke",
            params={
                "user_id": str(pharmacist_user["user"].id),
                "role_name": RoleName.PHARMACIST,
            },
        )

        assert response.status_code == 401


# ============================================================================
# SECURITY & EDGE-CASE TESTS
# ============================================================================

@pytest.mark.security
class TestSecurityEdgeCases:
    """Cross-cutting security and robustness tests."""

    def test_malformed_bearer_header_returns_401(self, client: TestClient):
        """Header without valid 'Bearer <token>' format must return 401."""
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "NotBearer some_token"},
        )

        assert response.status_code == 401

    def test_bearer_header_with_no_token_value_returns_401(self, client: TestClient):
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer"},
        )

        assert response.status_code == 401

    def test_tampered_jwt_signature_returns_401(
        self, client: TestClient, pharmacist_token: str
    ):
        """Modifying even the last three characters of a valid JWT must be rejected."""
        tampered = pharmacist_token[:-3] + "xxx"

        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {tampered}"},
        )

        assert response.status_code == 401

    def test_revoked_access_token_rejected_after_logout(
        self,
        client: TestClient,
        pharmacist_headers: dict,
    ):
        """After logout, subsequent requests with the same token must be 401."""
        client.post("/api/v1/auth/logout", headers=pharmacist_headers)

        response = client.get("/api/v1/auth/me", headers=pharmacist_headers)
        assert response.status_code == 401

    def test_locked_user_existing_token_rejected(
        self,
        client: TestClient,
        locked_user: dict,
        session: Session,
    ):
        """If a user's account is locked, a pre-existing token must be rejected."""
        # Simulate a token that was issued before the account was locked
        locked_user["user"].api_token = "pre_lock_fake_token"
        session.add(locked_user["user"])
        session.commit()

        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer pre_lock_fake_token"},
        )

        assert response.status_code == 401


# ============================================================================
# RUN
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])