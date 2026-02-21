"""
FILE: tests/conftest.py
Shared pytest fixtures and configuration for the E-Pharmacy multi-tenant API.

Fixture hierarchy:
    engine → session → client
    role_* → (consumed by user builders)
    platform_tenant → super_admin_user → super_admin_token → super_admin_headers
    demo_tenant → demo_store
              └→ tenant_admin_user → tenant_admin_token → tenant_admin_headers
              └→ store_manager_user → store_manager_token → store_manager_headers
              └→ pharmacist_user → pharmacist_token → pharmacist_headers
    second_tenant → second_store → other_tenant_user → other_tenant_token → other_tenant_headers
    locked_user, inactive_user  (edge-case users)
    valid_reset_token, expired_reset_token, used_reset_token
    valid_refresh_token
"""
import sys
import os

# Guarantee project root is on sys.path (belt-and-suspenders alongside pytest.ini pythonpath)
sys.path.insert(0, os.path.dirname(__file__))

import hashlib
import pytest
from datetime import datetime, timedelta
from typing import Dict, Tuple

from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine, select
from sqlmodel.pool import StaticPool

from main import app
from src.core.database import get_session
from src.core.security import (
    create_access_token,
    create_refresh_token_jwt,
    generate_reset_token,
    generate_salt,
    hash_password,
)
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
# DATABASE FIXTURES
# ============================================================================

@pytest.fixture(name="engine")
def engine_fixture():
    """Create in-memory SQLite engine for tests. Schema is created once."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    return engine


@pytest.fixture(name="session")
def session_fixture(engine):
    """Create a function-scoped session; rolls back after each test."""
    with Session(engine) as session:
        yield session
        session.rollback()


@pytest.fixture(name="client")
def client_fixture(session: Session):
    """TestClient with the DB session dependency overridden."""
    def get_session_override():
        return session

    app.dependency_overrides[get_session] = get_session_override
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


# ============================================================================
# ROLE FIXTURES
# ============================================================================

def _get_or_create_role(session: Session, name: str, description: str) -> Role:
    """Return existing role or create and flush a new one."""
    existing = session.exec(select(Role).where(Role.name == name)).first()
    if existing:
        return existing
    role = Role(name=name, description=description)
    session.add(role)
    session.flush()
    return role


@pytest.fixture(name="role_super_admin")
def role_super_admin_fixture(session: Session) -> Role:
    """SUPER_ADMIN role."""
    return _get_or_create_role(session, RoleName.SUPER_ADMIN, "Platform-wide administrator")


@pytest.fixture(name="role_tenant_admin")
def role_tenant_admin_fixture(session: Session) -> Role:
    """TENANT_ADMIN role."""
    return _get_or_create_role(session, RoleName.TENANT_ADMIN, "Pharmacy company admin")


@pytest.fixture(name="role_store_manager")
def role_store_manager_fixture(session: Session) -> Role:
    """STORE_MANAGER role."""
    return _get_or_create_role(session, RoleName.STORE_MANAGER, "Branch/store manager")


@pytest.fixture(name="role_pharmacist")
def role_pharmacist_fixture(session: Session) -> Role:
    """PHARMACIST role."""
    return _get_or_create_role(session, RoleName.PHARMACIST, "Licensed pharmacist")


@pytest.fixture(name="role_cashier")
def role_cashier_fixture(session: Session) -> Role:
    """CASHIER role."""
    return _get_or_create_role(session, RoleName.CASHIER, "Cashier")


@pytest.fixture(name="role_inventory_clerk")
def role_inventory_clerk_fixture(session: Session) -> Role:
    """INVENTORY_CLERK role."""
    return _get_or_create_role(session, RoleName.INVENTORY_CLERK, "Inventory clerk")


@pytest.fixture(name="role_rider")
def role_rider_fixture(session: Session) -> Role:
    """RIDER role."""
    return _get_or_create_role(session, RoleName.RIDER, "Delivery rider")


@pytest.fixture(name="role_patient")
def role_patient_fixture(session: Session) -> Role:
    """PATIENT role."""
    return _get_or_create_role(session, RoleName.PATIENT, "Patient / customer")


@pytest.fixture(name="all_roles")
def all_roles_fixture(
    role_super_admin: Role,
    role_tenant_admin: Role,
    role_store_manager: Role,
    role_pharmacist: Role,
    role_cashier: Role,
    role_inventory_clerk: Role,
    role_rider: Role,
    role_patient: Role,
    session: Session,
) -> Dict[str, Role]:
    """
    Seed all 8 roles and return a name→Role mapping.
    Use this whenever a test needs the full role catalogue pre-seeded.
    """
    session.commit()
    return {
        RoleName.SUPER_ADMIN: role_super_admin,
        RoleName.TENANT_ADMIN: role_tenant_admin,
        RoleName.STORE_MANAGER: role_store_manager,
        RoleName.PHARMACIST: role_pharmacist,
        RoleName.CASHIER: role_cashier,
        RoleName.INVENTORY_CLERK: role_inventory_clerk,
        RoleName.RIDER: role_rider,
        RoleName.PATIENT: role_patient,
    }


# ============================================================================
# TENANT & STORE FIXTURES
# ============================================================================

@pytest.fixture(name="platform_tenant")
def platform_tenant_fixture(session: Session) -> Tenant:
    """
    Pseudo-tenant used as the FK target for the SUPER_ADMIN UserRole row.
    Mirrors the seed.py convention (slug = 'platform').
    """
    existing = session.exec(select(Tenant).where(Tenant.slug == "platform")).first()
    if existing:
        return existing
    tenant = Tenant(
        name="Platform",
        slug="platform",
        registration_number="PLATFORM-001",
        email="platform@epharmacy.com",
    )
    session.add(tenant)
    session.flush()
    return tenant


@pytest.fixture(name="demo_tenant")
def demo_tenant_fixture(session: Session) -> Tenant:
    """Primary demo pharmacy company tenant used by most tests."""
    existing = session.exec(select(Tenant).where(Tenant.slug == "demo-pharmacy")).first()
    if existing:
        return existing
    tenant = Tenant(
        name="Demo Pharmacy Ltd.",
        slug="demo-pharmacy",
        registration_number="PHRM-2024-001",
        email="admin@demopharmacy.com",
        phone="+2348012345678",
        address="123 Health Avenue, Lagos, Nigeria",
    )
    session.add(tenant)
    session.flush()
    return tenant


@pytest.fixture(name="second_tenant")
def second_tenant_fixture(session: Session) -> Tenant:
    """A second, independent tenant for cross-tenant isolation tests."""
    existing = session.exec(select(Tenant).where(Tenant.slug == "other-pharmacy")).first()
    if existing:
        return existing
    tenant = Tenant(
        name="Other Pharmacy Co.",
        slug="other-pharmacy",
        registration_number="PHRM-2024-002",
        email="admin@otherpharmacy.com",
    )
    session.add(tenant)
    session.flush()
    return tenant


@pytest.fixture(name="demo_store")
def demo_store_fixture(session: Session, demo_tenant: Tenant) -> PharmacyStore:
    """Main branch of the demo tenant."""
    store = PharmacyStore(
        tenant_id=demo_tenant.id,
        name="Main Branch",
        address="123 Health Avenue",
        city="Lagos",
        state="Lagos",
        postal_code="100001",
        phone="+2348012345678",
        email="mainbranch@demopharmacy.com",
    )
    session.add(store)
    session.flush()
    return store


@pytest.fixture(name="second_store")
def second_store_fixture(session: Session, demo_tenant: Tenant) -> PharmacyStore:
    """Second branch of the same demo tenant."""
    store = PharmacyStore(
        tenant_id=demo_tenant.id,
        name="Ikeja Branch",
        address="45 Airport Road, Ikeja",
        city="Lagos",
        state="Lagos",
    )
    session.add(store)
    session.flush()
    return store


@pytest.fixture(name="other_tenant_store")
def other_tenant_store_fixture(session: Session, second_tenant: Tenant) -> PharmacyStore:
    """Branch belonging to the second (different) tenant. Used in isolation tests."""
    store = PharmacyStore(
        tenant_id=second_tenant.id,
        name="Other Co. Branch",
        address="99 Market Street",
        city="Abuja",
        state="FCT",
    )
    session.add(store)
    session.flush()
    return store


# ============================================================================
# INTERNAL HELPERS — user + role creation
# ============================================================================

def _create_user(
    session: Session,
    email: str,
    user_type: UserType = UserType.STAFF,
    first_name: str = "Test",
    last_name: str = "User",
    phone: str = None, # type: ignore
    password: str = "Password123!",
    is_active: bool = True,
    is_locked: bool = False,
) -> Tuple[User, str]:
    """
    Build and flush a User with bcrypt+salt hashed password.
    Returns (user, plain_password).
    """
    salt = generate_salt()
    user = User(
        email=email,
        phone=phone,
        first_name=first_name,
        last_name=last_name,
        password_hash=hash_password(password, salt),
        salt=salt,
        user_type=user_type,
        is_active=is_active,
        is_locked=is_locked,
        login_count=0,
        failed_login_attempts=0,
    )
    session.add(user)
    session.flush()
    return user, password


def _assign_role(
    session: Session,
    user: User,
    role: Role,
    tenant: Tenant,
    store: PharmacyStore = None, # type: ignore
) -> UserRole:
    """Assign a role to a user, scoped to a tenant (and optionally a store)."""
    user_role = UserRole(
        user_id=user.id,
        role_id=role.id,
        tenant_id=tenant.id,
        store_id=store.id if store else None,
    )
    session.add(user_role)
    session.flush()
    return user_role


def _create_token(
    session: Session,
    user: User,
    tenant: Tenant,
    store_ids=None,
    roles=None,
) -> str:
    """Create a JWT access token, persist it in user.api_token, and return the raw token."""
    store_ids = store_ids or []
    roles = roles or []
    access_token = create_access_token(
        user_id=user.id,
        email=user.email,
        user_type=user.user_type,
        tenant_id=tenant.id,
        store_ids=store_ids,
        roles=roles,
    )
    user.api_token = access_token
    session.add(user)
    session.flush()
    return access_token


# ============================================================================
# USER FIXTURES
# ============================================================================

@pytest.fixture(name="super_admin_user")
def super_admin_user_fixture(
    session: Session,
    platform_tenant: Tenant,
    role_super_admin: Role,
) -> dict:
    """Platform-level super admin. Has no store scope."""
    user, password = _create_user(
        session,
        email="superadmin@epharmacy.com",
        user_type=UserType.SUPER_ADMIN,
        first_name="Platform",
        last_name="Admin",
        phone="+2348000000001",
    )
    _assign_role(session, user, role_super_admin, platform_tenant)
    session.commit()
    session.refresh(user)
    return {"user": user, "password": password, "tenant": platform_tenant}


@pytest.fixture(name="tenant_admin_user")
def tenant_admin_user_fixture(
    session: Session,
    demo_tenant: Tenant,
    demo_store: PharmacyStore,
    role_tenant_admin: Role,
) -> dict:
    """Company-level admin for demo_tenant. Tenant-wide scope."""
    user, password = _create_user(
        session,
        email="tenantadmin@demopharmacy.com",
        user_type=UserType.STAFF,
        first_name="Tenant",
        last_name="Admin",
        phone="+2348011111111",
    )
    _assign_role(session, user, role_tenant_admin, demo_tenant)
    profile = StaffProfile(
        user_id=user.id,
        tenant_id=demo_tenant.id,
        store_id=demo_store.id,
        verified=True,
        verified_at=utcnow(),
    )
    session.add(profile)
    session.commit()
    session.refresh(user)
    return {"user": user, "password": password, "tenant": demo_tenant, "store": demo_store}


@pytest.fixture(name="store_manager_user")
def store_manager_user_fixture(
    session: Session,
    demo_tenant: Tenant,
    demo_store: PharmacyStore,
    role_store_manager: Role,
) -> dict:
    """Branch manager for demo_store. Store-scoped."""
    user, password = _create_user(
        session,
        email="manager@demopharmacy.com",
        user_type=UserType.STAFF,
        first_name="Branch",
        last_name="Manager",
        phone="+2348022222222",
    )
    _assign_role(session, user, role_store_manager, demo_tenant, demo_store)
    profile = StaffProfile(
        user_id=user.id,
        tenant_id=demo_tenant.id,
        store_id=demo_store.id,
        verified=True,
        verified_at=utcnow(),
    )
    session.add(profile)
    session.commit()
    session.refresh(user)
    return {"user": user, "password": password, "tenant": demo_tenant, "store": demo_store}


@pytest.fixture(name="pharmacist_user")
def pharmacist_user_fixture(
    session: Session,
    demo_tenant: Tenant,
    demo_store: PharmacyStore,
    role_pharmacist: Role,
) -> dict:
    """Pharmacist — store-scoped staff, below STORE_MANAGER."""
    user, password = _create_user(
        session,
        email="pharmacist@demopharmacy.com",
        user_type=UserType.STAFF,
        first_name="Jane",
        last_name="Pharmacist",
        phone="+2348033333333",
    )
    _assign_role(session, user, role_pharmacist, demo_tenant, demo_store)
    profile = StaffProfile(
        user_id=user.id,
        tenant_id=demo_tenant.id,
        store_id=demo_store.id,
        license_number="PCN-2024-001",
    )
    session.add(profile)
    session.commit()
    session.refresh(user)
    return {"user": user, "password": password, "tenant": demo_tenant, "store": demo_store}


@pytest.fixture(name="other_tenant_user")
def other_tenant_user_fixture(
    session: Session,
    second_tenant: Tenant,
    other_tenant_store: PharmacyStore,
    role_store_manager: Role,
) -> dict:
    """A store manager belonging to a completely different tenant."""
    user, password = _create_user(
        session,
        email="manager@otherpharmacy.com",
        user_type=UserType.STAFF,
        first_name="Other",
        last_name="Manager",
        phone="+2348044444444",
    )
    _assign_role(session, user, role_store_manager, second_tenant, other_tenant_store)
    session.commit()
    session.refresh(user)
    return {"user": user, "password": password, "tenant": second_tenant, "store": other_tenant_store}


@pytest.fixture(name="locked_user")
def locked_user_fixture(
    session: Session,
    demo_tenant: Tenant,
    demo_store: PharmacyStore,
    role_cashier: Role,
) -> dict:
    """A locked (is_locked=True) cashier — simulates account lockout."""
    user, password = _create_user(
        session,
        email="locked@demopharmacy.com",
        user_type=UserType.STAFF,
        first_name="Locked",
        last_name="Staff",
        phone="+2348055555555",
        is_locked=True,
    )
    user.failed_login_attempts = 5
    _assign_role(session, user, role_cashier, demo_tenant, demo_store)
    session.commit()
    session.refresh(user)
    return {"user": user, "password": password, "tenant": demo_tenant, "store": demo_store}


@pytest.fixture(name="inactive_user")
def inactive_user_fixture(
    session: Session,
    demo_tenant: Tenant,
    demo_store: PharmacyStore,
    role_cashier: Role,
) -> dict:
    """A deactivated (is_active=False) cashier."""
    user, password = _create_user(
        session,
        email="inactive@demopharmacy.com",
        user_type=UserType.STAFF,
        first_name="Inactive",
        last_name="Staff",
        phone="+2348066666666",
        is_active=False,
    )
    _assign_role(session, user, role_cashier, demo_tenant, demo_store)
    session.commit()
    session.refresh(user)
    return {"user": user, "password": password, "tenant": demo_tenant, "store": demo_store}


# ============================================================================
# TOKEN FIXTURES
# ============================================================================

@pytest.fixture(name="super_admin_token")
def super_admin_token_fixture(
    session: Session,
    super_admin_user: dict,
    platform_tenant: Tenant,
) -> str:
    """Valid JWT for the super_admin_user."""
    return _create_token(
        session,
        super_admin_user["user"],
        platform_tenant,
        roles=[RoleName.SUPER_ADMIN],
    )


@pytest.fixture(name="tenant_admin_token")
def tenant_admin_token_fixture(
    session: Session,
    tenant_admin_user: dict,
    demo_tenant: Tenant,
    demo_store: PharmacyStore,
) -> str:
    """Valid JWT for the tenant_admin_user."""
    return _create_token(
        session,
        tenant_admin_user["user"],
        demo_tenant,
        store_ids=[demo_store.id],
        roles=[RoleName.TENANT_ADMIN],
    )


@pytest.fixture(name="store_manager_token")
def store_manager_token_fixture(
    session: Session,
    store_manager_user: dict,
    demo_tenant: Tenant,
    demo_store: PharmacyStore,
) -> str:
    """Valid JWT for the store_manager_user."""
    return _create_token(
        session,
        store_manager_user["user"],
        demo_tenant,
        store_ids=[demo_store.id],
        roles=[RoleName.STORE_MANAGER],
    )


@pytest.fixture(name="pharmacist_token")
def pharmacist_token_fixture(
    session: Session,
    pharmacist_user: dict,
    demo_tenant: Tenant,
    demo_store: PharmacyStore,
) -> str:
    """Valid JWT for the pharmacist_user (lowest privileged staff)."""
    return _create_token(
        session,
        pharmacist_user["user"],
        demo_tenant,
        store_ids=[demo_store.id],
        roles=[RoleName.PHARMACIST],
    )


@pytest.fixture(name="other_tenant_token")
def other_tenant_token_fixture(
    session: Session,
    other_tenant_user: dict,
    second_tenant: Tenant,
    other_tenant_store: PharmacyStore,
) -> str:
    """Valid JWT for a user belonging to a different tenant."""
    return _create_token(
        session,
        other_tenant_user["user"],
        second_tenant,
        store_ids=[other_tenant_store.id],
        roles=[RoleName.STORE_MANAGER],
    )


# ============================================================================
# HEADER FIXTURES
# ============================================================================

@pytest.fixture(name="super_admin_headers")
def super_admin_headers_fixture(super_admin_token: str) -> dict:
    """Authorization headers for super_admin_user."""
    return {"Authorization": f"Bearer {super_admin_token}"}


@pytest.fixture(name="tenant_admin_headers")
def tenant_admin_headers_fixture(tenant_admin_token: str) -> dict:
    """Authorization headers for tenant_admin_user."""
    return {"Authorization": f"Bearer {tenant_admin_token}"}


@pytest.fixture(name="store_manager_headers")
def store_manager_headers_fixture(store_manager_token: str) -> dict:
    """Authorization headers for store_manager_user."""
    return {"Authorization": f"Bearer {store_manager_token}"}


@pytest.fixture(name="pharmacist_headers")
def pharmacist_headers_fixture(pharmacist_token: str) -> dict:
    """Authorization headers for pharmacist_user."""
    return {"Authorization": f"Bearer {pharmacist_token}"}


@pytest.fixture(name="other_tenant_headers")
def other_tenant_headers_fixture(other_tenant_token: str) -> dict:
    """Authorization headers for other_tenant_user."""
    return {"Authorization": f"Bearer {other_tenant_token}"}


# ============================================================================
# PASSWORD RESET TOKEN FIXTURES
# ============================================================================

@pytest.fixture(name="valid_reset_token")
def valid_reset_token_fixture(
    session: Session,
    pharmacist_user: dict,
) -> Tuple[str, PasswordResetToken]:
    """A valid, unexpired, unused password-reset token for pharmacist_user."""
    raw_token = generate_reset_token()
    record = PasswordResetToken(
        user_id=pharmacist_user["user"].id,
        token=raw_token,
        expires_at=utcnow() + timedelta(hours=24),
        is_used=False,
        ip_address="127.0.0.1",
        user_agent="pytest",
    )
    session.add(record)
    session.commit()
    return raw_token, record


@pytest.fixture(name="expired_reset_token")
def expired_reset_token_fixture(
    session: Session,
    pharmacist_user: dict,
) -> Tuple[str, PasswordResetToken]:
    """An expired password-reset token (expires_at in the past)."""
    raw_token = generate_reset_token()
    record = PasswordResetToken(
        user_id=pharmacist_user["user"].id,
        token=raw_token,
        expires_at=utcnow() - timedelta(hours=1),
        is_used=False,
    )
    session.add(record)
    session.commit()
    return raw_token, record


@pytest.fixture(name="used_reset_token")
def used_reset_token_fixture(
    session: Session,
    pharmacist_user: dict,
) -> Tuple[str, PasswordResetToken]:
    """An already-used password-reset token."""
    raw_token = generate_reset_token()
    record = PasswordResetToken(
        user_id=pharmacist_user["user"].id,
        token=raw_token,
        expires_at=utcnow() + timedelta(hours=24),
        is_used=True,
        used_at=utcnow(),
    )
    session.add(record)
    session.commit()
    return raw_token, record


# ============================================================================
# REFRESH TOKEN FIXTURE
# ============================================================================

@pytest.fixture(name="valid_refresh_token")
def valid_refresh_token_fixture(
    session: Session,
    pharmacist_user: dict,
) -> Tuple[str, RefreshToken]:
    """A valid (unexpired, not revoked) refresh token JWT for pharmacist_user."""
    raw_jwt = create_refresh_token_jwt(user_id=pharmacist_user["user"].id)
    token_hash = hashlib.sha256(raw_jwt.encode()).hexdigest()
    record = RefreshToken(
        user_id=pharmacist_user["user"].id,
        token_hash=token_hash,
        expires_at=utcnow() + timedelta(days=7),
        is_revoked=False,
        ip_address="127.0.0.1",
        user_agent="pytest",
    )
    session.add(record)
    session.commit()
    return raw_jwt, record


# ============================================================================
# EMAIL SERVICE FIXTURE
# ============================================================================

@pytest.fixture(name="mock_email_settings")
def mock_email_settings_fixture():
    """Disable outbound email for all tests. Restores original values after each test."""
    from src.email.config import email_settings

    original_send = email_settings.SEND_EMAILS
    original_key = email_settings.RESEND_API_KEY

    email_settings.SEND_EMAILS = False
    email_settings.RESEND_API_KEY = "re_test_key_no_real_sending"

    yield email_settings

    email_settings.SEND_EMAILS = original_send
    email_settings.RESEND_API_KEY = original_key


# ============================================================================
# SETUP / TEARDOWN
# ============================================================================

@pytest.fixture(autouse=True)
def reset_database(session: Session):
    """Rollback any uncommitted changes after each test (safety net)."""
    yield
    session.rollback()


# ============================================================================
# PYTEST MARKERS
# ============================================================================

def pytest_configure(config):
    """Register all custom test markers."""
    # Module-level markers
    config.addinivalue_line("markers", "auth: Authentication and token tests")
    config.addinivalue_line("markers", "users: User CRUD tests")
    config.addinivalue_line("markers", "tenants: Tenant management tests (SUPER_ADMIN only)")
    config.addinivalue_line("markers", "stores: Pharmacy store management tests")
    config.addinivalue_line("markers", "rbac: Role-based access control tests")
    config.addinivalue_line("markers", "email: Email service tests")

    # Cross-cutting markers
    config.addinivalue_line("markers", "tenant_isolation: Cross-tenant data isolation tests")
    config.addinivalue_line("markers", "security: Security and edge-case tests")
    config.addinivalue_line("markers", "unit: Unit tests (no HTTP client)")
    config.addinivalue_line("markers", "integration: Full HTTP stack integration tests")