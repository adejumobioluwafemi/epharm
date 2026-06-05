"""
FILE: seed.py
Database seeder — roles, super admin, demo tenant, demo store
Run: python seed.py
"""
import sys
import os

sys.path.append(os.path.dirname(__file__))

from sqlalchemy import and_
from sqlmodel import Session, select

from src.core.database import engine, create_db_and_tables
from src.core.security import generate_salt, hash_password, generate_temp_password
from src.shared.models import (
    PharmacyStore,
    Role,
    RoleName,
    Tenant,
    User,
    UserRole,
    UserType,
    StaffProfile,
    utcnow,
)
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ─── Role definitions ─────────────────────────────────────────────────────────
ROLES = [
    {"name": RoleName.SUPER_ADMIN, "description": "Platform-wide administrator"},
    {"name": RoleName.TENANT_ADMIN, "description": "Pharmacy company super-admin"},
    {"name": RoleName.STORE_MANAGER, "description": "Branch / store manager"},
    {"name": RoleName.PHARMACIST, "description": "Licensed pharmacist"},
    {"name": RoleName.CASHIER, "description": "Cashier / sales assistant"},
    {"name": RoleName.INVENTORY_CLERK, "description": "Inventory management staff"},
    {"name": RoleName.RIDER, "description": "Delivery rider"},
    {"name": RoleName.PATIENT, "description": "Patient / customer"},
]


# ─── Seeders ──────────────────────────────────────────────────────────────────
def seed_roles(session: Session) -> dict:
    """Seed all roles. Returns name → Role map.

    Role.name is a VARCHAR column, so persist the enum's *value* ('SUPER_ADMIN'),
    not the enum object, to keep lookups (Role.name == 'SUPER_ADMIN') consistent.
    """
    role_map = {}
    for role_data in ROLES:
        role_name = role_data["name"].value  # store the string value
        existing = session.exec(select(Role).where(Role.name == role_name)).first()
        if existing:
            role_map[role_data["name"]] = existing
            continue
        role = Role(name=role_name, description=role_data["description"])
        session.add(role)
        session.flush()
        role_map[role_data["name"]] = role
        logger.info(f"  ✓ Role: {role_name}")
    session.commit()
    return role_map


def seed_platform_tenant(session: Session) -> Tenant:
    """A pseudo-tenant row used as the FK target for the SUPER_ADMIN role row."""
    slug = "platform"
    existing = session.exec(select(Tenant).where(Tenant.slug == slug)).first()
    if existing:
        logger.info("  ✓ Platform tenant already exists")
        return existing
    tenant = Tenant(
        name="Platform",
        slug=slug,
        registration_number="PLATFORM-001",
        email="platform@epharmacy.com",
        is_active=True,
    )
    session.add(tenant)
    session.flush()
    logger.info("  ✓ Platform tenant created")
    return tenant


def seed_super_admin(session: Session, role_map: dict, platform_tenant: Tenant) -> User:
    """Create the platform SUPER_ADMIN user and assign the SUPER_ADMIN role.

    The role is scoped to the platform tenant purely to satisfy the
    UserRole.tenant_id FK constraint. Tenant-scoping bypass for SUPER_ADMIN is
    driven by the SUPER_ADMIN *role* (TenantContext.is_super_admin()), not by the
    tenant_id carried in the JWT, so this binding does not restrict the account.
    """
    email = os.getenv("SUPER_ADMIN_EMAIL", "superadmin@epharmacy.com")
    password = os.getenv("SUPER_ADMIN_PASSWORD", generate_temp_password(16))

    user = session.exec(select(User).where(User.email == email)).first()
    if user:
        logger.info(f"  ✓ Super admin already exists: {email}")
    else:
        salt = generate_salt()
        user = User(
            email=email,
            phone=os.getenv("SUPER_ADMIN_PHONE", "+2348000000000"),
            first_name="Platform",
            last_name="Admin",
            password_hash=hash_password(password, salt),
            salt=salt,
            user_type=UserType.SUPER_ADMIN,
            is_active=True,
            is_locked=False,
        )
        session.add(user)
        session.flush()
        logger.info(f"  ✓ Super admin created: {email}  |  password: {password}")

    # Assign SUPER_ADMIN role (idempotent) — scoped to platform tenant, no store
    sa_role = role_map[RoleName.SUPER_ADMIN]
    existing_role = session.exec(
        select(UserRole).where(
            and_(
                UserRole.user_id == user.id,        # type: ignore
                UserRole.role_id == sa_role.id,     # type: ignore
            )
        )
    ).first()
    if not existing_role:
        session.add(
            UserRole(
                user_id=user.id,
                role_id=sa_role.id,
                tenant_id=platform_tenant.id,
                store_id=None,
            )
        )
        logger.info("  ✓ SUPER_ADMIN role assigned")

    return user


def seed_demo_tenant(session: Session) -> Tenant:
    """Create a demo pharmacy company."""
    slug = "demo-pharmacy"
    existing = session.exec(select(Tenant).where(Tenant.slug == slug)).first()
    if existing:
        logger.info(f"  ✓ Demo tenant already exists: {slug}")
        return existing
    tenant = Tenant(
        name="Demo Pharmacy Ltd.",
        slug=slug,
        registration_number="PHRM-2024-001",
        email="admin@demopharmacy.com",
        phone="+2348012345678",
        address="123 Health Avenue, Lagos, Nigeria",
    )
    session.add(tenant)
    session.flush()
    logger.info(f"  ✓ Demo tenant created: {tenant.name}")
    return tenant


def seed_demo_store(session: Session, tenant: Tenant) -> PharmacyStore:
    """Create a demo branch for the demo tenant."""
    existing = session.exec(
        select(PharmacyStore).where(
            and_(
                PharmacyStore.tenant_id == tenant.id,  # type: ignore
                PharmacyStore.name == "Main Branch",   # type: ignore
            )
        )
    ).first()
    if existing:
        logger.info("  ✓ Demo store already exists: Main Branch")
        return existing
    store = PharmacyStore(
        tenant_id=tenant.id,
        name="Main Branch",
        address="123 Health Avenue",
        city="Lagos",
        state="Lagos",
        postal_code="100001",
        phone="+2348012345678",
        email="mainbranch@demopharmacy.com",
        latitude=6.5244,    # type: ignore
        longitude=3.3792,   # type: ignore
    )
    session.add(store)
    session.flush()
    logger.info(f"  ✓ Demo store created: {store.name}")
    return store


def seed_tenant_admin(
    session: Session, tenant: Tenant, store: PharmacyStore, role_map: dict
) -> User:
    """Create a TENANT_ADMIN for the demo tenant (tenant-wide role, no store)."""
    email = "admin@demopharmacy.com"
    password = os.getenv("DEMO_ADMIN_PASSWORD", generate_temp_password(12))

    user = session.exec(select(User).where(User.email == email)).first()
    if user:
        logger.info(f"  ✓ Tenant admin already exists: {email}")
        return user

    salt = generate_salt()
    user = User(
        email=email,
        phone="+2348011111111",
        first_name="Demo",
        last_name="Admin",
        password_hash=hash_password(password, salt),
        salt=salt,
        user_type=UserType.STAFF,
        is_active=True,
        is_locked=False,
    )
    session.add(user)
    session.flush()

    session.add(
        UserRole(
            user_id=user.id,
            role_id=role_map[RoleName.TENANT_ADMIN].id,
            tenant_id=tenant.id,
            store_id=None,  # tenant-wide
        )
    )
    session.add(
        StaffProfile(
            user_id=user.id,
            tenant_id=tenant.id,
            store_id=store.id,
            verified=True,
            verified_at=utcnow(),
        )
    )
    logger.info(f"  ✓ Tenant admin created: {email}  |  password: {password}")
    return user


def seed_demo_store_manager(
    session: Session, tenant: Tenant, store: PharmacyStore, role_map: dict
) -> User:
    """Create a STORE_MANAGER scoped to the main branch."""
    email = "manager@demopharmacy.com"
    password = os.getenv("DEMO_MANAGER_PASSWORD", generate_temp_password(12))

    user = session.exec(select(User).where(User.email == email)).first()
    if user:
        logger.info(f"  ✓ Store manager already exists: {email}")
        return user

    salt = generate_salt()
    user = User(
        email=email,
        phone="+2348022222222",
        first_name="Branch",
        last_name="Manager",
        password_hash=hash_password(password, salt),
        salt=salt,
        user_type=UserType.STAFF,
        is_active=True,
        is_locked=False,
    )
    session.add(user)
    session.flush()

    session.add(
        UserRole(
            user_id=user.id,
            role_id=role_map[RoleName.STORE_MANAGER].id,
            tenant_id=tenant.id,
            store_id=store.id,  # store-scoped
        )
    )
    session.add(
        StaffProfile(
            user_id=user.id,
            tenant_id=tenant.id,
            store_id=store.id,
            verified=True,
            verified_at=utcnow(),
        )
    )
    logger.info(f"  ✓ Store manager created: {email}  |  password: {password}")
    return user


# ─── Entrypoint ───────────────────────────────────────────────────────────────
def main():
    logger.info("🌱 Starting database seeding...")
    create_db_and_tables()

    with Session(engine) as session:
        logger.info("\n📋 Seeding roles...")
        role_map = seed_roles(session)

        logger.info("\n🏢 Seeding platform tenant...")
        platform_tenant = seed_platform_tenant(session)
        session.commit()

        logger.info("\n👤 Seeding super admin...")
        seed_super_admin(session, role_map, platform_tenant)
        session.commit()

        logger.info("\n🏪 Seeding demo tenant & store...")
        demo_tenant = seed_demo_tenant(session)
        session.commit()
        demo_store = seed_demo_store(session, demo_tenant)
        session.commit()

        logger.info("\n👥 Seeding demo users...")
        seed_tenant_admin(session, demo_tenant, demo_store, role_map)
        seed_demo_store_manager(session, demo_tenant, demo_store, role_map)
        session.commit()

    logger.info("\n✅ Seeding complete!")
    logger.info("─" * 50)
    logger.info("Demo credentials:")
    logger.info("  Super Admin  : superadmin@epharmacy.com")
    logger.info("  Tenant Admin : admin@demopharmacy.com")
    logger.info("  Store Manager: manager@demopharmacy.com")
    logger.info("  (Passwords printed above or in .env)")


if __name__ == "__main__":
    main()