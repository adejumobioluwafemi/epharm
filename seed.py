"""
FILE: seed.py
Database seeder — roles, super admin, demo tenant, demo store, and at least
two users for every role type.
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

# ─── How each role is scoped & what user_type it maps to ──────────────────────
# tenant_wide=True  → UserRole.store_id is NULL (role applies to whole tenant)
# tenant_wide=False → UserRole.store_id is set  (role scoped to a store)
# staff_profile=True → also create a StaffProfile row (staff-type users only)
ROLE_SEED_PLAN = {
    RoleName.TENANT_ADMIN:   {"user_type": UserType.STAFF,   "tenant_wide": True,  "staff_profile": True},
    RoleName.STORE_MANAGER:  {"user_type": UserType.STAFF,   "tenant_wide": False, "staff_profile": True},
    RoleName.PHARMACIST:     {"user_type": UserType.STAFF,   "tenant_wide": False, "staff_profile": True},
    RoleName.CASHIER:        {"user_type": UserType.STAFF,   "tenant_wide": False, "staff_profile": True},
    RoleName.INVENTORY_CLERK:{"user_type": UserType.STAFF,   "tenant_wide": False, "staff_profile": True},
    RoleName.RIDER:          {"user_type": UserType.RIDER,   "tenant_wide": False, "staff_profile": False},
    RoleName.PATIENT:        {"user_type": UserType.PATIENT, "tenant_wide": True,  "staff_profile": False},
}

USERS_PER_ROLE = 2  # seed at least two of each role


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


def _create_staff_user(
    session: Session,
    *,
    email: str,
    first_name: str,
    last_name: str,
    phone: str,
    user_type: UserType,
    password_env: str = None,  # type: ignore
) -> tuple[User, str]:
    """Create a user (idempotent by email). Returns (user, password_or_marker).

    If the user already exists, returns ("__exists__") as the password marker so
    the caller knows not to re-log a fresh credential.
    """
    existing = session.exec(select(User).where(User.email == email)).first()
    if existing:
        return existing, "__exists__"

    password = (os.getenv(password_env) if password_env else None) or generate_temp_password(12)
    salt = generate_salt()
    user = User(
        email=email,
        phone=phone,
        first_name=first_name,
        last_name=last_name,
        password_hash=hash_password(password, salt),
        salt=salt,
        user_type=user_type,
        is_active=True,
        is_locked=False,
    )
    session.add(user)
    session.flush()
    return user, password


def _assign_role(
    session: Session,
    user: User,
    role: Role,
    tenant: Tenant,
    store: PharmacyStore = None,  # type: ignore
) -> None:
    """Idempotently assign a role to a user, scoped to tenant (+ optional store)."""
    store_id = store.id if store else None
    existing = session.exec(
        select(UserRole).where(
            and_(
                UserRole.user_id == user.id,        # type: ignore
                UserRole.role_id == role.id,        # type: ignore
                UserRole.tenant_id == tenant.id,    # type: ignore
                UserRole.store_id == store_id,      # type: ignore
            )
        )
    ).first()
    if existing:
        return
    session.add(
        UserRole(
            user_id=user.id,
            role_id=role.id,
            tenant_id=tenant.id,
            store_id=store_id,
        )
    )


def seed_super_admins(session: Session, role_map: dict, platform_tenant: Tenant) -> None:
    """Create at least two platform SUPER_ADMIN users."""
    sa_role = role_map[RoleName.SUPER_ADMIN]
    for i in range(1, USERS_PER_ROLE + 1):
        # Keep the first super admin on the well-known email / env override.
        if i == 1:
            email = os.getenv("SUPER_ADMIN_EMAIL", "superadmin@epharmacy.com")
            phone = os.getenv("SUPER_ADMIN_PHONE", "+2348000000000")
            password_env = "SUPER_ADMIN_PASSWORD"
        else:
            email = f"superadmin{i}@epharmacy.com"
            phone = f"+234800000000{i}"
            password_env = None  # type: ignore

        user, password = _create_staff_user(
            session,
            email=email,
            first_name="Platform",
            last_name=f"Admin {i}",
            phone=phone,
            user_type=UserType.SUPER_ADMIN,
            password_env=password_env, # type: ignore
        )
        _assign_role(session, user, sa_role, platform_tenant)  # tenant-wide, no store
        if password == "__exists__":
            logger.info(f"  ✓ Super admin already exists: {email}")
        else:
            logger.info(f"  ✓ Super admin created: {email}  |  password: {password}")


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


def seed_demo_stores(session: Session, tenant: Tenant) -> list[PharmacyStore]:
    """Create two demo branches for the demo tenant. Returns [main, second]."""
    wanted = [
        {
            "name": "Main Branch",
            "address": "123 Health Avenue",
            "city": "Lagos", "state": "Lagos", "postal_code": "100001",
            "phone": "+2348012345678", "email": "mainbranch@demopharmacy.com",
            "latitude": 6.5244, "longitude": 3.3792,
        },
        {
            "name": "Ikeja Branch",
            "address": "45 Airport Road, Ikeja",
            "city": "Lagos", "state": "Lagos", "postal_code": "100211",
            "phone": "+2348012345679", "email": "ikeja@demopharmacy.com",
            "latitude": 6.6018, "longitude": 3.3515,
        },
    ]
    stores: list[PharmacyStore] = []
    for s in wanted:
        existing = session.exec(
            select(PharmacyStore).where(
                and_(
                    PharmacyStore.tenant_id == tenant.id,  # type: ignore
                    PharmacyStore.name == s["name"],       # type: ignore
                )
            )
        ).first()
        if existing:
            logger.info(f"  ✓ Demo store already exists: {s['name']}")
            stores.append(existing)
            continue
        store = PharmacyStore(tenant_id=tenant.id, **s)  # type: ignore
        session.add(store)
        session.flush()
        logger.info(f"  ✓ Demo store created: {store.name}")
        stores.append(store)
    return stores


def seed_role_users(
    session: Session,
    role_map: dict,
    tenant: Tenant,
    stores: list[PharmacyStore],
) -> None:
    """Seed at least two users for each non-super-admin role, per ROLE_SEED_PLAN.

    Store-scoped roles are spread across the available stores so the two users
    don't all land on the same branch.
    """
    for role_name, plan in ROLE_SEED_PLAN.items():
        role = role_map[role_name]
        slug = role_name.value.lower()  # e.g. "pharmacist"
        for i in range(1, USERS_PER_ROLE + 1):
            email = f"{slug}{i}@demopharmacy.com"
            # Distribute store-scoped users round-robin across stores.
            store = None if plan["tenant_wide"] else stores[(i - 1) % len(stores)]

            user, password = _create_staff_user(
                session,
                email=email,
                first_name=role_name.value.replace("_", " ").title(),
                last_name=f"User {i}",
                phone=f"+23480{abs(hash(email)) % 100000000:08d}",
                user_type=plan["user_type"],
            )
            _assign_role(session, user, role, tenant, store) # type: ignore

            if plan["staff_profile"] and password != "__exists__":
                # StaffProfile requires a concrete store; tenant-wide staff (tenant
                # admin) get attached to the first store for profile purposes.
                profile_store = store or stores[0]
                session.add(
                    StaffProfile(
                        user_id=user.id,
                        tenant_id=tenant.id,
                        store_id=profile_store.id,
                        verified=True,
                        verified_at=utcnow(),
                    )
                )

            if password == "__exists__":
                logger.info(f"  ✓ {role_name.value} already exists: {email}")
            else:
                logger.info(f"  ✓ {role_name.value} created: {email}  |  password: {password}")


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

        logger.info("\n👤 Seeding super admins...")
        seed_super_admins(session, role_map, platform_tenant)
        session.commit()

        logger.info("\n🏪 Seeding demo tenant & stores...")
        demo_tenant = seed_demo_tenant(session)
        session.commit()
        demo_stores = seed_demo_stores(session, demo_tenant)
        session.commit()

        logger.info("\n👥 Seeding two users per role...")
        seed_role_users(session, role_map, demo_tenant, demo_stores)
        session.commit()

    logger.info("\n✅ Seeding complete!")
    logger.info("─" * 50)
    logger.info("Seeded at least two users per role under the demo tenant.")
    logger.info("Login emails follow the pattern <role>1@demopharmacy.com / <role>2@demopharmacy.com")
    logger.info("  e.g. pharmacist1@demopharmacy.com, cashier2@demopharmacy.com")
    logger.info("Super admins: superadmin@epharmacy.com, superadmin2@epharmacy.com")
    logger.info("(Generated passwords are printed above; set *_PASSWORD env vars to pin them.)")


if __name__ == "__main__":
    main()