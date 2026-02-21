"""
FILE: src/users/router.py
Users, Tenants, and Stores CRUD — tenant-isolated & paginated
"""

from fastapi import APIRouter, Depends
from sqlmodel import Session
from uuid import UUID
from typing import Optional

from src.core.database import get_session
from src.core.dependencies import (
    TenantContext,
    get_current_user,
    pagination_params,
    require_store_manager,
    require_super_admin,
    require_tenant_admin,
)
from src.shared.models import User
from src.shared.schemas import PaginatedResponse, ResponseModel
from src.users.schemas import (
    CreateStoreRequest,
    CreateTenantRequest,
    StoreOut,
    TenantOut,
    UpdateUserRequest,
    UserOut,
    UserWithRoles,
)
from src.users.services import StoreService, TenantService, UserService
import logging

logger = logging.getLogger(__name__)

router = APIRouter()

# Users 

users_router = APIRouter(prefix="/users", tags=["Users"])


@users_router.get(
    "",
    response_model=PaginatedResponse[UserWithRoles],
    dependencies=[Depends(require_store_manager())],
)
async def list_users(
    ctx: TenantContext = Depends(),
    pagination: dict = Depends(pagination_params),
    session: Session = Depends(get_session),
):
    """List all users within the current tenant. Requires store manager+."""
    tenant_id = ctx.require_tenant()
    users, total = await UserService.get_users_in_tenant(
        tenant_id, session, skip=pagination["skip"], limit=pagination["limit"]
    )
    return PaginatedResponse.build(
        items=users,
        total=total,
        page=pagination["page"],
        page_size=pagination["page_size"],
    )


@users_router.get("/me", response_model=ResponseModel)
async def get_my_profile(
    current_user: User = Depends(get_current_user),
):
    """Return the authenticated user's own profile."""
    return ResponseModel(success=True, data=UserOut.model_validate(current_user).model_dump())


@users_router.get(
    "/{user_id}",
    response_model=ResponseModel,
    dependencies=[Depends(require_store_manager())],
)
async def get_user(
    user_id: UUID,
    ctx: TenantContext = Depends(),
    session: Session = Depends(get_session),
):
    tenant_id = ctx.require_tenant()
    user = await UserService.get_user_by_id(user_id, tenant_id, session)
    return ResponseModel(success=True, data=user.model_dump())


@users_router.patch(
    "/{user_id}",
    response_model=ResponseModel,
    dependencies=[Depends(require_store_manager())],
)
async def update_user(
    user_id: UUID,
    req: UpdateUserRequest,
    ctx: TenantContext = Depends(),
    session: Session = Depends(get_session),
):
    tenant_id = ctx.require_tenant()
    user = await UserService.update_user(user_id, req, tenant_id, session)
    return ResponseModel(success=True, message="User updated", data=user.model_dump())


@users_router.patch(
    "/{user_id}/deactivate",
    response_model=ResponseModel,
    dependencies=[Depends(require_tenant_admin())],
)
async def deactivate_user(
    user_id: UUID,
    ctx: TenantContext = Depends(),
    session: Session = Depends(get_session),
):
    tenant_id = ctx.require_tenant()
    await UserService.deactivate_user(user_id, tenant_id, session)
    return ResponseModel(success=True, message="User deactivated")


@users_router.patch(
    "/{user_id}/lock",
    response_model=ResponseModel,
    dependencies=[Depends(require_tenant_admin())],
)
async def lock_user(
    user_id: UUID,
    ctx: TenantContext = Depends(),
    session: Session = Depends(get_session),
):
    tenant_id = ctx.require_tenant()
    await UserService.lock_user(user_id, tenant_id, session)
    return ResponseModel(success=True, message="User locked")


@users_router.patch(
    "/{user_id}/unlock",
    response_model=ResponseModel,
    dependencies=[Depends(require_tenant_admin())],
)
async def unlock_user(
    user_id: UUID,
    ctx: TenantContext = Depends(),
    session: Session = Depends(get_session),
):
    tenant_id = ctx.require_tenant()
    await UserService.unlock_user(user_id, tenant_id, session)
    return ResponseModel(success=True, message="User unlocked")


# Tenants (SUPER_ADMIN only)

tenants_router = APIRouter(
    prefix="/tenants",
    tags=["Tenants"],
    dependencies=[Depends(require_super_admin())],
)


@tenants_router.post("", response_model=ResponseModel)
async def create_tenant(
    req: CreateTenantRequest,
    session: Session = Depends(get_session),
):
    """Create a new pharmacy company (tenant). SUPER_ADMIN only."""
    tenant = await TenantService.create_tenant(req, session)
    return ResponseModel(
        success=True,
        message="Tenant created",
        data=TenantOut.model_validate(tenant).model_dump(),
    )


@tenants_router.get("", response_model=PaginatedResponse[TenantOut])
async def list_tenants(
    pagination: dict = Depends(pagination_params),
    session: Session = Depends(get_session),
):
    """List all tenants. SUPER_ADMIN only."""
    tenants, total = await TenantService.list_tenants(
        session, skip=pagination["skip"], limit=pagination["limit"]
    )
    return PaginatedResponse.build(
        items=[TenantOut.model_validate(t) for t in tenants],
        total=total,
        page=pagination["page"],
        page_size=pagination["page_size"],
    )


@tenants_router.get("/{tenant_id}", response_model=ResponseModel)
async def get_tenant(
    tenant_id: UUID,
    session: Session = Depends(get_session),
):
    tenant = await TenantService.get_tenant(tenant_id, session)
    return ResponseModel(success=True, data=TenantOut.model_validate(tenant).model_dump())


# Stores

stores_router = APIRouter(prefix="/stores", tags=["Pharmacy Stores"])


@stores_router.post(
    "",
    response_model=ResponseModel,
    dependencies=[Depends(require_tenant_admin())],
)
async def create_store(
    req: CreateStoreRequest,
    ctx: TenantContext = Depends(),
    session: Session = Depends(get_session),
):
    """Create a new pharmacy store/branch within your tenant."""
    tenant_id = ctx.require_tenant()
    store = await StoreService.create_store(req, tenant_id, session)
    return ResponseModel(
        success=True,
        message="Store created",
        data=StoreOut.model_validate(store).model_dump(),
    )


@stores_router.get(
    "",
    response_model=PaginatedResponse[StoreOut],
    dependencies=[Depends(require_store_manager())],
)
async def list_stores(
    ctx: TenantContext = Depends(),
    pagination: dict = Depends(pagination_params),
    session: Session = Depends(get_session),
):
    """List all stores within the current tenant."""
    tenant_id = ctx.require_tenant()
    stores, total = await StoreService.list_stores(
        tenant_id, session, skip=pagination["skip"], limit=pagination["limit"]
    )
    return PaginatedResponse.build(
        items=[StoreOut.model_validate(s) for s in stores],
        total=total,
        page=pagination["page"],
        page_size=pagination["page_size"],
    )


@stores_router.get(
    "/{store_id}",
    response_model=ResponseModel,
    dependencies=[Depends(require_store_manager())],
)
async def get_store(
    store_id: UUID,
    ctx: TenantContext = Depends(),
    session: Session = Depends(get_session),
):
    tenant_id = ctx.require_tenant()
    store = await StoreService.get_store(store_id, tenant_id, session)
    return ResponseModel(success=True, data=StoreOut.model_validate(store).model_dump())


@stores_router.patch(
    "/{store_id}/deactivate",
    response_model=ResponseModel,
    dependencies=[Depends(require_tenant_admin())],
)
async def deactivate_store(
    store_id: UUID,
    ctx: TenantContext = Depends(),
    session: Session = Depends(get_session),
):
    tenant_id = ctx.require_tenant()
    await StoreService.deactivate_store(store_id, tenant_id, session)
    return ResponseModel(success=True, message="Store deactivated")


# Combine into single router 
router.include_router(users_router)
router.include_router(tenants_router)
router.include_router(stores_router)