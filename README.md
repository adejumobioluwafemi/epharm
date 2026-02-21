# E-Pharmacy Multi-Tenant API

## Architecture Overview

### Tenant Hierarchy
```
Platform (SUPER_ADMIN)
  └── Tenant (Pharmacy Company)        ← tenant_id
        └── PharmacyStore (Branch)     ← store_id
              ├── Staff (UserRole)
              ├── Inventory (future)
              └── Orders (future)
```

### Tenant Isolation Strategy
Every business table carries `tenant_id`. Store-specific tables also carry `store_id`.
All queries in service layers are filtered by `tenant_id` extracted from the JWT.
No cross-tenant data leakage is possible because the JWT is the single source of truth for scope.

### JWT Structure
```json
{
  "sub":       "<user_uuid>",
  "email":     "user@example.com",
  "user_type": "STAFF",
  "tenant_id": "<tenant_uuid>",
  "store_ids": ["<store_uuid>", "..."],
  "roles":     ["STORE_MANAGER"],
  "iss": "epharm-api",
  "aud": "epharm-frontend",
  "iat": 1234567890,
  "exp": 1234571490
}
```

### Role-Permission Matrix
| Role             | Scope          | Capabilities                                      |
|------------------|----------------|---------------------------------------------------|
| SUPER_ADMIN      | Platform-wide  | Create tenants, all operations                    |
| TENANT_ADMIN     | Tenant-wide    | Create stores, manage all staff, assign roles     |
| STORE_MANAGER    | Store-scoped   | Register staff, view all store data               |
| PHARMACIST       | Store-scoped   | Dispense, manage prescriptions                    |
| CASHIER          | Store-scoped   | Process sales, view inventory                     |
| INVENTORY_CLERK  | Store-scoped   | Manage stock, receive orders                      |
| RIDER            | Tenant-scoped  | Delivery management                               |
| PATIENT          | Self           | Place orders, view own prescriptions              |

### Password Security
- Passwords are hashed with **bcrypt** after being salted with a 64-char random hex salt.
- Salt is stored alongside the hash in the `users` table.
- Formula: `bcrypt(salt + plain_password)` — each user has a unique salt.
- Refresh tokens are stored as SHA-256 hashes (never raw).
- Access tokens are stored per-user for single-session enforcement (revocation).

### API Naming Conventions
```
GET    /api/v1/users                     # list (paginated)
POST   /api/v1/users                     # create
GET    /api/v1/users/{id}               # get one
PATCH  /api/v1/users/{id}               # partial update
DELETE /api/v1/users/{id}               # soft delete

POST   /api/v1/auth/login
POST   /api/v1/auth/logout
POST   /api/v1/auth/refresh
POST   /api/v1/auth/register
POST   /api/v1/auth/forgot-password
POST   /api/v1/auth/reset-password
GET    /api/v1/auth/validate-reset-token
POST   /api/v1/auth/change-password
GET    /api/v1/auth/me
POST   /api/v1/auth/roles/assign
DELETE /api/v1/auth/roles/revoke

GET    /api/v1/tenants                  # SUPER_ADMIN only
POST   /api/v1/tenants
GET    /api/v1/tenants/{id}

POST   /api/v1/stores
GET    /api/v1/stores
GET    /api/v1/stores/{id}
```

### Pagination
All list endpoints use `?page=1&page_size=20` query params.
Response envelope:
```json
{
  "success": true,
  "data": [...],
  "total": 150,
  "page": 1,
  "page_size": 20,
  "total_pages": 8
}
```

---

## Project Structure
```
epharm/
├── main.py                    # FastAPI entry point
├── seed.py                    # DB seeder (roles, super admin, demo data)
├── alembic/                   # Database migrations
│   ├── env.py
│   ├── script.py.mako
│   └── versions/
├── src/
│   ├── core/
│   │   ├── config.py          # Settings from .env
│   │   ├── database.py        # Engine, session, init_db
│   │   ├── security.py        # bcrypt+salt, JWT creation/decode
│   │   └── dependencies.py    # FastAPI deps: auth, RBAC, tenant context, pagination
│   ├── shared/
│   │   ├── models.py          # All SQLModel ORM models
│   │   └── schemas.py         # Shared response schemas (ResponseModel, PaginatedResponse)
│   ├── auth/
│   │   ├── schemas.py         # Auth request/response schemas
│   │   ├── services.py        # Auth business logic
│   │   └── router.py          # Auth endpoints
│   ├── users/
│   │   ├── schemas.py         # User/Tenant/Store schemas
│   │   ├── services.py        # CRUD services (tenant-isolated)
│   │   └── router.py          # User, Tenant, Store endpoints
│   └── email/
│       ├── config.py          # Email settings
│       ├── schemas.py         # Email data schemas
│       └── service.py         # Resend-based email service
├── requirements.txt
├── .env.example
└── alembic.ini
```

---

## Setup

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure environment
```bash
cp .env.example .env
# Edit .env with your DB credentials, JWT secret, Resend key
```

### 3. Run migrations
```bash
alembic revision --autogenerate -m "initial"
alembic upgrade head
```

### 4. Seed database
```bash
python seed.py
```

### 5. Start the API
```bash
uvicorn main:app --reload
# or
python main.py
```

### 6. Access docs
Open `http://localhost:8000/docs`

---

## Week 1 Deliverables ✅
- [x] FastAPI project initialized
- [x] PostgreSQL + SQLModel + Alembic configured
- [x] Core tables: `tenants`, `pharmacy_stores`, `users`, `roles`, `user_roles`, `staff_profiles`
- [x] Seeder: super admin, demo tenant, demo store, all roles
- [x] Architecture document (this README)
- [x] Tenant-aware DB foundation

## Week 2 Deliverables ✅
- [x] `/auth/register` — staff registration (manager+)
- [x] `/auth/login` — email/phone + bcrypt+salt verification
- [x] `/auth/refresh` — refresh token rotation
- [x] `/auth/logout` — token revocation
- [x] `/auth/forgot-password`, `/auth/reset-password`, `/auth/change-password`
- [x] User CRUD (tenant-filtered)
- [x] Role assignment / revocation endpoints
- [x] Tenant filtering on all user queries
- [x] TenantContext middleware dep for automatic isolation
- [x] JWT with tenant_id, store_ids, roles
- [x] RBAC dependency factories (require_roles, require_tenant_admin, etc.)
- [x] Email notifications (welcome, reset, locked, changed)
- [x] Pagination on all list endpoints