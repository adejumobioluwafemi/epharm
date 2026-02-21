"""
FILE: src/shared/schemas.py
Shared Pydantic schemas — standard response wrappers & pagination
"""

from pydantic import BaseModel
from typing import Any, Generic, List, Optional, TypeVar
from datetime import datetime
from uuid import UUID

T = TypeVar("T")


class ResponseModel(BaseModel):
    """Standard API response envelope."""
    success: bool
    message: Optional[str] = None
    data: Optional[Any] = None


class PaginatedResponse(BaseModel, Generic[T]):
    """Standard paginated response envelope."""
    success: bool = True
    message: Optional[str] = None
    data: List[T] = []
    total: int
    page: int
    page_size: int
    total_pages: int

    @classmethod
    def build(
        cls,
        *,
        items: List[T],
        total: int,
        page: int,
        page_size: int,
        message: Optional[str] = None,
    ) -> "PaginatedResponse[T]":
        import math
        return cls(
            data=items,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=math.ceil(total / page_size) if page_size else 0,
            message=message,
        )