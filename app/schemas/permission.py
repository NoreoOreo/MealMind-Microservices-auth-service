from typing import Optional

from pydantic import BaseModel


class PermissionBase(BaseModel):
    name: str


class PermissionOut(PermissionBase):
    id: int

    class Config:
        from_attributes = True


class PermissionCreate(PermissionBase):
    pass


class PermissionUpdate(BaseModel):
    name: Optional[str] = None
