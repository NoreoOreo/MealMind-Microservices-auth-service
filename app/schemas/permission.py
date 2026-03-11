from typing import Optional

from pydantic import BaseModel


class PermissionBase(BaseModel):
    name: str


class PermissionOut(PermissionBase):
    id: str

    class Config:
        from_attributes = True


class PermissionCreate(PermissionBase):
    pass


class PermissionUpdate(BaseModel):
    name: Optional[str] = None
