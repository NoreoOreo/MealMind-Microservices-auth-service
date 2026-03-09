from typing import List, Optional

from pydantic import BaseModel, Field

from .permission import PermissionOut


class GroupBase(BaseModel):
    name: str


class GroupOut(GroupBase):
    id: str
    permissions: List[PermissionOut] = []

    class Config:
        from_attributes = True


class GroupCreate(GroupBase):
    permissions: Optional[List[str]] = Field(default=None, description="Permission names to attach")


class GroupUpdate(BaseModel):
    name: Optional[str] = None
    permissions: Optional[List[str]] = Field(default=None, description="Permission names to replace with")
