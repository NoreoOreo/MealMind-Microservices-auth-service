from .auth import router as auth_router
from .groups import router as groups_router
from .permissions import router as permissions_router
from .health import router as health_router

__all__ = ["auth_router", "groups_router", "permissions_router", "health_router"]
