from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.api import auth_router, groups_router, permissions_router, health_router
from app.config import get_settings
from app.events import lifespan

settings = get_settings()
app = FastAPI(title="Auth Service", version="0.1.0", lifespan=lifespan)

# register routers
api_prefix = "/api/v1"
app.include_router(auth_router, prefix=api_prefix)
app.include_router(groups_router, prefix=api_prefix)
app.include_router(permissions_router, prefix=api_prefix)
app.include_router(health_router, prefix=api_prefix)
