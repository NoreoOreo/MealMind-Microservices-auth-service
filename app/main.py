import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.api import auth_router, oauth_router, openid_router, groups_router, permissions_router, health_router
from app.config import get_settings
from app.events import lifespan

settings = get_settings()

# Ensure custom audit events are emitted to container stdout and picked up by Promtail.
logging.getLogger("auth.audit").setLevel(logging.INFO)

app = FastAPI(title="Auth Service", version="0.1.0", lifespan=lifespan)

# register routers
api_prefix = ""
app.include_router(auth_router, prefix=api_prefix)
app.include_router(oauth_router, prefix=api_prefix)
app.include_router(openid_router, prefix=api_prefix)
app.include_router(groups_router, prefix=api_prefix)
app.include_router(permissions_router, prefix=api_prefix)
app.include_router(health_router, prefix=api_prefix)
