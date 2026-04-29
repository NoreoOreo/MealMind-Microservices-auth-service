from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from authlib.oauth2.rfc6749.authenticate_client import ClientAuthentication
from authlib.oauth2.rfc6749.errors import InvalidClientError
from authlib.oauth2.rfc6749.requests import BasicOAuth2Payload
from authlib.oauth2.rfc6749.util import extract_basic_authorization
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import OAuthClient
from app.security import verify_password


class _AuthlibClient:
    def __init__(self, client: OAuthClient):
        self.client = client

    def check_client_secret(self, client_secret: str) -> bool:
        if not self.client.client_secret_hash:
            return False
        return verify_password(client_secret, self.client.client_secret_hash)

    def check_endpoint_auth_method(self, method: str, endpoint: str) -> bool:
        if endpoint != "token":
            return False
        if self.client.is_confidential:
            return method in {"client_secret_basic", "client_secret_post"}
        return method == "none"


@dataclass
class _TokenRequest:
    headers: dict[str, str]
    form: dict[str, Any]
    payload: BasicOAuth2Payload
    auth_method: str | None = None


async def authenticate_client(
    session: AsyncSession,
    body: dict[str, Any],
    authorization: str | None,
) -> OAuthClient:
    headers: dict[str, str] = {}
    if authorization:
        headers["authorization"] = authorization

    header_client_id, _ = extract_basic_authorization(headers)
    candidate_ids = {cid for cid in [header_client_id, body.get("client_id")] if cid}

    clients = {}
    if candidate_ids:
        rows = (
            await session.scalars(select(OAuthClient).where(OAuthClient.client_id.in_(list(candidate_ids))))
        ).all()
        clients = {c.client_id: c for c in rows}

    def query_client(client_id: str):
        client = clients.get(client_id)
        if not client:
            return None
        if not client.is_active:
            return None
        return _AuthlibClient(client)

    request = _TokenRequest(headers=headers, form=body, payload=BasicOAuth2Payload(body))
    auth = ClientAuthentication(query_client)
    wrapped = auth(request, methods=["client_secret_basic", "client_secret_post", "none"], endpoint="token")
    if not wrapped:
        raise InvalidClientError(description="The client cannot be authenticated.")
    return wrapped.client
