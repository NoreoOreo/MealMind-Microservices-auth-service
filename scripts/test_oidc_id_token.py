#!/usr/bin/env python3
import argparse
import json
import os
import sys
from urllib import request
from urllib.error import HTTPError, URLError

from jose import jwk, jwt
from jose.utils import base64url_decode


def http_json(method: str, url: str, body: dict | None = None) -> dict:
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = request.Request(url=url, data=data, method=method, headers=headers)
    try:
        with request.urlopen(req, timeout=10) as resp:
            payload = resp.read().decode("utf-8")
            return json.loads(payload) if payload else {}
    except HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        print(f"HTTP {exc.code} on {url}")
        print(raw)
        raise
    except URLError as exc:
        print(f"Network error on {url}: {exc}")
        raise


def get_id_token(base_url: str, username: str, password: str, scope: str) -> str:
    token_url = f"{base_url.rstrip('/')}/oauth/token"
    payload = {
        "grant_type": "password",
        "username": username,
        "password": password,
        "scope": scope,
    }
    token_response = http_json("POST", token_url, payload)

    id_token = token_response.get("id_token")
    if not id_token:
        print("No id_token in response.")
        print(json.dumps(token_response, indent=2, ensure_ascii=False))
        raise RuntimeError("id_token is missing. Ensure OIDC is enabled and scope includes 'openid'.")

    return id_token


def verify_id_token(id_token: str, jwks: dict, audience: str | None, issuer: str | None) -> dict:
    header = jwt.get_unverified_header(id_token)
    claims_unverified = jwt.get_unverified_claims(id_token)

    kid = header.get("kid")
    alg = header.get("alg")
    if not kid:
        raise RuntimeError("id_token header does not contain 'kid'.")

    jwk_key = next((key for key in jwks.get("keys", []) if key.get("kid") == kid), None)
    if not jwk_key:
        raise RuntimeError(f"No matching key in JWKS for kid={kid}")

    message, encoded_sig = id_token.rsplit(".", 1)
    decoded_sig = base64url_decode(encoded_sig.encode("utf-8"))
    key = jwk.construct(jwk_key, algorithm=alg)
    if not key.verify(message.encode("utf-8"), decoded_sig):
        raise RuntimeError("Signature verification failed")

    decode_kwargs: dict = {"algorithms": [alg]}
    options = {}
    if audience:
        decode_kwargs["audience"] = audience
    else:
        options["verify_aud"] = False

    if issuer:
        decode_kwargs["issuer"] = issuer

    claims_verified = jwt.decode(id_token, jwk_key, options=options, **decode_kwargs)

    return {
        "header": header,
        "claims_unverified": claims_unverified,
        "claims_verified": claims_verified,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch and verify OIDC id_token, then print token info")
    parser.add_argument("--base-url", default=os.getenv("OIDC_BASE_URL", "http://localhost/api/v1/auth"), help="Auth service base URL")
    parser.add_argument("--username", default=os.getenv("OIDC_TEST_USERNAME", "profile@admin.com"), help="User email/username for password grant")
    parser.add_argument("--password", default=os.getenv("OIDC_TEST_PASSWORD", os.getenv("PROFILE_ADMIN_PASSWORD", "changeme")), help="User password for password grant")
    parser.add_argument("--scope", default=os.getenv("OIDC_SCOPE", "openid profile email"), help="OAuth scope")
    parser.add_argument("--audience", default=os.getenv("OIDC_AUDIENCE"), help="Expected id_token audience")
    parser.add_argument("--issuer", default=os.getenv("OIDC_ISSUER", "http://localhost/api/v1/auth"), help="Expected id_token issuer")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    print(
        f"Using base_url={base_url}, username={args.username}, "
        f"scope={args.scope}, audience={args.audience}, issuer={args.issuer}"
    )

    try:
        discovery = http_json("GET", f"{base_url}/.well-known/openid-configuration")
        jwks_uri = discovery.get("jwks_uri", f"{base_url}/.well-known/jwks.json")
        print("OpenID discovery:")
        print(json.dumps(discovery, indent=2, ensure_ascii=False))

        id_token = get_id_token(base_url, args.username, args.password, args.scope)
        print("\nid_token:")
        print(id_token)

        jwks = http_json("GET", jwks_uri)
        verified = verify_id_token(id_token, jwks, args.audience, args.issuer)

        print("\nDecoded/verified token info:")
        print(json.dumps(verified, indent=2, ensure_ascii=False))
        print("\nOK: id_token signature and claims are valid.")
        return 0
    except Exception as exc:
        print(f"\nFAIL: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
