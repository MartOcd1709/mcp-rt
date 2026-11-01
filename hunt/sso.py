"""Single Sign-On (OIDC) for the dashboard — enterprises log in with their existing IdP.

Provider-agnostic OpenID Connect (Google, Okta, Azure AD, Auth0, …). Enabled only when the
OIDC env vars are set; otherwise the dashboard stays on API-token auth. A successful login
provisions/looks up the user in a configured org and puts {email, org_id, role} in the session,
which the webapp's auth() accepts exactly like an API token (same RBAC).

Config (env):
  OIDC_ISSUER          e.g. https://accounts.google.com  (its /.well-known/openid-configuration)
  OIDC_CLIENT_ID       OAuth client id from the IdP
  OIDC_CLIENT_SECRET   OAuth client secret
  OIDC_ORG_ID          org new SSO users join (default 1)
  OIDC_DEFAULT_ROLE    role for a first-time SSO user (default "member")
"""
from __future__ import annotations

import os


def sso_config() -> dict | None:
    """Return the OIDC config if fully set, else None (SSO disabled)."""
    issuer = os.getenv("OIDC_ISSUER")
    cid = os.getenv("OIDC_CLIENT_ID")
    secret = os.getenv("OIDC_CLIENT_SECRET")
    if not (issuer and cid and secret):
        return None
    return {"issuer": issuer.rstrip("/"), "client_id": cid, "client_secret": secret,
            "org_id": int(os.getenv("OIDC_ORG_ID", "1")),
            "default_role": os.getenv("OIDC_DEFAULT_ROLE", "member")}


def provision_sso_user(store, org_id: int, email: str, default_role: str) -> str:
    """Return the role for an SSO user, creating them in the org on first login. Pure + testable."""
    for u in store.list_users(org_id):
        if u.email == email:
            return u.role
    store.add_user(org_id, email, default_role)
    return default_role


def configure_sso(app, store) -> bool:
    """Wire /auth/login, /auth/callback, /auth/logout if OIDC is configured. Returns enabled?."""
    cfg = sso_config()
    if cfg is None:
        return False
    from authlib.integrations.starlette_client import OAuth
    from starlette.responses import JSONResponse, RedirectResponse

    oauth = OAuth()
    oauth.register(
        name="oidc",
        server_metadata_url=f"{cfg['issuer']}/.well-known/openid-configuration",
        client_id=cfg["client_id"], client_secret=cfg["client_secret"],
        client_kwargs={"scope": "openid email profile"},
    )

    @app.get("/auth/login")
    async def login(request):
        return await oauth.oidc.authorize_redirect(request, request.url_for("auth_callback"))

    @app.get("/auth/callback", name="auth_callback")
    async def auth_callback(request):
        token = await oauth.oidc.authorize_access_token(request)
        info = token.get("userinfo") or {}
        email = info.get("email")
        if not email:
            return JSONResponse({"error": "identity provider returned no email"}, status_code=400)
        role = provision_sso_user(store, cfg["org_id"], email, cfg["default_role"])
        request.session.update({"email": email, "org_id": cfg["org_id"], "role": role})
        return RedirectResponse("/")

    @app.get("/auth/logout")
    def logout(request):
        request.session.clear()
        return RedirectResponse("/")

    return True
