"""Hardened wiring: close every bypass demonstrated in app.py.

Rules applied (each is verifiable in test_audit.py):

1. Authorization lives on the VIEW via permission=, enforced by the
   security policy inside Router.handle_request -> _call_view(secure=True).
   That path runs for subrequests regardless of use_tweens, so it cannot be
   switched off by an app-level invoke_subrequest call.

2. The tween keeps cross-cutting duties (logging, rate limiting) but is NOT
   the security boundary. If it also does authz, that is defense in depth,
   never the only check.

3. Subrequests get a FRESH Request.blank with credentials propagated
   explicitly. The outer request's identity is never silently inherited;
   every hop's identity is visible in the audit log.

4. The calling view re-checks the result defensively: a subrequest is just
   another caller, and "internal" is not a trust level.
"""

from pyramid.config import Configurator
from pyramid.httpexceptions import HTTPForbidden
from pyramid.request import Request
from pyramid.response import Response
from pyramid.security import Allowed, Denied
from pyramid.threadlocal import get_current_request

from subrequest_audit.app import log


class HeaderSecurityPolicy:
    def identity(self, request):
        return request.headers.get("X-User")

    def permits(self, request, context, permission):
        identity = self.identity(request)
        if permission == "__no_permission_required__":
            return Allowed("public")
        if identity == "admin" and permission == "admin":
            return Allowed("admin role")
        return Denied(f"{identity!r} lacks {permission!r}")

    def remember(self, request, userid, **kw):
        return []

    def forget(self, request, **kw):
        return []


def audit_tween_factory(handler, registry):
    """Observability only. Authz is enforced by the policy + view perms."""

    def tween(request):
        log("tween-enter", request)
        try:
            return handler(request)
        finally:
            log("tween-exit", request)

    return tween


def call_internal(request, path, permission):
    """Single choke point for subrequests: explicit creds + re-check."""
    sub = Request.blank(path)
    identity = request.identity
    if identity is not None:
        sub.headers["X-User"] = identity
    try:
        response = request.invoke_subrequest(sub, use_tweens=False)
    except HTTPForbidden:
        return Response(
            json_dumps({"error": "internal call denied", "path": path}),
            status=403,
            content_type="application/json",
            charset="utf-8",
        )
    # Defense in depth: the caller asserts the permission it relies on,
    # evaluated against the subrequest's own identity.
    if not isinstance(_policy.permits(sub, None, permission), Allowed):
        return Response(status=403)
    return response


_policy = HeaderSecurityPolicy()


def json_dumps(payload):
    import json

    return json.dumps(payload)


def public_view(request):
    log("view:public", request)
    before = id(get_current_request())
    response = call_internal(request, "/internal/admin-only", "admin")
    assert id(get_current_request()) == before == id(request)
    return response


def admin_only_view(request):
    log("view:admin_only", request)
    return Response(
        json_dumps(
            {
                "view": "admin_only",
                "identity": request.identity,
                "note": "permission=admin enforced by the security policy",
            }
        ),
        content_type="application/json",
        charset="utf-8",
    )


def make_app():
    with Configurator() as config:
        config.set_security_policy(HeaderSecurityPolicy())
        config.add_tween("subrequest_audit.hardened.audit_tween_factory")

        config.add_route("public", "/public")
        config.add_view(public_view, route_name="public")

        config.add_route("admin_only", "/internal/admin-only")
        config.add_view(
            admin_only_view,
            route_name="admin_only",
            permission="admin",
        )
        return config.make_wsgi_app()
