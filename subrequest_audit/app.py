"""Minimal Pyramid app: tween-based auth vs framework-enforced permission.

Layout
------
/public/loose        outer view (no permission); invokes /internal/loose
/public/protected    outer view (no permission); invokes /internal/protected
/internal/loose      protected ONLY by the tween (no view permission) -- the
                     team's assumption
/internal/protected  protected by permission='admin' on the view, enforced by
                     the security policy inside the main router handler
/broken              view that raises; an exception view is registered
/nested              view that itself fires a subrequest to /internal/loose
"""

from pyramid.config import Configurator
from pyramid.httpexceptions import HTTPForbidden
from pyramid.request import Request
from pyramid.security import Allowed, Denied
from pyramid.threadlocal import get_current_request


AUDIT = []


def log(event, request):
    AUDIT.append(
        {
            "event": event,
            "id": id(request),
            "path": request.path_info,
            "identity": getattr(request, "identity", None),
            "current_id": id(get_current_request()),
        }
    )


class HeaderSecurityPolicy:
    """Identity comes from X-User; admins get the admin permission."""

    def identity(self, request):
        return request.headers.get("X-User")

    def permits(self, request, context, permission):
        identity = self.identity(request)
        if permission == "__no_permission_required__":
            return Allowed("public view")
        if identity == "admin":
            return Allowed("admin role")
        if identity is None:
            return Denied("no credentials")
        return Denied(f"user {identity!r} lacks {permission!r}")

    def remember(self, request, userid, **kw):
        return []

    def forget(self, request, **kw):
        return []


def auth_tween_factory(handler, registry):
    """Where the team put authz: deny anything not carrying X-User: admin."""

    def tween(request):
        log("tween-enter", request)
        if request.headers.get("X-User") != "admin":
            log("tween-deny", request)
            # Return the response directly: this tween sits OUTSIDE the
            # excview tween in the default chain, so raising here would bypass
            # registered exception/forbidden views entirely.
            return HTTPForbidden("tween says: admin only")
        response = handler(request)
        log("tween-exit", request)
        return response

    return tween


def _sub(request, path, use_tweens):
    sub = Request.blank(path)
    # Outer credentials are NOT copied on purpose: the subrequest presents
    # its own identity (anonymous here), which is the realistic bypass case.
    return request.invoke_subrequest(sub, use_tweens=use_tweens)


def public_loose(request):
    log("view:public_loose", request)
    before = id(get_current_request())
    try:
        response = _sub(request, "/internal/loose", use_tweens=request.use_tweens)
        result = response.text
    except Exception as exc:  # surfaced to caller when tweens are skipped
        result = f"subrequest raised {type(exc).__name__}: {exc}"
    after = id(get_current_request())
    assert before == after == id(request), "outer request not restored!"
    return {
        "outer_identity": request.identity,
        "subrequest_result": result,
        "outer_request_restored": before == after == id(request),
    }


def public_protected(request):
    log("view:public_protected", request)
    before = id(get_current_request())
    try:
        response = _sub(
            request, "/internal/protected", use_tweens=request.use_tweens
        )
        result = response.text
    except HTTPForbidden as exc:
        result = f"HTTPForbidden: {exc}"
    after = id(get_current_request())
    assert before == after == id(request), "outer request not restored!"
    return {
        "outer_identity": request.identity,
        "subrequest_result": result,
        "outer_request_restored": before == after == id(request),
    }


def public_protected_admincreds(request):
    """Subrequest presents its OWN admin credentials (explicit propagation)."""
    log("view:public_protected_admincreds", request)
    sub = Request.blank("/internal/protected", headers={"X-User": "admin"})
    response = request.invoke_subrequest(sub, use_tweens=False)
    return Response_json(
        {
            "outer_identity": request.identity,
            "subrequest_result": response.json,
        }
    )


def internal_loose(request):
    # No permission= configured: the ONLY thing protecting this view is the
    # tween. Note whose identity the policy sees on THIS request.
    log("view:internal_loose", request)
    return Response_json(
        {
            "view": "internal_loose",
            "identity_seen_by_view": request.identity,
            "current_request_is_self": id(get_current_request()) == id(request),
        }
    )


def internal_protected(request):
    log("view:internal_protected", request)
    return Response_json(
        {
            "view": "internal_protected",
            "identity_seen_by_view": request.identity,
        }
    )


def broken_view(request):
    log("view:broken", request)
    raise ValueError("boom in subrequest")


def exc_view(exc, request):
    log("exception-view", request)
    request.response.status_int = 500
    request.response.text = "handled by exception view"
    return request.response


def forbidden_view(exc, request):
    log("forbidden-view", request)
    request.response.status_int = 403
    request.response.text = f"forbidden: {exc}"
    return request.response


def nested_view(request):
    """A subrequest that fires its own subrequest (both use_tweens=False)."""
    log("view:nested", request)
    inner = Request.blank("/internal/loose")
    response = request.invoke_subrequest(inner, use_tweens=False)
    return Response_json(
        {
            "view": "nested",
            "identity_seen_by_view": request.identity,
            "inner": response.json,
            "current_request_is_self": id(get_current_request()) == id(request),
        }
    )


def public_nested(request):
    log("view:public_nested", request)
    before = id(get_current_request())
    sub = Request.blank("/nested")
    response = request.invoke_subrequest(sub, use_tweens=request.use_tweens)
    after = id(get_current_request())
    assert before == after == id(request)
    return Response_json(
        {
            "outer_identity": request.identity,
            "nested": response.json,
            "outer_request_restored": before == after == id(request),
        }
    )


def public_broken(request):
    log("view:public_broken", request)
    before = id(get_current_request())
    sub = Request.blank("/broken")
    try:
        response = request.invoke_subrequest(sub, use_tweens=request.use_tweens)
        result = response.text
    except ValueError as exc:
        result = f"ValueError propagated: {exc}"
    after = id(get_current_request())
    assert before == after == id(request)
    return Response_json(
        {
            "outer_identity": request.identity,
            "subrequest_result": result,
            "outer_request_restored": before == after == id(request),
        }
    )


def public_broken_with_creds(request):
    """Same as public_broken, but the subrequest carries admin creds so the
    auth tween passes and the excview tween gets a chance to run."""
    log("view:public_broken_with_creds", request)
    sub = Request.blank("/broken", headers={"X-User": "admin"})
    response = request.invoke_subrequest(sub, use_tweens=True)
    return Response_json(
        {
            "outer_identity": request.identity,
            "subrequest_result": response.text,
        }
    )


def Response_json(payload):
    from pyramid.response import Response
    import json

    return Response(
        json.dumps(payload),
        content_type="application/json",
        charset="utf-8",
    )


def make_app():
    with Configurator() as config:
        config.set_security_policy(HeaderSecurityPolicy())
        config.add_tween("subrequest_audit.app.auth_tween_factory")

        config.add_route("public_loose", "/public/loose")
        config.add_view(
            public_loose, route_name="public_loose", renderer="json"
        )

        config.add_route("public_protected", "/public/protected")
        config.add_view(
            public_protected, route_name="public_protected", renderer="json"
        )

        config.add_route(
            "public_protected_admincreds", "/public/protected-admin-creds"
        )
        config.add_view(
            public_protected_admincreds,
            route_name="public_protected_admincreds",
            renderer="json",
        )

        config.add_route("internal_loose", "/internal/loose")
        # NOTE: no permission argument -- tween-only protection.
        config.add_view(
            internal_loose, route_name="internal_loose", renderer="json"
        )

        config.add_route("internal_protected", "/internal/protected")
        config.add_view(
            internal_protected,
            route_name="internal_protected",
            permission="admin",
            renderer="json",
        )

        config.add_route("broken", "/broken")
        config.add_view(broken_view, route_name="broken")
        config.add_view(exc_view, context=ValueError)
        config.add_view(forbidden_view, context=HTTPForbidden)

        config.add_route("nested", "/nested")
        config.add_view(nested_view, route_name="nested", renderer="json")

        config.add_route("public_nested", "/public/nested")
        config.add_view(
            public_nested, route_name="public_nested", renderer="json"
        )

        config.add_route("public_broken", "/public/broken")
        config.add_view(
            public_broken, route_name="public_broken", renderer="json"
        )

        config.add_route(
            "public_broken_with_creds", "/public/broken-with-creds"
        )
        config.add_view(
            public_broken_with_creds,
            route_name="public_broken_with_creds",
            renderer="json",
        )

        config.add_request_method(
            lambda request: request.params.get("use_tweens") == "1",
            name="use_tweens",
            property=True,
            reify=True,
        )
        return config.make_wsgi_app()
