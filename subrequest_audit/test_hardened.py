import io

import pytest

from subrequest_audit.app import AUDIT
from subrequest_audit.hardened import make_app


def _call(app, path, user=None):
    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": path,
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "80",
        "wsgi.url_scheme": "http",
        "wsgi.input": io.BytesIO(b""),
        "wsgi.errors": __import__("sys").stderr,
    }
    if user:
        environ["HTTP_X_USER"] = user
    status = {}
    body = b"".join(
        app(environ, lambda s, h, exc_info=None: status.update(s=s))
    )
    return status["s"], body


@pytest.fixture()
def app():
    AUDIT.clear()
    return make_app()


def test_anonymous_outer_is_denied_at_internal_view(app):
    status, body = _call(app, "/public")
    assert status.startswith("403")
    assert b"internal call denied" in body


def test_admin_outer_reaches_internal_view_with_propagated_identity(app):
    status, body = _call(app, "/public", user="admin")
    assert status.startswith("200")
    assert b"admin_only" in body
    assert b'"identity": "admin"' in body


def test_anonymous_direct_hit_on_internal_route_denied(app):
    status, _ = _call(app, "/internal/admin-only")
    assert status.startswith("403")


def test_non_admin_direct_hit_denied(app):
    status, _ = _call(app, "/internal/admin-only", user="bob")
    assert status.startswith("403")


def test_security_boundary_does_not_depend_on_the_tween(app):
    # The hardened tween does no authz at all; denial must still happen.
    assert not any(
        r["event"] == "tween-deny" for r in AUDIT
    )
