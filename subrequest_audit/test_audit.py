"""Regression tests pinning the security-relevant subrequest behavior.

These tests encode EVIDENCE, not trust: each bypass path is exercised against
the real router so a future Pyramid change or app wiring change would fail.
"""

import io

import pytest

from subrequest_audit.app import AUDIT, make_app


@pytest.fixture()
def wsgi():
    app = make_wsgi = make_app()

    def _call(path, user=None):
        if "?" in path:
            path_info, query = path.split("?", 1)
        else:
            path_info, query = path, ""
        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": path_info,
            "QUERY_STRING": query,
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "80",
            "wsgi.url_scheme": "http",
            "wsgi.input": io.BytesIO(b""),
            "wsgi.errors": __import__("sys").stderr,
        }
        if user is not None:
            environ["HTTP_X_USER"] = user
        status = {}
        body = b"".join(
            app(environ, lambda s, h, exc_info=None: status.update(s=s))
        )
        return status["s"], body

    AUDIT.clear()
    return _call


def test_tween_protects_direct_request(wsgi):
    status, _ = wsgi("/internal/loose")
    assert status.startswith("403")


def test_default_subrequest_skips_tween_and_reaches_tween_only_view(wsgi):
    import json

    status, body = wsgi("/public/loose", user="admin")
    assert status.startswith("200")
    payload = json.loads(body)
    inner = json.loads(payload["subrequest_result"])
    assert inner["view"] == "internal_loose"
    assert inner["identity_seen_by_view"] is None
    sub_tween_events = [
        r for r in AUDIT
        if r["event"].startswith("tween") and r["path"] == "/internal/loose"
    ]
    assert sub_tween_events == []


def test_use_tweens_true_runs_tween_on_the_subrequest(wsgi):
    status, body = wsgi("/public/loose?use_tweens=1", user="admin")
    assert status.startswith("200")
    assert any(
        r["event"] == "tween-deny" and r["path"] == "/internal/loose"
        for r in AUDIT
    )


def test_view_permission_enforced_even_when_tweens_skipped(wsgi):
    status, body = wsgi("/public/protected", user="admin")
    assert status.startswith("200")
    assert b"HTTPForbidden" in body
    assert b"failed permission check" in body
    # The protected view callable itself must never have run.
    assert not any(
        r["event"] == "view:internal_protected" for r in AUDIT
    )


def test_explicit_subrequest_credentials_govern_permission_check(wsgi):
    status, body = wsgi("/public/protected-admin-creds", user="admin")
    assert status.startswith("200")
    assert b'"identity_seen_by_view": "admin"' in body


def test_exception_propagates_without_tweens(wsgi):
    status, body = wsgi("/public/broken", user="admin")
    assert status.startswith("200")
    assert b"ValueError propagated" in body
    assert not any(r["event"] == "exception-view" for r in AUDIT)


def test_exception_view_renders_with_tweens(wsgi):
    status, body = wsgi("/public/broken-with-creds", user="admin")
    assert status.startswith("200")
    assert b"handled by exception view" in body
    assert any(r["event"] == "exception-view" for r in AUDIT)


def test_nested_subrequests_restore_outer_request_each_level(wsgi):
    status, body = wsgi("/public/nested", user="admin")
    assert status.startswith("200")
    assert b'"outer_request_restored": true' in body
    assert b'"current_request_is_self": true' in body
    # No tween events for either nested request.
    assert not any(
        r["event"].startswith("tween")
        and r["path"] in ("/nested", "/internal/loose")
        for r in AUDIT
    )


def test_outer_current_request_restored_after_every_scenario(wsgi):
    for path in (
        "/public/loose",
        "/public/loose?use_tweens=1",
        "/public/protected",
        "/public/broken",
        "/public/nested",
    ):
        status, body = wsgi(path, user="admin")
        assert status.startswith("200"), path
        assert b'"outer_request_restored": true' in body, path
