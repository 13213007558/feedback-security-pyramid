"""Evidence-gathering verification run.

Run: .venv/bin/python -m subrequest_audit.verify
Each scenario prints: response payload + the ordered audit trail showing
which Request object the tween and the security policy actually saw.
"""

import json

from pyramid.httpexceptions import HTTPForbidden
from pyramid.security import Allowed, Denied
from pyramid.threadlocal import get_current_request

from subrequest_audit.app import AUDIT, HeaderSecurityPolicy, make_app


app = make_app()


def call(path, user=None):
    if "?" in path:
        path_info, query_string = path.split("?", 1)
    else:
        path_info, query_string = path, ""
    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": path_info,
        "QUERY_STRING": query_string,
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "80",
        "wsgi.url_scheme": "http",
        "wsgi.input": __import__("io").BytesIO(b""),
        "wsgi.errors": __import__("sys").stderr,
    }
    if user is not None:
        environ["HTTP_X_USER"] = user
    captured = {}

    def start_response(status, headers, exc_info=None):
        captured["status"] = status
        captured["headers"] = headers

    body = b"".join(app(environ, start_response))
    captured["body"] = body
    return captured


def show(title, path, user=None):
    AUDIT.clear()
    print("=" * 78)
    print(f"SCENARIO: {title}")
    print(f"  GET {path} as {user!r}")
    resp = call(path, user=user)
    print(f"  HTTP {resp['status']}")
    try:
        payload = json.loads(resp["body"])
        print("  payload:", json.dumps(payload, ensure_ascii=False, indent=4))
    except Exception:
        print("  body:", resp["body"][:200])
    print("  audit trail (ordered):")
    for row in AUDIT:
        mark = "self" if row["id"] == row["current_id"] else "OUTER"
        print(
            f"    - {row['event']:<22} path={row['path']:<20} "
            f"identity={row['identity']!r:<8} get_current_request={mark}"
        )
    print()
    return resp, list(AUDIT)


def main():
    results = {}

    # 0. Baseline: tween does protect a direct, anonymous request.
    resp, _ = show("0. direct anonymous hit -> tween must block", "/internal/loose")
    results["direct_anonymous_blocked"] = resp["status"].startswith("403")

    # 1. Subrequest, use_tweens=False (the default): tween bypassed.
    resp, trail = show(
        "1a. outer=admin -> /internal/loose, use_tweens=False (DEFAULT)",
        "/public/loose",
        user="admin",
    )
    payload = json.loads(resp["body"])
    results["default_tween_skipped"] = not any(
        r["event"].startswith("tween") and r["path"] == "/internal/loose"
        for r in trail
    )
    results["default_loose_view_reached_anon"] = (
        payload["subrequest_result"].find("internal_loose") >= 0
    )
    results["default_outer_restored"] = payload["outer_request_restored"]
    results["subrequest_has_own_identity"] = (
        '"identity_seen_by_view": null' in payload["subrequest_result"]
    )

    # 2. Same path with use_tweens=True: tween now sees the subrequest and
    #    blocks it because the subrequest carries no X-User header.
    resp, trail = show(
        "1b. outer=admin -> /internal/loose, use_tweens=True",
        "/public/loose?use_tweens=1",
        user="admin",
    )
    payload = json.loads(resp["body"])
    results["tweens_on_tween_sees_subrequest"] = any(
        r["event"] == "tween-deny" and r["path"] == "/internal/loose"
        for r in trail
    )
    results["tweens_on_blocked"] = payload["subrequest_result"] == ""
    results["tweens_on_outer_restored"] = payload["outer_request_restored"]

    # 3. Permission-protected internal view: framework check applies either way.
    resp, trail = show(
        "2a. outer=admin -> /internal/protected, use_tweens=False",
        "/public/protected",
        user="admin",
    )
    payload = json.loads(resp["body"])
    results["perm_enforced_without_tweens"] = (
        "HTTPForbidden" in payload["subrequest_result"]
    )
    results["perm_outer_restored"] = payload["outer_request_restored"]

    resp, trail = show(
        "2b. subrequest with its OWN admin creds, use_tweens=False",
        "/public/protected-admin-creds",
        user="admin",
    )
    payload = json.loads(resp["body"])
    results["perm_allows_explicit_admin_creds"] = (
        payload["subrequest_result"]["identity_seen_by_view"] == "admin"
    )

    # 4. Exception in subrequest: propagation vs exception view.
    resp, trail = show(
        "3a. subrequest raises, use_tweens=False -> excview tween skipped",
        "/public/broken",
        user="admin",
    )
    payload = json.loads(resp["body"])
    results["exc_propagates_without_tweens"] = (
        "ValueError propagated" in payload["subrequest_result"]
    )
    results["excview_skipped_without_tweens"] = not any(
        r["event"] == "exception-view" for r in trail
    )
    results["exc_outer_restored"] = payload["outer_request_restored"]

    resp, trail = show(
        "3b. subrequest raises, use_tweens=True + own admin creds "
        "-> exception view renders",
        "/public/broken-with-creds",
        user="admin",
    )
    payload = json.loads(resp["body"])
    results["excview_runs_with_tweens"] = (
        "exception view" in payload["subrequest_result"]
    )
    results["excview_tween_present_in_trail"] = any(
        r["event"] == "exception-view" for r in trail
    )
    results["exc_with_tweens_outer_restored"] = (
        resp["status"].startswith("200")
    )

    # 5. Nested subrequests (subrequest firing its own subrequest).
    resp, trail = show(
        "4. nested subrequests, outer use_tweens=False",
        "/public/nested",
        user="admin",
    )
    payload = json.loads(resp["body"])
    results["nested_reaches_loose_view"] = (
        payload["nested"]["inner"]["view"] == "internal_loose"
    )
    results["nested_each_level_restored"] = (
        payload["outer_request_restored"]
        and payload["nested"]["current_request_is_self"]
        and payload["nested"]["inner"]["current_request_is_self"]
    )

    # 6. Direct probe that the policy's permits() is what enforces view
    #    permissions, independent of the tween.
    policy = HeaderSecurityPolicy()
    class FakeReq:
        def __init__(self, user):
            self.headers = {"X-User": user} if user else {}

    results["policy_denies_anonymous"] = isinstance(
        policy.permits(FakeReq(None), None, "admin"), Denied
    )
    results["policy_denies_nonadmin"] = isinstance(
        policy.permits(FakeReq("bob"), None, "admin"), Denied
    )
    results["policy_allows_admin"] = isinstance(
        policy.permits(FakeReq("admin"), None, "admin"), Allowed
    )

    print("#" * 78)
    print("ASSERTION SUMMARY")
    ok = True
    for name, passed in results.items():
        ok &= passed
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
    print("\nALL PASS" if ok else "\nSOME CHECKS FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
