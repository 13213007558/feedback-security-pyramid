"""Run the same requests against both stacks and print the comparison.

Usage (from the repository root)::

    .venv/bin/python examples/auth_tkt_migration/run_demo.py

All requests are in-process WSGI calls via WebTest; nothing binds a port
or talks to a network.
"""

import os
import sys
import warnings

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from webtest import TestApp  # noqa: E402

from pyramid.authentication import AuthTicket  # noqa: E402

import legacy_app  # noqa: E402
import new_app  # noqa: E402
from shared import COOKIE_NAME, GHOST_USERID, SECRET  # noqa: E402

# Fields that must be identical on every scenario.  These are the semantics
# the migration is required to preserve.
PARITY_FIELDS = (
    'authenticated_userid',
    'is_authenticated',
    'can_view',
    'can_edit',
    'can_view_profile',
)

# Fields whose difference is expected and explained in the README.
KNOWN_DIFFERENCES = ('unauthenticated_userid', 'effective_principals')


def fresh_apps():
    # A fresh TestApp per scenario means cookies never leak between cases.
    return TestApp(legacy_app.make_app()), TestApp(new_app.make_app())


def forged_ticket_cookie(userid):
    """Mint a structurally valid ticket for an unknown userid.

    The helper defaults to sha512, so the forged ticket must use the same
    algorithm or it fails parsing and looks like a malformed cookie instead
    of a well-formed claim for an unknown userid.
    """
    ticket = AuthTicket(
        SECRET,
        userid,
        '0.0.0.0',
        cookie_name=COOKIE_NAME,
        hashalg='sha512',
    )
    return f'{COOKIE_NAME}={ticket.cookie_value()}'


def _set_cookie_values(response):
    return [
        value
        for name, value in response.headerlist
        if name.lower() == 'set-cookie'
    ]


def call_whoami(app, extra_cookie=None, expect_errors=False):
    headers = {'Cookie': extra_cookie} if extra_cookie else {}
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter('always')
        response = app.get(
            '/whoami', headers=headers, expect_errors=expect_errors
        )
    body = response.json
    body['_deprecation_warnings'] = sorted(
        {str(w.message).split('.')[0] for w in caught}
    )
    return response.status_int, body


def scenarios():
    """Yield (label, function(app) -> (status, body)) pairs."""

    def anonymous(app):
        return call_whoami(app)

    def bad_login(app):
        response = app.post_json(
            '/login',
            {'userid': 'alice', 'password': 'wrong'},
            expect_errors=True,
        )
        return response.status_int, response.json

    def login_editor(app):
        app.post_json('/login', {'userid': 'alice', 'password': 'alice-pw'})
        return call_whoami(app)

    def login_plain_user(app):
        app.post_json('/login', {'userid': 'bob', 'password': 'bob-pw'})
        return call_whoami(app)

    def login_banned_user(app):
        app.post_json('/login', {'userid': 'carol', 'password': 'carol-pw'})
        return call_whoami(app)

    def forged_unknown_userid(app):
        cookie = forged_ticket_cookie(GHOST_USERID)
        return call_whoami(app, extra_cookie=cookie)

    def malformed_cookie(app):
        return call_whoami(
            app, extra_cookie=f'{COOKIE_NAME}=not-a-valid-ticket'
        )

    def protected_as_anonymous(app):
        response = app.get('/protected', expect_errors=True)
        return response.status_int, response.json

    def protected_as_editor(app):
        app.post_json('/login', {'userid': 'alice', 'password': 'alice-pw'})
        response = app.get('/protected', expect_errors=True)
        return response.status_int, response.json

    def inherited_acl_doc(app):
        # /doc-1 has no __acl__; the decision comes from Root's ACL.
        app.post_json('/login', {'userid': 'alice', 'password': 'alice-pw'})
        response = app.get('/doc-1', expect_errors=True)
        return response.status_int, response.json

    def logout_clears_session(app):
        app.post_json('/login', {'userid': 'alice', 'password': 'alice-pw'})
        response = app.get('/logout')
        after = app.get('/whoami')
        return response.status_int, {
            'logout_set_cookie': _set_cookie_values(response),
            'whoami_after_logout': after.json['parity'],
        }

    return [
        ('anonymous request', anonymous),
        ('bad credentials at login', bad_login),
        ('login as editor (alice)', login_editor),
        ('login as plain user (bob)', login_plain_user),
        ('login as banned user (carol)', login_banned_user),
        ('forged ticket, unknown userid', forged_unknown_userid),
        ('malformed cookie', malformed_cookie),
        ('protected resource, anonymous', protected_as_anonymous),
        ('protected resource, editor', protected_as_editor),
        ('edit on resource inheriting Root ACL', inherited_acl_doc),
        ('forget() on logout', logout_clears_session),
    ]


def cross_stack_flow():
    """A ticket issued by one stack must be accepted by the other."""
    legacy, new = fresh_apps()
    login = legacy.post_json(
        '/login', {'userid': 'alice', 'password': 'alice-pw'}
    )
    ticket = _set_cookie_values(login)[0].split(';', 1)[0]
    accepted = new.get('/whoami', headers={'Cookie': ticket})
    return {
        'ticket_issued_by': 'legacy',
        'ticket_consumed_by': 'new',
        'authenticated_userid': accepted.json['parity'][
            'authenticated_userid'
        ],
        'can_edit': accepted.json['parity']['can_edit'],
    }


def compare(label, legacy_result, new_result):
    legacy_status, legacy_body = legacy_result
    new_status, new_body = new_result
    status_match = legacy_status == new_status
    parity_matches = all(
        legacy_body.get('parity', {}).get(field)
        == new_body.get('parity', {}).get(field)
        for field in PARITY_FIELDS
    )
    return status_match and parity_matches


def main():
    failures = []
    print('=' * 78)
    print('AuthTkt migration: legacy AuthTkt+ACL policies vs ISecurityPolicy')
    print('=' * 78)

    for label, runner in scenarios():
        legacy, new = fresh_apps()
        legacy_result = runner(legacy)
        new_result = runner(new)
        ok = compare(label, legacy_result, new_result)
        if not ok:
            failures.append(label)
        print(f'\n### {label}  [{"PARITY" if ok else "MISMATCH"}]')
        print(
            f'  status:        legacy={legacy_result[0]} new={new_result[0]}'
        )
        if 'parity' in legacy_result[1]:
            for field in PARITY_FIELDS:
                left = legacy_result[1]['parity'][field]
                right = new_result[1]['parity'][field]
                mark = '==' if left == right else '!='
                line = (
                    f'  {field:<22} legacy={left!r:<24} '
                    f'{mark} new={right!r}'
                )
                print(line)
        for field in KNOWN_DIFFERENCES:
            left = legacy_result[1].get('legacy_only', {}).get(field)
            right = new_result[1].get('legacy_only', {}).get(field)
            if left is not None or right is not None:
                print(f'  {field:<22} legacy={left!r}')
                print(f'  {"":<22} new   ={right!r}   (documented difference)')

    print('\n### cross-stack ticket acceptance')
    flow = cross_stack_flow()
    print(f'  {flow}')
    if flow['authenticated_userid'] != 'alice' or not flow['can_edit']:
        failures.append('cross-stack ticket acceptance')

    print('\n' + '-' * 78)
    if failures:
        print(f'FAILED ({len(failures)}): {failures}')
        return 1
    print('All shared scenarios behave identically on both stacks.')
    print('Only deprecated 1.x-only APIs (unauthenticated_userid,')
    print('effective_principals) differ, as documented in README.rst.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
