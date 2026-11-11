"""Executable parity checks for the AuthTkt migration example.

Run either way::

    .venv/bin/python -m pytest examples/auth_tkt_migration/test_parity.py
    .venv/bin/python examples/auth_tkt_migration/test_parity.py

The default repository test run only collects ``tests/`` (see
``pyproject.toml``), so this file does not affect ``pytest`` with no args.
"""

import os
import sys
import unittest
import warnings

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from webtest import TestApp  # noqa: E402

from pyramid.authentication import AuthTicket  # noqa: E402
from pyramid.request import Request  # noqa: E402
import legacy_app  # noqa: E402
import new_app  # noqa: E402
from new_app import AuthTktSecurityPolicy  # noqa: E402
from shared import COOKIE_NAME, GHOST_USERID, SECRET  # noqa: E402


def _forged_cookie(userid):
    ticket = AuthTicket(
        SECRET,
        userid,
        '0.0.0.0',
        cookie_name=COOKIE_NAME,
        hashalg='sha512',
    )
    return f'{COOKIE_NAME}={ticket.cookie_value()}'


class ParityTests(unittest.TestCase):
    """Behaviour that must match on both stacks."""

    def setUp(self):
        self.legacy = TestApp(legacy_app.make_app())
        self.new = TestApp(new_app.make_app())

    def _parity(self, app, cookie=None):
        headers = {'Cookie': cookie} if cookie else {}
        response = app.get('/whoami', headers=headers)
        return response.json['parity']

    def _login(self, app, userid):
        app.post_json(
            '/login', {'userid': userid, 'password': f'{userid}-pw'}
        )

    def test_anonymous_identity(self):
        for app in (self.legacy, self.new):
            parity = self._parity(app)
            self.assertIsNone(parity['authenticated_userid'])
            self.assertFalse(parity['is_authenticated'])
            self.assertTrue(parity['can_view'])
            self.assertFalse(parity['can_edit'])
            self.assertFalse(parity['can_view_profile'])

    def test_login_and_group_principals(self):
        for app in (self.legacy, self.new):
            self._login(app, 'alice')
            parity = self._parity(app)
            self.assertEqual(parity['authenticated_userid'], 'alice')
            self.assertTrue(parity['is_authenticated'])
            # group:editors grants edit via the Root ACL.
            self.assertTrue(parity['can_edit'])
            self.assertTrue(parity['can_view_profile'])

    def test_plain_user_gets_no_edit_principal(self):
        for app in (self.legacy, self.new):
            self._login(app, 'bob')
            parity = self._parity(app)
            self.assertEqual(parity['authenticated_userid'], 'bob')
            self.assertTrue(parity['can_view_profile'])
            self.assertFalse(parity['can_edit'])

    def test_explicit_deny_beats_allow(self):
        for app in (self.legacy, self.new):
            self._login(app, 'carol')
            parity = self._parity(app)
            self.assertEqual(parity['authenticated_userid'], 'carol')
            # group:banned is denied ALL_PERMISSIONS before any Allow ACE.
            self.assertFalse(parity['can_view'])
            self.assertFalse(parity['can_edit'])
            self.assertFalse(parity['can_view_profile'])

    def test_acl_inheritance_on_child_resource(self):
        for app in (self.legacy, self.new):
            self._login(app, 'alice')
            allowed = app.get('/doc-1')
            self.assertEqual(allowed.status_int, 200)
            self._login(app, 'carol')
            denied = app.get('/doc-1', expect_errors=True)
            self.assertEqual(denied.status_int, 403)

    def test_malformed_cookie_is_anonymous(self):
        for app in (self.legacy, self.new):
            parity = self._parity(
                app, cookie=f'{COOKIE_NAME}=garbage'
            )
            self.assertIsNone(parity['authenticated_userid'])
            self.assertFalse(parity['is_authenticated'])

    def test_bad_credentials_are_rejected(self):
        for app in (self.legacy, self.new):
            response = app.post_json(
                '/login',
                {'userid': 'alice', 'password': 'nope'},
                expect_errors=True,
            )
            self.assertEqual(response.status_int, 401)
            self.assertFalse(response.json['ok'])
            self.assertIsNone(self._parity(app)['authenticated_userid'])

    def test_remember_and_forget_headers(self):
        for app in (self.legacy, self.new):
            login = app.post_json(
                '/login', {'userid': 'alice', 'password': 'alice-pw'}
            )
            remember_cookies = [
                value
                for name, value in login.headerlist
                if name.lower() == 'set-cookie'
            ]
            self.assertEqual(len(remember_cookies), 1)
            self.assertIn(f'{COOKIE_NAME}=', remember_cookies[0])

            logout = app.get('/logout')
            forget_cookies = [
                value
                for name, value in logout.headerlist
                if name.lower() == 'set-cookie'
            ]
            self.assertEqual(len(forget_cookies), 1)
            # forget() expires the ticket rather than issuing a new one.
            self.assertIn('Max-Age=0', forget_cookies[0])
            self.assertIsNone(self._parity(app)['authenticated_userid'])

    def test_tickets_are_cross_stack_compatible(self):
        login = self.legacy.post_json(
            '/login', {'userid': 'alice', 'password': 'alice-pw'}
        )
        ticket = login.headers['Set-Cookie'].split(';', 1)[0]
        accepted = self.new.get('/whoami', headers={'Cookie': ticket})
        self.assertEqual(
            accepted.json['parity']['authenticated_userid'], 'alice'
        )
        self.assertTrue(accepted.json['parity']['can_edit'])

        # And in the reverse direction.
        login = self.new.post_json(
            '/login', {'userid': 'bob', 'password': 'bob-pw'}
        )
        ticket = login.headers['Set-Cookie'].split(';', 1)[0]
        accepted = self.legacy.get('/whoami', headers={'Cookie': ticket})
        self.assertEqual(
            accepted.json['parity']['authenticated_userid'], 'bob'
        )


class TrustBoundaryTests(unittest.TestCase):
    """The specific traps called out in the migration notes."""

    def setUp(self):
        self.legacy = TestApp(legacy_app.make_app())
        self.new = TestApp(new_app.make_app())

    def test_unverified_claim_is_not_authenticated(self):
        # A well-formed ticket for a userid the profile store does not know.
        cookie = _forged_cookie(GHOST_USERID)
        for app in (self.legacy, self.new):
            parity = app.get('/whoami', headers={'Cookie': cookie}).json
            self.assertIsNone(
                parity['parity']['authenticated_userid'],
                'a ticket claim must be verified before authentication',
            )
            self.assertFalse(parity['parity']['is_authenticated'])
            self.assertIsNone(parity['identity'])

    def test_legacy_unauthenticated_userid_is_untrusted(self):
        cookie = _forged_cookie(GHOST_USERID)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            legacy_body = self.legacy.get(
                '/whoami', headers={'Cookie': cookie}
            ).json
            new_body = self.new.get(
                '/whoami', headers={'Cookie': cookie}
            ).json

        # The legacy stack exposes the unverified claim separately...
        self.assertEqual(
            legacy_body['legacy_only']['unauthenticated_userid'], GHOST_USERID
        )
        # ...while still refusing to authenticate it.
        self.assertIsNone(legacy_body['parity']['authenticated_userid'])
        # The new security policy has no untrusted channel: it never returns
        # the claim as an authenticated userid.
        self.assertIsNone(
            new_body['legacy_only']['unauthenticated_userid']
        )

    def test_identity_cache_is_request_scoped(self):
        policy = AuthTktSecurityPolicy(SECRET, COOKIE_NAME)

        request_one = Request.blank('/whoami')
        request_one.cookies = {
            COOKIE_NAME: _forged_cookie('alice').split('=', 1)[1]
        }
        request_two = Request.blank('/whoami')  # no cookie

        identity_one = policy.identity(request_one)
        self.assertEqual(identity_one['userid'], 'alice')
        # The second request must not inherit the first request's identity.
        self.assertIsNone(policy.identity(request_two))
        # Repeated access inside request one hits the cache instead of
        # re-parsing the cookie, and returns the very same object.
        self.assertIs(policy.identity(request_one), identity_one)
        # The store is keyed per request object (a WeakKeyDictionary);
        # processing finished callbacks releases the cached entry.
        request_one._process_finished_callbacks()
        request_two._process_finished_callbacks()
        self.assertNotIn(request_one, policy.identity_cache._store)
        self.assertNotIn(request_two, policy.identity_cache._store)


if __name__ == '__main__':
    unittest.main(verbosity=2)
