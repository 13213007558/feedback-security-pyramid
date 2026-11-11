"""New stack: a single ISecurityPolicy replacing the two legacy policies.

The migration keeps three moving parts, each with a 1.x counterpart:

* :class:`pyramid.authentication.AuthTktCookieHelper` replaces the ticket
  parsing/cookie half of ``AuthTktAuthenticationPolicy``.
* :class:`pyramid.authorization.ACLHelper` replaces
  ``ACLAuthorizationPolicy``; resource lineage ACLs are evaluated exactly
  as before.
* :class:`pyramid.request.RequestLocalCache` caches the identity for the
  life of one request only.  It is keyed by a weakref to the request and
  cleared via a finished callback, so it can never leak one request's
  identity into another -- unlike a module-level dict.
"""

from pyramid.authentication import AuthTktCookieHelper
from pyramid.authorization import ACLHelper, Authenticated, Everyone
from pyramid.config import Configurator
from pyramid.interfaces import ISecurityPolicy
from pyramid.request import RequestLocalCache
from zope.interface import implementer

from shared import (
    COOKIE_NAME,
    SECRET,
    configure_views,
    groupfinder,
    root_factory,
)


@implementer(ISecurityPolicy)
class AuthTktSecurityPolicy:
    def __init__(self, secret, cookie_name):
        self.helper = AuthTktCookieHelper(
            secret,
            cookie_name=cookie_name,
            secure=False,
            http_only=True,
        )
        self.acl = ACLHelper()
        self.identity_cache = RequestLocalCache(self._load_identity)

    def _load_identity(self, request):
        """Resolve the trusted identity for one request.

        ``helper.identify`` only proves the cookie is *well-formed and
        unexpired*; its ``userid`` is a claim, the same value the legacy API
        exposed as ``request.unauthenticated_userid``.  It must not be
        treated as an authenticated user until the profile store accepts
        it -- that is what the groupfinder check below does.
        """
        ticket = self.helper.identify(request)
        if ticket is None:
            return None

        userid = ticket['userid']
        # Re-run the same trust decision the legacy callback made.
        # ``None`` means the profile store does not recognise the userid.
        groups = groupfinder(userid, request)
        if groups is None:
            return None

        return {
            'userid': userid,
            'principals': groups,
            'tokens': ticket['tokens'],
        }

    def identity(self, request):
        return self.identity_cache.get_or_create(request)

    def authenticated_userid(self, request):
        identity = self.identity(request)
        if identity is None:
            return None
        return identity['userid']

    def permits(self, request, context, permission):
        # Rebuild the exact principal list CallbackAuthenticationPolicy
        # built for effective_principals(), then defer to the same ACL
        # machinery the old ACLAuthorizationPolicy used.
        principals = {Everyone}
        identity = self.identity(request)
        if identity is not None:
            principals.add(Authenticated)
            principals.add(identity['userid'])
            principals.update(identity['principals'])
        return self.acl.permits(context, principals, permission)

    def remember(self, request, userid, **kw):
        return self.helper.remember(request, userid, **kw)

    def forget(self, request, **kw):
        return self.helper.forget(request, **kw)


def make_app():
    config = Configurator(root_factory=root_factory)
    config.set_security_policy(
        AuthTktSecurityPolicy(SECRET, cookie_name=COOKIE_NAME)
    )
    configure_views(config)
    return config.make_wsgi_app()
