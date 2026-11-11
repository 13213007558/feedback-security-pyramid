"""Shared pieces for the AuthTkt legacy-vs-new security migration example.

Everything here is deliberately in-memory and local:

* ``USERS`` / ``GROUPS`` are plain module-level dictionaries, there is no
  connection to a real account system.
* Requests are generated against the WSGI app in-process (see ``run_demo``
  and ``test_parity``), no socket is ever opened.

The two stacks built in :mod:`legacy_app` and :mod:`new_app` share this
module so that the only variable under comparison is the security wiring.
"""

from pyramid.authorization import (
    ALL_PERMISSIONS,
    Allow,
    Authenticated,
    Deny,
    Everyone,
)
from pyramid.httpexceptions import HTTPForbidden
from pyramid.response import Response
from pyramid.security import forget, remember

# Same secret and cookie name on both stacks: the ticket produced by one
# stack must be readable by the other, proving wire-level compatibility.
SECRET = 'local-demo-secret-not-for-production'
COOKIE_NAME = 'auth_tkt'

# In-memory user profiles: userid -> password.  This stands in for whatever
# real account storage an application has; nothing here performs I/O.
USERS = {
    'alice': {'password': 'alice-pw'},
    'bob': {'password': 'bob-pw'},
    'carol': {'password': 'carol-pw'},
    # A userid that exists in a valid cookie but is unknown to the local
    # profile store.  It lets the demo show that an untrusted ticket claim
    # is not an authenticated identity.  It has no password entry on purpose:
    # the only way to obtain a ``ghost`` ticket is by forging one directly.
}
GHOST_USERID = 'ghost'

# In-memory group membership, keyed by userid.  The legacy ``callback`` and
# the new security policy read the same table so group principals behave
# identically on both sides.
GROUPS = {
    'alice': ['group:editors'],
    'bob': [],
    # An authenticated user hit by an explicit ``Deny`` ACE.
    'carol': ['group:banned'],
}


def groupfinder(userid, request):
    """Legacy-style groupfinder callback.

    Return ``None`` when the userid is not recognised by the profile store
    (the callback contract: ``None`` rejects the claimed identity),
    otherwise return the group principal list (possibly empty).
    """
    if userid not in USERS:
        return None
    return list(GROUPS.get(userid, ()))


class Document:
    """A child resource with no ACL of its own.

    Every permission decision made against it is inherited from :class:`Root`
    through the resource lineage, which is how ACL inheritance is exercised
    in the demo.
    """

    __name__ = 'doc-1'
    __parent__ = None

    def __init__(self, parent):
        self.__parent__ = parent


class Root:
    """Root resource carrying the ACL consulted for every request."""

    __name__ = ''
    __parent__ = None

    __acl__ = [
        # Explicit deny wins over later allows: ``carol`` presents a valid
        # ticket but is still refused, even though she is authenticated.
        (Deny, 'group:banned', ALL_PERMISSIONS),
        (Allow, Everyone, 'view'),
        (Allow, 'group:editors', 'edit'),
        (Allow, Authenticated, 'view-profile'),
    ]

    def __getitem__(self, name):
        if name == 'doc-1':
            return Document(self)
        raise KeyError(name)


def root_factory(request):
    return Root()


def login(request):
    """Validate local credentials and return remember() headers."""
    try:
        payload = request.json_body or {}
    except Exception:
        payload = {}
    userid = payload.get('userid')
    password = payload.get('password')
    profile = USERS.get(userid)
    if profile is None or profile['password'] != password:
        request.response.status = 401
        return {'ok': False, 'error': 'bad credentials'}
    headers = remember(request, userid)
    request.response.headerlist.extend(headers)
    return {'ok': True, 'userid': userid}


def logout(request):
    """Return forget() headers, which expire the auth ticket cookie."""
    headers = forget(request)
    request.response.headerlist.extend(headers)
    return {'ok': True}


def whoami(request):
    """Report everything the two stacks expose for the current request.

    Fields under ``parity`` are expected to match on both stacks for every
    scenario.  Fields under ``legacy_only`` call deprecated 1.x APIs whose
    meaning changed under a security policy; those differences are the
    point of the migration notes, not bugs.
    """
    context = request.context
    return {
        'parity': {
            'authenticated_userid': request.authenticated_userid,
            'is_authenticated': request.is_authenticated,
            'can_view': bool(request.has_permission('view', context)),
            'can_edit': bool(request.has_permission('edit', context)),
            'can_view_profile': bool(
                request.has_permission('view-profile', context)
            ),
        },
        'identity': _safe_identity(request),
        'legacy_only': {
            # Deprecated in Pyramid 2.0: read the README before copying.
            'unauthenticated_userid': request.unauthenticated_userid,
            'effective_principals': request.effective_principals,
        },
        'permits_detail': {
            'view': str(request.has_permission('view', context)),
            'edit': str(request.has_permission('edit', context)),
        },
    }


def _safe_identity(request):
    """Render request.identity as JSON-safe data for both stack shapes."""
    identity = request.identity
    if identity is None:
        return None
    if isinstance(identity, dict):
        return identity
    return {'userid': identity}


def forbidden(request):
    """JSON 403 view so permission denials are readable in the demo output."""
    return HTTPForbidden(json={'ok': False, 'error': 'forbidden'})


def configure_views(config):
    config.add_view(
        login, name='login', renderer='json', request_method='POST'
    )
    config.add_view(logout, name='logout', renderer='json')
    config.add_view(whoami, name='whoami', renderer='json')
    config.add_view(
        lambda ctx, request: Response(json={'ok': True, 'resource': 'doc-1'}),
        name='',
        context=Document,
        renderer='json',
        permission='edit',
    )
    config.add_view(
        lambda ctx, request: Response(json={'ok': True, 'resource': 'root'}),
        name='protected',
        renderer='json',
        permission='view-profile',
    )
    config.add_forbidden_view(forbidden, renderer='json')
