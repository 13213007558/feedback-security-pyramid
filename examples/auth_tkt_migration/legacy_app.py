"""Legacy stack: AuthTktAuthenticationPolicy + ACLAuthorizationPolicy.

This is the Pyramid 1.x wiring that still works (through
:class:`pyramid.security.LegacySecurityPolicy`) but is deprecated.
"""

from pyramid.authentication import AuthTktAuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.config import Configurator

from shared import (
    COOKIE_NAME,
    SECRET,
    configure_views,
    groupfinder,
    root_factory,
)


def make_app():
    authn_policy = AuthTktAuthenticationPolicy(
        SECRET,
        callback=groupfinder,
        cookie_name=COOKIE_NAME,
        # Keep the demo cookie visible over plain in-process HTTP calls.
        secure=False,
        http_only=True,
    )
    authz_policy = ACLAuthorizationPolicy()

    config = Configurator(root_factory=root_factory)
    config.set_authentication_policy(authn_policy)
    config.set_authorization_policy(authz_policy)
    configure_views(config)
    return config.make_wsgi_app()
