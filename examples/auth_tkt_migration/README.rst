==============================
AuthTkt Migration Walkthrough
==============================

A runnable side-by-side of the two security styles Pyramid supports:

* **legacy** — :class:`pyramid.authentication.AuthTktAuthenticationPolicy`
  combined with :class:`pyramid.authorization.ACLAuthorizationPolicy`
  (``legacy_app.py``)
* **new** — one object implementing
  :class:`pyramid.interfaces.ISecurityPolicy`, built from
  :class:`pyramid.authentication.AuthTktCookieHelper` and
  :class:`pyramid.authorization.ACLHelper` (``new_app.py``)

Both applications share the same in-memory user profiles, group table,
resource tree, ACL and views (``shared.py``).  All requests are generated
in-process against the WSGI app with WebTest; nothing binds a port, opens
a socket, or talks to a real account system.

Running the example
===================

From the repository root::

    .venv/bin/python examples/auth_tkt_migration/run_demo.py
    .venv/bin/python -m pytest examples/auth_tkt_migration/test_parity.py -v

The driver prints every scenario twice (one row per stack), flags each as
``PARITY`` or ``MISMATCH``, and exits non-zero if any preserved semantic
diverges.  The pytest module contains the same checks as executable
assertions, plus the trust-boundary and cache-isolation tests below.

What is preserved
=================

The ``run_demo.py`` output shows identical results on both stacks for:

* **Anonymous identity.** No cookie, an unparseable cookie, or a ticket for
  an unknown userid all yield ``authenticated_userid is None``,
  ``is_authenticated is False``, and only the ``system.Everyone``-derived
  permissions (``can_view`` is true, everything else false).
* **Authentication failure.** A wrong password returns ``401`` and sets no
  identity; a malformed cookie is silently treated as anonymous rather than
  raising.
* **Group principals.** ``alice`` carries ``group:editors`` and therefore
  passes the ``edit`` permission; ``bob`` has no groups and fails ``edit``
  while keeping the ``view-profile`` permission granted to
  ``system.Authenticated``.
* **Resource ACL inheritance.** ``/doc-1`` is a resource with no
  ``__acl__``; the decision is made against the root ACL through the
  lineage, on both stacks.  The explicit ``(Deny, 'group:banned',
  ALL_PERMISSIONS)`` ACE ahead of the allows also wins for ``carol`` on
  both stacks, proving ACE ordering and deny-first semantics survive.
* **remember/forget headers.** ``remember()`` emits one ``Set-Cookie``
  carrying the auth ticket; ``forget()`` emits an expiring cookie
  (``Max-Age=0``) and the next request is anonymous again.  A ticket issued
  by the legacy app is accepted by the new app and vice-versa, because both
  use the same secret, cookie name and hash algorithm.

Mechanical replacements
=======================

These calls keep their shape and their meaning, and can be swapped without
rethinking trust.  The demo's parity rows are the evidence: the same
request produces the same ``authenticated_userid``, booleans and status
codes on both sides.

==============================================================  ============================================================
Legacy 1.x wiring                                                ISecurityPolicy wiring
==============================================================  ============================================================
``AuthTktAuthenticationPolicy(secret, callback=groupfinder)``   ``AuthTktCookieHelper(secret)`` plus the groupfinder call kept
                                                               inside ``identity()``
``ACLAuthorizationPolicy()``                                    ``ACLHelper()`` called from the policy's ``permits()``
``config.set_authentication_policy(...)`` plus                  ``config.set_security_policy(policy)`` (one registration
``config.set_authorization_policy(...)``                         instead of two)
``authn.remember(request, userid)`` / ``forget(request)``       ``policy.remember/forget``, reached unchanged through
                                                               ``pyramid.security.remember/forget``
``effective_principals`` assembly                               build the same set — ``Everyone``, ``Authenticated``,
                                                               ``userid``, callback groups — inside ``permits()``
==============================================================  ============================================================

``request.authenticated_userid``, ``request.is_authenticated``,
``request.has_permission(...)`` and the ``permission=`` argument to
``add_view`` are unchanged application code.  The views in ``shared.py``
are registered against both stacks with zero edits.

Trust boundaries that need re-understanding
===========================================

Two deprecated request APIs cannot be translated mechanically, because the
new policy deliberately removes the distinction they relied on.

1. ``request.unauthenticated_userid`` is a *claim*, not a user.

   The cookie helper's ``identify()`` only proves the ticket is signed,
   well-formed and unexpired.  The ``userid`` it returns is exactly what
   the old API called ``unauthenticated_userid``: an asserted name that has
   not been checked against the profile store.  The forged-ticket scenario
   demonstrates the trap — a valid ticket for the unknown userid ``ghost``:

   * legacy stack: ``unauthenticated_userid == 'ghost'`` while
     ``authenticated_userid is None`` (the groupfinder callback rejected
     it);
   * new stack: the policy's ``identity()`` runs the same groupfinder check
     and returns ``None``, so there is no channel that ever exposes
     ``'ghost'`` as a current user.

   Rule: never treat the ``identify()`` result (or anything derived from it
   before the profile-store check) as an authenticated identity.  The
   verification step that used to live implicitly in the callback must now
   be written explicitly in ``identity()``.

2. Principals moved from the request into the policy.

   ``request.effective_principals`` has no new equivalent: under a security
   policy it always returns ``['system.Everyone']`` regardless of the
   logged-in user (visible in every authenticated row of the demo output).
   The full principal list now exists only transiently inside
   ``permits()``, where ``identity['principals']`` is combined with
   ``Everyone``, ``Authenticated`` and the userid and handed to
   ``ACLHelper``.  Code that branched on ``effective_principals`` outside
   of a permission check must be re-expressed against
   ``request.identity``; it cannot be renamed one-for-one.

Two related constraints the example enforces deliberately:

* **No cross-request identity cache.** The policy caches ``identity()`` with
  :class:`pyramid.request.RequestLocalCache`, which keys on a weakref to the
  request and drops the entry in a finished callback.  A module-level dict
  keyed by userid would leak one request's identity into another and turn
  the per-request trust decision into process-global state.  The
  ``test_identity_cache_is_request_scoped`` test asserts two different
  request objects get independent identities and that the store is emptied
  when the request finishes.
* **Identity is request-scoped data, not a global.** Both stacks read the
  same in-memory ``USERS``/``GROUPS`` tables, but the resolved identity is
  always recomputed from the current request's ticket.

File map
========

================  ==============================================================
File              Role
================  ==============================================================
``shared.py``     In-memory profiles/groups, groupfinder, resource tree with
                  root ACL and an ACL-less child, login/logout/whoami views
``legacy_app.py`` The deprecated two-policy combination, kept as the baseline
``new_app.py``    The replacement ``ISecurityPolicy`` (helper + ACLHelper +
                  request-local identity cache)
``run_demo.py``   Sends the same eleven request scenarios to both WSGI apps
                  and prints the comparison table
``test_parity.py`` unittest assertions for parity, the untrusted-claim
                  boundary, and cache isolation
================  ==============================================================
