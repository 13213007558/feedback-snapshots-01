..
  SPDX-FileCopyrightText: SPDX-FileCopyrightText: 2026 CacheControl contributors

  SPDX-License-Identifier: Apache-2.0

=============================================
 Authorization Redirects and Short-Lived URLs
=============================================

Some services expose a *stable* download entry point that responds with a
redirect to a *short-lived* authorized URL, such as a presigned object-store
link that embeds a token and an expiry time::

  GET /download/report
  301 Moved Permanently
  Location: https://storage.example.com/report?token=...&expires=...

Caching that redirect is unsafe: a later caller would be sent a signed URL
that has already expired, or worse, one minted for a different request. The
redirect must still be delivered to the caller that made the request, but it
must not be written to the cache as a reusable entry.

CacheControl lets the application decide which redirects have this property
through the ``authorization_redirect`` callback. It receives the prepared
request and the redirect response and returns ``True`` for redirects that
point at an application-defined, short-lived authorized URL::

  import requests

  from cachecontrol import CacheControl

  def is_authorization_redirect(request, response):
      location = response.headers.get("Location", "")
      return "token=" in location

  sess = CacheControl(
      requests.Session(),
      authorization_redirect=is_authorization_redirect,
  )

When the callback returns ``True``, CacheControl:

* still returns the redirect to the online caller, unchanged, and
* never stores it as a reusable cache entry. If an entry already exists for
  the request URL, it is removed so that a stale signed redirect cannot be
  served later.

Public redirects
================

A redirect that is explicitly marked public must always remain cacheable.
CacheControl therefore checks ``Cache-Control: public`` *before* invoking the
callback: a public redirect is cached using the ordinary rules even when its
``Location`` would otherwise match the authorization-redirect rule::

  301 Moved Permanently
  Cache-Control: public
  Location: https://cdn.example.com/report

This makes the policy opt-in and narrowly scoped: with no
``authorization_redirect`` callback supplied, caching behavior is unchanged,
and only the 3xx responses carrying a ``Location`` header are ever evaluated.

Usage with the adapter
======================

The same option is available directly on
:class:`~cachecontrol.adapter.CacheControlAdapter`::

  from cachecontrol.adapter import CacheControlAdapter

  adapter = CacheControlAdapter(
      authorization_redirect=is_authorization_redirect,
  )
