..
  SPDX-FileCopyrightText: SPDX-FileCopyrightText: 2026 William Woodruff

  SPDX-License-Identifier: Apache-2.0

=======================
Security Considerations
=======================

HTTP caching is a security-sensitive operation. Improper caching and use
of cached data can introduce security vulnerabilities into otherwise secure
applications.

This page will help you decide if you *can* use CacheControl securely
in your application, and if so, how to do so.

CacheControl's security model
=============================

CacheControl's security model is based on the following assumptions:

* CacheControl provides a **private** cache. This means that both shared
  *and* private responses are cached, and the cache is assumed to be accessible only
  to a single logical user. You **cannot** use CacheControl securely
  in a multi-user environment where cached data may be shared between
  different logical users. **Do not** use CacheControl for this;
  it **will** end badly for you.

* You **must** treat cached data as potentially sensitive. CacheControl
  does not natively encrypt or otherwise protect cached data. If an attacker
  can read your cache, they can read all cached responses. You must
  ensure that your cache storage is protected appropriately for the
  sensitivity of the data you are caching. Another framing of this is that
  CacheControl **assumes** the security of your cache storage, similar to
  how browsers assume the security of your local machine for the purpose
  of storing history, cookies, and cached data.

* You **must** trust the origins (i.e., servers)
  you are communicating with. A malicious origin can always send
  you malicious responses, which in the context of caching can mean
  sending you cacheable responses that you don't expect, spamming you
  with cache entries, and so on. In practice, this means that you must
  also trust your transport layer; if you use HTTP, any
  adversary on your network path can tamper with your connected
  origin's responses, and CacheControl has no way to protect you from that.

Conversely, here are some assumptions that CacheControl **does** attempt
to enforce; violating these assumptions would be a security vulnerability in
CacheControl itself:

* An attacker should not be able to trick CacheControl into caching across
  origins. For example, an attacker who controls ``evil.example.com``
  should not be able to trick CacheControl into caching responses for
  ``bank.example.com``.

* An attacker should not be able to trick CacheControl into serving cached
  responses to requests that would not normally receive those cached
  responses. For example, an attacker should not be able to trick
  CacheControl into serving a cached response to an unauthenticated
  request when the cached response was originally received in response
  to an authenticated request.

TLS verification and protected mode
===================================

A single client is sometimes used with different TLS settings: a relaxed
configuration that does not verify the server's identity (for example
``requests``' ``verify=False`` while debugging) and a strict configuration
that does. A response obtained without peer verification is only as trusted
as the network path it traveled over, so it must not be reused by a request
that requires verification.

CacheControl therefore offers an opt-in **protected mode**. Enable it by
passing ``protected=True`` to :func:`cachecontrol.CacheControl` or
:class:`cachecontrol.CacheControlAdapter`:

.. code-block:: python

    import requests
    from cachecontrol import CacheControl

    session = CacheControl(requests.Session(), protected=True)

In protected mode CacheControl records, with every cached entry, whether the
response was received while peer verification was required. It then enforces
the following rules:

* A request that verifies the peer (``verify`` is ``True`` or a path to a CA
  bundle) is served from, or revalidated against, only entries that were
  themselves received while verifying the peer.
* A request that does not verify the peer (``verify=False``) remains able to
  use unverified entries, since it makes no stronger claim about the peer.
* Entries written by older CacheControl versions carry no verification
  information. They are treated as **unverified** and therefore rejected for
  a peer-verifying request, which falls back to contacting the origin. The
  replacement entry then records its verification setting.

When protected mode is off (the default) CacheControl behaves exactly as
before, so existing applications and on-disk caches keep working without
changes.

Reporting security issues
=========================

.. important::

    Please make sure to read the security model above before reporting
    issues. Reports that don't take the security model into account will
    be considered invalid.

We take security reports very seriously, and aim to address them as quickly
as possible.

Please use GitHub's `security advisory process`_ to report security issues.

.. _security advisory process: https://github.com/psf/cachecontrol/security/advisories/new
