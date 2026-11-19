..
  SPDX-FileCopyrightText: SPDX-FileCopyrightText: 2015 Eric Larson

  SPDX-License-Identifier: Apache-2.0

====================
 Using CacheControl
====================

.. important::

    You **must** read the :doc:`security` page before using CacheControl.

CacheControl assumes you are using a `requests.Session` for your
requests. If you are making ad-hoc requests using `requests.get` then
you probably are not terribly concerned about caching.

There are two way to use CacheControl, via the wrapper and the
adapter.


Wrapper
=======

The easiest way to use CacheControl is to utilize the basic
wrapper. Here is an example: ::

  import requests
  import cachecontrol

  sess = cachecontrol.CacheControl(requests.Session())
  resp = sess.get('http://google.com')

This uses the default cache store, a thread safe in-memory dictionary.


Adapter
=======

The other way to use CacheControl is via a requests `Transport
Adapter`_.

Here is how the adapter works: ::

  import requests
  import cachecontrol

  sess = requests.Session()
  sess.mount('http://', cachecontrol.CacheControlAdapter())

  resp = sess.get('http://google.com')


Under the hood, the wrapper method of using CacheControl mentioned
above is the same as this example.


Use a Different Cache Store
===========================

Both the wrapper and adapter classes allow providing a custom cache
store object for storing your cached data. Here is an example using
the provided `FileCache` from CacheControl: ::

  import requests

  from cachecontrol import CacheControl

  # NOTE: This requires filelock be installed
  from cachecontrol.caches import FileCache

  sess = CacheControl(requests.Session(),
                      cache=FileCache('.webcache'))


The `FileCache` will create a directory called `.webcache` and store a
file for each cached request.



Limit How Long Cached Data Is Reused
====================================

CacheControl normally follows the freshness lifetime declared by the
response's ``Cache-Control`` and ``Expires`` headers.  When responses travel
through proxies whose clocks are ahead of the local clock, a ``Date`` in the
future would otherwise make a response look younger than it is.

Set ``max_reusable_age`` (in seconds) to put a hard upper bound on how long
any cached response may be reused, regardless of what its headers claim: ::

  import requests
  import cachecontrol

  sess = cachecontrol.CacheControl(requests.Session(), max_reusable_age=3600)

  # or, when using the adapter directly:
  adapter = cachecontrol.CacheControlAdapter(max_reusable_age=3600)

Freshness is measured from the local time at which the response was
received and includes any ``Age`` header reported upstream.  The bound is
enforced when a cached entry is read; it does not rewrite the ``Date``,
``Age``, ``Cache-Control`` or ``Expires`` headers, so the values the upstream
server sent remain observable.  ``controller.cache_age(response)`` returns
the age CacheControl computed for a response.

A local clock that moves backwards never revives an expired entry or
postpones its expiration: if the wall clock reports a time before the
recorded receive time, the entry is treated as stale.  Entries cached by
older versions have no receive time recorded; when ``max_reusable_age`` is
set, an entry whose ``Date`` is in the future is likewise treated as stale.

.. _Transport Adapter: http://docs.python-requests.org/en/latest/user/advanced/#transport-adapters
