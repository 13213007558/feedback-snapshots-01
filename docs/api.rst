=============
Top Level API
=============

This is the user facing API of the SDK. It's exposed as ``sentry_sdk``.
With this API you can implement a custom performance monitoring or error reporting solution.

Initializing the SDK
====================

.. autoclass:: sentry_sdk.client.ClientConstructor
   :members:
   :undoc-members:
   :special-members: __init__
   :noindex:

Capturing Data
==============

.. autofunction:: sentry_sdk.api.capture_event
.. autofunction:: sentry_sdk.api.capture_exception
.. autofunction:: sentry_sdk.api.capture_message


Enriching Events
================

.. autofunction:: sentry_sdk.api.add_attachment
.. autofunction:: sentry_sdk.api.add_breadcrumb
.. autofunction:: sentry_sdk.api.set_context
.. autofunction:: sentry_sdk.api.set_extra
.. autofunction:: sentry_sdk.api.set_level
.. autofunction:: sentry_sdk.api.set_tag
.. autofunction:: sentry_sdk.api.set_user


Performance Monitoring
======================

.. autofunction:: sentry_sdk.api.trace
.. autofunction:: sentry_sdk.api.continue_trace
.. autofunction:: sentry_sdk.api.get_current_span
.. autofunction:: sentry_sdk.api.start_span
.. autofunction:: sentry_sdk.api.start_transaction
.. autofunction:: sentry_sdk.api.update_current_span


Distributed Tracing
===================

.. autofunction:: sentry_sdk.api.get_baggage
.. autofunction:: sentry_sdk.api.get_traceparent


Client Management
=================

.. autofunction:: sentry_sdk.api.is_initialized
.. autofunction:: sentry_sdk.api.get_client


Managing Scope (advanced)
=========================

.. autofunction:: sentry_sdk.api.configure_scope
.. autofunction:: sentry_sdk.api.push_scope

.. autofunction:: sentry_sdk.api.new_scope


Project Routing
===============

.. autoclass:: sentry_sdk.projects.ProjectRouter
   :members:

.. autoclass:: sentry_sdk.projects.ProjectTransport
   :members:

.. autoclass:: sentry_sdk.projects.MemoryTransport
   :members:

A service that collects events for several customers, each with its own
configured transport, registers every approved project once and binds the
request or background task to the project that must receive its events::

    import sentry_sdk
    from sentry_sdk.projects import MemoryTransport, ProjectRouter

    router = ProjectRouter()
    router.register("customer-a", MemoryTransport())
    router.register("customer-b", MemoryTransport())

    def handle_request(customer):
        with router.scope(customer):
            sentry_sdk.capture_message("request failed")

Events without a binding, or with a customer that was never registered, are
not sent anywhere. The default project only receives events captured inside
``router.scope("default")``.

If a project's transport cannot send, its events stay queued on that project's
transport. ``router.retry("customer-a")`` retries only that project's queue;
its events never move to another project or to the default project.
