Working With Fork Process Models
================================

The `BatchSpanProcessor` uses a background thread to export spans. Forking a
multithreaded process can leave a child with locks held by threads that no longer
exist. The current SDK reinitializes the processor's internal lock, event and
worker thread in the child and clears the inherited span queue. On platforms
that support ``os.register_at_fork``, this happens in an after-fork hook.

This support covers the processor's internal state, not every exporter or its
transport. An exporter may have its own restrictions on sharing connections
across a fork. Initializing the tracer provider, processor and exporter in each
worker avoids inheriting those connections and is a useful approach for manual
instrumentation with pre-fork servers such as Gunicorn and uWSGI.

Opt-in ownership and recovery boundary
--------------------------------------

Applications that need an auditable ownership token can construct either batch
processor with ``enable_process_ownership=True``. Exporters that implement
``ProcessOwnershipAwareExporter`` opt in automatically. The processor exposes
``process_ownership`` and ``process_ownership_boundary``; call
``checkpoint_process_ownership()`` before forking to record how many records
were admitted to the queue but not yet submitted to the exporter.

After a fork, the child detaches its copied queue, increments
``ProcessOwnership.generation`` and stores a ``ForkRecoveryBoundary`` in
``process_ownership_boundary.recovery``. The report's
``inherited_batch_finalizer`` is ``"parent_processor"``. In other words, the
child exports only records admitted in its new process generation; the parent's
original processor remains responsible for flushing and acknowledging the
inherited batch. Records popped into an in-progress exporter call immediately
before the fork are likewise finalized by the surviving parent call, not by the
child.

Exporters can implement ``bind_process_ownership()`` and
``recover_after_fork()`` to reopen process-local files, sessions or
connections. Inside ``export()``, ``current_process_ownership()`` returns the
ownership token for the current batch, which local audit exporters can write
alongside their acknowledgement.

The hooks make process identity and the recovery point observable; they do not
make an inherited network connection safe if the exporter itself does not reset
it. Initializing SDK components in each worker remains the strongest boundary.

The server lifecycle hooks below show how to initialize tracing in each worker.
They are an alternative to configuring tracing in the parent process, rather
than a second initialization step for applications that already configure
tracing through auto-instrumentation.

For signal-specific auto-instrumentation support and workarounds, see the
`Python auto-instrumentation troubleshooting guide
<https://opentelemetry.io/docs/zero-code/python/troubleshooting/#pre-fork-server-issues>`_.

The source code for the examples with Flask app are available :scm_web:`here <docs/examples/fork-process-model/>`.

Gunicorn post_fork hook
-----------------------

.. code-block:: python

    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor


    def post_fork(server, worker):
        server.log.info("Worker spawned (pid: %s)", worker.pid)

        resource = Resource.create(attributes={
            "service.name": "api-service"
        })

        trace.set_tracer_provider(TracerProvider(resource=resource))
        span_processor = BatchSpanProcessor(
            OTLPSpanExporter(endpoint="http://localhost:4317")
        )
        trace.get_tracer_provider().add_span_processor(span_processor)


uWSGI postfork decorator
------------------------

.. code-block:: python

    from uwsgidecorators import postfork

    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor


    @postfork
    def init_tracing():
        resource = Resource.create(attributes={
            "service.name": "api-service"
        })

        trace.set_tracer_provider(TracerProvider(resource=resource))
        span_processor = BatchSpanProcessor(
            OTLPSpanExporter(endpoint="http://localhost:4317")
        )
        trace.get_tracer_provider().add_span_processor(span_processor)
