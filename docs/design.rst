Design
------

Waitress uses a combination of asynchronous and synchronous code to do its job.
It handles I/O to and from clients using the :term:`wasyncore`, which is :term:`asyncore` vendored into Waitress.
It services requests via threads.

.. note::
    :term:`asyncore` has been deprecated since Python 3.6.
    Work continues on its inevitable removal from the Python standard library.
    Its recommended replacement is :mod:`asyncio`.

    Although :term:`asyncore` has been vendored into Waitress as :term:`wasyncore`, you may see references to "asyncore" in this documentation's code examples and API.
    The terms are effectively the same and may be used interchangeably.

The :term:`wasyncore` module:

- Uses the ``select.select`` function to wait for connections from clients
  and determine if a connected client is ready to receive output.

- Creates a channel whenever a new connection is made to the server.

- Executes methods of a channel whenever it believes data can be read from or
  written to the channel.

A "channel" is created for each connection from a client to the server.  The
channel handles all requests over the same connection from that client.  A
channel will handle some number of requests during its lifetime: zero to how
ever many HTTP requests are sent to the server by the client over a single
connection.  For example, an HTTP/1.1 client may issue a theoretically
infinite number of requests over the same connection; each of these will be
handled by the same channel.  An HTTP/1.0 client without a "Connection:
keep-alive" header will request usually only one over a single TCP
connection, however, and when the request has completed, the client
disconnects and reconnects (which will create another channel).  When the
connection related to a channel is closed, the channel is destroyed and
garbage collected.

When a channel determines the client has sent at least one full valid HTTP
request, it schedules a "task" with a "thread dispatcher".  The thread
dispatcher maintains a fixed pool of worker threads available to do client
work (by default, 4 threads).  If a worker thread is available when a task is
scheduled, the worker thread runs the task.  The task has access to the
channel, and can write back to the channel's output buffer.  When all worker
threads are in use, scheduled tasks will wait in a queue for a worker thread
to become available.

I/O is always done asynchronously (by :term:`wasyncore`) in the main thread.
Worker threads never do any I/O.
This means that

#.  a large number of clients can be connected to the server at once, and
#.  worker threads will never be hung up trying to send data to a slow client.

No attempt is made to kill a "hung thread".  It's assumed that when a task
(application logic) starts that it will eventually complete.  If for some
reason WSGI application logic never completes and spins forever, the worker
thread related to that WSGI application will be consumed "forever", and if
enough worker threads are consumed like this, the server will stop responding
entirely.

Periodic maintenance is done by the main thread (the thread handling I/O).
If a channel hasn't sent or received any data in a while, the channel's
connection is closed, and the channel is destroyed.

Request body buffering and ``wsgi.input`` lifetime
--------------------------------------------------

When a client sends a request body, Waitress buffers it before the WSGI
application runs.  Small bodies are kept in memory.  Once the buffered
data grows past the ``inbuf_overflow`` adjustment, the buffer spills over
into an unnamed temporary file created with
:func:`tempfile.TemporaryFile`; the file has no directory entry and is
deleted by the operating system as soon as its file handle is closed.

``environ["wsgi.input"]`` is a read handle onto that buffer.  It is valid
only while the request is being serviced: once the task for the request
has finished, Waitress closes the buffer.  Any reference the application
keeps to ``wsgi.input`` beyond that point is dead, and reading it raises
``ValueError``.  Applications that need the body later must copy the
bytes they need while the request is being serviced.

Each request gets its own buffer.  Buffers are never shared or reused
between requests, including pipelined requests on a single connection,
and including requests that are rejected while being parsed: a rejected
request's buffer is closed along with the connection, and its contents
are never handed to a later request.

Two caveats about the temporary file are worth stating explicitly:

- If a connection is torn down abruptly (the client disconnects in the
  middle of an upload, or the channel is cancelled), the partially
  filled buffer is not closed explicitly; its file handle is released
  only when the garbage collector finalizes it.

- Even when the buffer is closed promptly, Waitress does not overwrite
  the data.  The bytes may persist in unallocated disk blocks (or in
  swap) until the operating system reuses them.  Deployments that must
  not let request bodies touch persistent storage should point the
  system temporary directory at a ``tmpfs`` or encrypted volume, or
  raise ``inbuf_overflow`` so that bodies stay in memory.
