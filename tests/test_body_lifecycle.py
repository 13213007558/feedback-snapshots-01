"""Regression tests for the request body lifecycle.

These tests pin down the security-relevant behavior of request body
buffers:

- bodies larger than ``inbuf_overflow`` are spooled from memory to an
  unnamed temporary file (driven here with a tiny spool threshold and a
  shrunken ``STRBUF_LIMIT`` so the real buffering transitions run against
  small fixtures);
- normal completion, parse rejection, and connection teardown never hand
  a previous request's body bytes to a subsequent request;
- each request owns a distinct buffer and file handle, which is closed
  exactly once when the request is retired on the serviced paths;
- references to ``wsgi.input`` retained after the request has ended are
  dead (reads raise ``ValueError``) on the serviced paths, while on
  abrupt teardown paths the buffer is finalized only by garbage
  collection -- Waitress never overwrites spooled bytes on disk.
"""

import gc
import unittest
from unittest import mock
import weakref

import waitress.buffers
from waitress.adjustments import Adjustments
from waitress.channel import HTTPChannel
from waitress.parser import HTTPRequestParser
from waitress.utilities import BadRequest, RequestEntityTooLarge


def _marker(tag, fill):
    # 96 bytes: well above the shrunken STRBUF_LIMIT (32) used in these
    # tests, so every body takes the strbuf -> BytesIO -> tempfile path.
    return tag + b":" + fill * (96 - len(tag) - 1)


MARKER_ALPHA = _marker(b"MARKER-ALPHA", b"A")
MARKER_BRAVO = _marker(b"MARKER-BRAVO", b"B")
MARKER_CHARLIE = _marker(b"MARKER-CHARLIE", b"C")
MARKER_DELTA = _marker(b"MARKER-DELTA", b"D")
MARKER_ECHO = _marker(b"MARKER-ECHO", b"E")


def post_request(body, path=b"/"):
    return (
        b"POST "
        + path
        + b" HTTP/1.1\r\n"
        + b"Host: example.com\r\n"
        + b"Content-Length: "
        + str(len(body)).encode("ascii")
        + b"\r\n\r\n"
        + body
    )


CHUNKED_HEADERS = (
    b"POST / HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"\r\n"
)


def chunk_frame(data):
    return b"%X\r\n%s\r\n" % (len(data), data)


class TrackedBodyFile:
    """Proxy around a real TemporaryFile that records close calls."""

    def __init__(self, real_file):
        self._real_file = real_file
        self.close_count = 0

    @property
    def closed(self):
        return self._real_file.closed

    def close(self):
        self.close_count += 1
        self._real_file.close()

    def __getattr__(self, name):
        return getattr(self._real_file, name)


class TempfileTracker:
    """Patches tempfile.TemporaryFile and records every file created."""

    def __init__(self):
        self.created = []

    def start(self):
        import tempfile

        real_factory = tempfile.TemporaryFile

        def factory(mode="w+b", *args, **kwargs):
            proxy = TrackedBodyFile(real_factory(mode, *args, **kwargs))
            self.created.append(proxy)
            return proxy

        self._patcher = mock.patch("tempfile.TemporaryFile", factory)
        self._patcher.start()

    def stop(self):
        self._patcher.stop()
        for proxy in self.created:
            if not proxy.closed:
                proxy.close()


class BodyLifecycleTestCase(unittest.TestCase):
    def setUp(self):
        self.tracker = TempfileTracker()
        self.tracker.start()
        self.addCleanup(self.tracker.stop)
        # Shrink the in-memory stages so small fixtures exercise the real
        # transition to a temporary file; inbuf_overflow is set per-parser
        # or per-channel via make_parser/make_channel.
        strbuf_patcher = mock.patch.object(waitress.buffers, "STRBUF_LIMIT", 32)
        strbuf_patcher.start()
        self.addCleanup(strbuf_patcher.stop)

    def make_parser(self, **overrides):
        adj = Adjustments()
        adj.inbuf_overflow = 16
        for name, value in overrides.items():
            setattr(adj, name, value)
        return HTTPRequestParser(adj)

    @staticmethod
    def feed(parser, data):
        # mimic the channel: keep feeding until every byte is consumed
        while data:
            consumed = parser.received(data)
            if consumed == 0:
                break
            data = data[consumed:]
        return data


class TestParserBodyLifecycle(BodyLifecycleTestCase):
    def test_normal_completion_spools_and_close_releases_handle(self):
        parser = self.make_parser()
        self.feed(parser, post_request(MARKER_ALPHA))
        self.assertTrue(parser.completed)
        self.assertIsNone(parser.error)

        buf = parser.body_rcv.getbuf()
        self.assertTrue(buf.overflowed)
        self.assertEqual(len(self.tracker.created), 1)
        proxy = self.tracker.created[0]

        stream = parser.get_body_stream()
        self.assertIs(stream, proxy)
        self.assertGreaterEqual(proxy.fileno(), 0)  # open file handle
        self.assertEqual(stream.read(), MARKER_ALPHA)

        parser.close()
        self.assertEqual(proxy.close_count, 1)
        self.assertTrue(proxy.closed)
        self.assertEqual(len(buf), 0)
        # the file handle is gone: fileno() and reads both fail
        with self.assertRaises(ValueError):
            proxy.fileno()
        with self.assertRaises(ValueError):
            stream.read()

    def test_half_read_body_is_fully_released(self):
        # the application reads only part of the body; the unread
        # remainder must be discarded with the buffer, not leaked onward
        parser = self.make_parser()
        self.feed(parser, post_request(MARKER_ALPHA))
        stream = parser.get_body_stream()
        half = stream.read(len(MARKER_ALPHA) // 2)
        self.assertEqual(half, MARKER_ALPHA[: len(MARKER_ALPHA) // 2])

        parser.close()
        proxy = self.tracker.created[0]
        self.assertEqual(proxy.close_count, 1)
        with self.assertRaises(ValueError):
            stream.read()

        # the next request gets a fresh buffer containing only its own
        # bytes; the unread half of the previous body is nowhere in it
        parser2 = self.make_parser()
        self.feed(parser2, post_request(MARKER_BRAVO))
        stream2 = parser2.get_body_stream()
        self.assertIsNot(stream2, stream)
        self.assertEqual(stream2.read(), MARKER_BRAVO)
        parser2.close()

    def test_unread_body_is_fully_released(self):
        # the application never touches wsgi.input
        parser = self.make_parser()
        self.feed(parser, post_request(MARKER_ALPHA))
        self.assertTrue(parser.completed)

        parser.close()
        proxy = self.tracker.created[0]
        self.assertEqual(proxy.close_count, 1)
        self.assertTrue(proxy.closed)

        parser2 = self.make_parser()
        self.feed(parser2, post_request(MARKER_BRAVO))
        self.assertEqual(parser2.get_body_stream().read(), MARKER_BRAVO)
        parser2.close()

    def test_content_length_over_limit_never_spools(self):
        parser = self.make_parser(max_request_body_size=64)
        data = post_request(MARKER_ALPHA)
        consumed = parser.received(data)
        self.assertLess(consumed, len(data))  # body bytes not consumed
        self.assertTrue(parser.completed)
        self.assertIsInstance(parser.error, RequestEntityTooLarge)
        # rejected at the header boundary: no temporary file was created
        self.assertEqual(self.tracker.created, [])
        parser.close()  # safe no-op
        self.assertEqual(self.tracker.created, [])

    def test_chunked_over_limit_spools_then_close_releases(self):
        parser = self.make_parser(max_request_body_size=64)
        self.feed(parser, CHUNKED_HEADERS + chunk_frame(MARKER_CHARLIE[:48]))
        self.assertFalse(parser.completed)
        self.feed(parser, chunk_frame(MARKER_CHARLIE[48:]))
        self.assertTrue(parser.completed)
        self.assertIsInstance(parser.error, RequestEntityTooLarge)

        # the partial body was spooled before the rejection was noticed
        self.assertEqual(len(self.tracker.created), 1)
        proxy = self.tracker.created[0]
        parser.close()
        self.assertEqual(proxy.close_count, 1)
        self.assertTrue(proxy.closed)
        with self.assertRaises(ValueError):
            proxy.read()

    def test_header_parse_error_creates_no_body_buffer(self):
        parser = self.make_parser()
        data = (
            b"GET / HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Content-Length: 96\r\n"
            b"Content-Length: 96\r\n"
            b"\r\n"
        ) + MARKER_ALPHA
        self.feed(parser, data)
        self.assertTrue(parser.completed)
        self.assertIsInstance(parser.error, BadRequest)
        # the header parse failed before any body receiver was created:
        # no buffer, no temporary file, and the body bytes went nowhere
        self.assertIsNone(parser.body_rcv)
        self.assertEqual(self.tracker.created, [])
        self.assertEqual(parser.get_body_stream().read(), b"")
        parser.close()  # safe no-op
        self.assertEqual(self.tracker.created, [])

    def test_chunked_garbage_error_releases_spooled_body(self):
        parser = self.make_parser()
        self.feed(parser, CHUNKED_HEADERS + chunk_frame(MARKER_CHARLIE[:48]))
        self.assertFalse(parser.completed)
        self.feed(parser, b"NOT-A-CHUNK-SIZE\r\n")
        self.assertTrue(parser.completed)
        self.assertIsInstance(parser.error, BadRequest)

        self.assertEqual(len(self.tracker.created), 1)
        proxy = self.tracker.created[0]
        parser.close()
        self.assertEqual(proxy.close_count, 1)
        self.assertTrue(proxy.closed)

    def test_each_parser_owns_distinct_buffer_and_file(self):
        parser1 = self.make_parser()
        self.feed(parser1, post_request(MARKER_ALPHA))
        parser2 = self.make_parser()
        self.feed(parser2, post_request(MARKER_BRAVO))

        self.assertEqual(len(self.tracker.created), 2)
        self.assertIsNot(parser1.body_rcv.getbuf(), parser2.body_rcv.getbuf())
        self.assertIsNot(parser1.get_body_stream(), parser2.get_body_stream())
        self.assertIsNot(self.tracker.created[0], self.tracker.created[1])

        parser1.close()
        parser2.close()


class DummySock:
    def __init__(self):
        self.sent = b""
        self.closed = False

    def setblocking(self, flag):
        pass

    def fileno(self):
        return 100

    def getsockopt(self, level, option):
        return 2048

    def send(self, data):
        self.sent += data
        return len(data)

    def recv(self, size):
        return b""

    def close(self):
        self.closed = True


class DummyServer:
    effective_port = 8080
    server_name = "localhost"

    def __init__(self, adj, application):
        self.adj = adj
        self.application = application
        self.tasks = []
        self.active_channels = {}
        self.trigger_pulled = False

    def add_task(self, task):
        self.tasks.append(task)

    def pull_trigger(self):
        self.trigger_pulled = True


def make_app(captured, read_modes):
    """A WSGI app that records wsgi.input and reads it per read_modes."""

    modes = list(read_modes)

    def application(environ, start_response):
        stream = environ["wsgi.input"]
        captured["inputs"].append(stream)
        mode = modes.pop(0) if modes else "none"
        if mode == "all":
            captured["bodies"].append(stream.read())
        elif mode == "half":
            length = int(environ["CONTENT_LENGTH"])
            captured["bodies"].append(stream.read(length // 2))
        start_response("200 OK", [("Content-Length", "2")])
        return [b"ok"]

    return application


class TestChannelBodyLifecycle(BodyLifecycleTestCase):
    def make_channel(self, application, **overrides):
        adj = Adjustments()
        adj.inbuf_overflow = 16
        for name, value in overrides.items():
            setattr(adj, name, value)
        server = DummyServer(adj, application)
        sock = DummySock()
        channel = HTTPChannel(server, sock, ("127.0.0.1", 12345), adj=adj, map={})
        return channel, server, sock

    def test_pipelined_requests_isolated_bodies(self):
        captured = {"inputs": [], "bodies": []}
        app = make_app(captured, ["half", "all"])
        channel, server, sock = self.make_channel(app)

        data = post_request(MARKER_ALPHA) + post_request(MARKER_BRAVO, path=b"/two")
        self.assertTrue(channel.received(data))
        self.assertEqual(len(channel.requests), 2)
        request_alpha, request_bravo = channel.requests

        # both bodies were spooled before either request was serviced,
        # to distinct temporary files owned by distinct buffers
        self.assertEqual(len(self.tracker.created), 2)
        self.assertIsNot(self.tracker.created[0], self.tracker.created[1])
        self.assertIsNot(
            request_alpha.body_rcv.getbuf(), request_bravo.body_rcv.getbuf()
        )

        channel.service()  # services request_alpha (app reads half)
        proxy_alpha = captured["inputs"][0]
        self.assertIs(proxy_alpha, self.tracker.created[0])
        self.assertEqual(
            captured["bodies"][0], MARKER_ALPHA[: len(MARKER_ALPHA) // 2]
        )
        # alpha's file is retired exactly once; bravo's is still open
        self.assertEqual(proxy_alpha.close_count, 1)
        self.assertTrue(proxy_alpha.closed)
        self.assertFalse(self.tracker.created[1].closed)

        channel.service()  # services request_bravo (app reads all)
        proxy_bravo = captured["inputs"][1]
        self.assertIs(proxy_bravo, self.tracker.created[1])
        self.assertIsNot(proxy_bravo, proxy_alpha)
        # the pipelined body contains only its own marker: none of
        # alpha's bytes (read or unread) leaked into it
        self.assertEqual(captured["bodies"][1], MARKER_BRAVO)
        self.assertNotIn(b"ALPHA", captured["bodies"][1])
        self.assertEqual(proxy_bravo.close_count, 1)
        self.assertTrue(proxy_bravo.closed)

        # references the app retained to either wsgi.input are dead now
        for stream in captured["inputs"]:
            with self.assertRaises(ValueError):
                stream.read()
            with self.assertRaises(ValueError):
                stream.fileno()

    def test_unread_body_released_after_service(self):
        captured = {"inputs": [], "bodies": []}
        app = make_app(captured, ["none"])
        channel, server, sock = self.make_channel(app)

        channel.received(post_request(MARKER_ALPHA))
        channel.service()

        self.assertEqual(captured["bodies"], [])
        proxy = captured["inputs"][0]
        self.assertEqual(proxy.close_count, 1)
        self.assertTrue(proxy.closed)
        with self.assertRaises(ValueError):
            proxy.read()

    def test_parse_error_discards_queued_pipeline(self):
        captured = {"inputs": [], "bodies": []}
        app = make_app(captured, ["all"])
        channel, server, sock = self.make_channel(app)

        bad_request = (
            b"GET / HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Content-Length: 3\r\n"
            b"Content-Length: 3\r\n"
            b"\r\n"
        )
        channel.received(bad_request + post_request(MARKER_BRAVO))
        self.assertEqual(len(channel.requests), 2)
        self.assertIsInstance(channel.requests[0].error, BadRequest)

        channel.service()
        channel.handle_write()  # flush the error response

        # the application never ran and never saw either body
        self.assertEqual(captured["inputs"], [])
        self.assertIn(b"400", sock.sent)
        self.assertNotIn(MARKER_BRAVO, sock.sent)
        # the queued pipelined request was retired unserviced, its
        # spooled body closed exactly once and handed to no one
        self.assertEqual(channel.requests, [])
        self.assertEqual(len(self.tracker.created), 1)
        proxy = self.tracker.created[0]
        self.assertEqual(proxy.close_count, 1)
        self.assertTrue(proxy.closed)

    def test_chunked_over_limit_error_releases_body(self):
        captured = {"inputs": [], "bodies": []}
        app = make_app(captured, ["all"])
        channel, server, sock = self.make_channel(app, max_request_body_size=64)

        channel.received(CHUNKED_HEADERS + chunk_frame(MARKER_CHARLIE[:48]))
        self.assertEqual(len(channel.requests), 0)  # still in progress
        channel.received(chunk_frame(MARKER_CHARLIE[48:]))
        self.assertEqual(len(channel.requests), 1)
        request = channel.requests[0]
        self.assertIsInstance(request.error, RequestEntityTooLarge)

        channel.service()
        channel.handle_write()

        self.assertEqual(captured["inputs"], [])
        self.assertIn(b"413", sock.sent)
        self.assertNotIn(MARKER_CHARLIE, sock.sent)
        # the partially spooled body was closed exactly once
        self.assertEqual(len(self.tracker.created), 1)
        proxy = self.tracker.created[0]
        self.assertEqual(proxy.close_count, 1)
        self.assertTrue(proxy.closed)

    def test_disconnect_mid_body_relies_on_gc(self):
        captured = {"inputs": [], "bodies": []}
        app = make_app(captured, ["all"])
        channel, server, sock = self.make_channel(app)

        headers = (
            b"POST / HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Content-Length: 4096\r\n"
            b"\r\n"
        )
        channel.received(headers + MARKER_CHARLIE)  # partial body
        parser = channel.request
        self.assertIsNotNone(parser)
        self.assertFalse(parser.completed)
        self.assertEqual(len(self.tracker.created), 1)
        proxy = self.tracker.created[-1]

        channel.handle_close()

        # documented behavior: abrupt teardown does NOT explicitly close
        # the in-progress body buffer; the file handle is still open and
        # a retained reference still exposes the spooled bytes
        self.assertEqual(proxy.close_count, 0)
        self.assertFalse(proxy.closed)
        self.assertEqual(proxy.read(), MARKER_CHARLIE)

        # ...but those bytes are unreachable from any new connection
        captured2 = {"inputs": [], "bodies": []}
        channel2, server2, sock2 = self.make_channel(make_app(captured2, ["all"]))
        channel2.received(post_request(MARKER_DELTA))
        channel2.service()
        self.assertEqual(captured2["bodies"], [MARKER_DELTA])
        self.assertIsNot(captured2["inputs"][0], proxy)

        # cleanup of the abandoned buffer is GC-dependent: once the last
        # reference is gone, finalization closes the file (and unlinks
        # it) -- Waitress itself never overwrites the spooled bytes
        real_file_ref = weakref.ref(proxy._real_file)
        self.tracker.created.remove(proxy)
        del proxy, parser, channel
        gc.collect()
        self.assertIsNone(real_file_ref())

    def test_cancel_drops_queued_request_relies_on_gc(self):
        captured = {"inputs": [], "bodies": []}
        app = make_app(captured, ["all"])
        channel, server, sock = self.make_channel(app)

        channel.received(post_request(MARKER_ECHO))
        self.assertEqual(len(channel.requests), 1)  # queued, unserviced
        self.assertEqual(len(self.tracker.created), 1)
        proxy = self.tracker.created[-1]

        channel.cancel()
        self.assertEqual(channel.requests, [])

        # as with disconnect, cancel() performs no explicit close; the
        # recorded reference still reads the spooled bytes
        self.assertEqual(proxy.close_count, 0)
        self.assertFalse(proxy.closed)
        self.assertEqual(proxy.read(), MARKER_ECHO)

        real_file_ref = weakref.ref(proxy._real_file)
        self.tracker.created.remove(proxy)
        del proxy, channel
        gc.collect()
        self.assertIsNone(real_file_ref())


if __name__ == "__main__":
    unittest.main()
