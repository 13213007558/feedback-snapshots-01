"""Regression tests for the ``wsgi.file_wrapper`` transfer window.

A sensitive download is handed to Waitress through ``wsgi.file_wrapper`` as an
already positioned file handle.  The tests in this module pin down the
security relevant semantics of that handoff:

* The remaining amount must be computed from the *current* file position, not
  from the start of the file.  Re-serving the same wrapper must therefore not
  be re-sized against the whole file.

* Only the authorized window may ever leave the process.  A distinct marker
  byte is used for the unauthorized prefix and for the unauthorized suffix so
  that a leak from either side is detectable in the bytes actually sent, not
  merely in the advertised ``Content-Length``.

* The underlying file must not be read past the window and then trimmed at the
  output side.  Every ``read()`` is recorded with its absolute range and the
  ranges are asserted to stay inside the window.

* Short writes (the socket accepting fewer bytes than offered) and an early
  EOF must keep the window accounting consistent.

* ``HEAD`` requests must not produce a message body even though the same file
  wrapper is used for a ``GET``.

* Closing the resource is owned either by the channel (once the wrapper has
  been queued for sending) or by the task (when it keeps the wrapper), never
  both and never neither.
"""

import io
import unittest


# Distinct markers make a leak from either side of the window unambiguous.
PREFIX_MARKER = 0x50  # b'P', the unauthorized prefix
WINDOW_MARKER = 0x57  # b'W', the authorized window
SUFFIX_MARKER = 0x53  # b'S', the unauthorized suffix

PREFIX_LEN = 10
WINDOW_LEN = 15
SUFFIX_LEN = 8

WINDOW_START = PREFIX_LEN
WINDOW_END = PREFIX_LEN + WINDOW_LEN
FILE_LEN = WINDOW_END + SUFFIX_LEN

FILE_DATA = (
    bytes([PREFIX_MARKER]) * PREFIX_LEN
    + bytes([WINDOW_MARKER]) * WINDOW_LEN
    + bytes([SUFFIX_MARKER]) * SUFFIX_LEN
)
WINDOW_DATA = bytes([WINDOW_MARKER]) * WINDOW_LEN


class TrackingFile(io.BytesIO):
    """A seekable file that records every read as an absolute byte range."""

    def __init__(self, data=FILE_DATA):
        super().__init__(data)
        self.read_ranges = []
        self.close_count = 0

    def read(self, size=-1):
        start = self.tell()
        result = super().read(size)
        self.read_ranges.append((start, start + len(result)))
        return result

    def close(self):
        self.close_count += 1
        super().close()

    def assert_reads_within_window(self, test_case, start=WINDOW_START, end=WINDOW_END):
        test_case.assertTrue(
            self.read_ranges, "the underlying file was never read"
        )
        for read_start, read_end in self.read_ranges:
            test_case.assertGreaterEqual(
                read_start,
                start,
                "read began before the authorized window: %r" % (self.read_ranges,),
            )
            test_case.assertLessEqual(
                read_end,
                end,
                "read ran past the authorized window: %r" % (self.read_ranges,),
            )


class NonSeekableFile:
    """A file-like object with only ``read``/``close`` (no seek/tell)."""

    def __init__(self, data=FILE_DATA, start=0):
        self._data = data
        self._pos = start
        self.read_ranges = []
        self.close_count = 0

    def read(self, size=-1):
        start = self._pos
        if size is None or size < 0:
            chunk = self._data[start:]
            self._pos = len(self._data)
        else:
            chunk = self._data[start : start + size]
            self._pos += len(chunk)
        self.read_ranges.append((start, start + len(chunk)))
        return chunk

    def close(self):
        self.close_count += 1

    def assert_reads_within_window(self, test_case, start=WINDOW_START, end=WINDOW_END):
        test_case.assertTrue(
            self.read_ranges, "the underlying file was never read"
        )
        for read_start, read_end in self.read_ranges:
            test_case.assertGreaterEqual(read_start, start)
            test_case.assertLessEqual(read_end, end)


class ShortSendingDummySock:
    """Stand-in socket whose ``send`` always accepts at most ``take`` bytes.

    This reproduces a short write at the channel boundary so the
    ``_flush_some`` loop has to come back for the rest instead of assuming a
    single ``send`` drains an outbuf.
    """

    blocking = False
    closed = False

    def __init__(self, take=4):
        self.take = take
        self.remote_sent = b""

    def setblocking(self, *arg):
        self.blocking = True

    def fileno(self):
        return 100

    def getpeername(self):
        return "127.0.0.1"

    def getsockopt(self, level, option):
        return 2048

    def close(self):
        self.closed = True

    def send(self, data):
        take = min(self.take, len(data))
        self.remote_sent += data[:take]
        return take

    def recv(self, buffer_size):
        result = self.remote_sent[:buffer_size]
        self.remote_sent = self.remote_sent[buffer_size:]
        return result

    def local(self):
        outer = self

        class LocalDummySock:
            def send(self, data):
                take = min(outer.take, len(data))
                outer.remote_sent += data[:take]
                return take

            def recv(self, buffer_size):
                return outer.recv(buffer_size)

            def close(self):
                outer.closed = True

            @property
            def sent(self):
                return outer.remote_sent

            @property
            def closed(self):
                return outer.closed

            @property
            def remote(self):
                return outer

        return LocalDummySock()


def make_channel(sock=None):
    from waitress.channel import HTTPChannel
    from tests.test_channel import DummyAdjustments, DummyLock, DummyServer

    if sock is None:
        from tests.test_channel import DummySock

        sock = DummySock()
    channel = HTTPChannel(
        DummyServer(), sock, "127.0.0.1", adj=DummyAdjustments(), map={}
    )
    channel.outbuf_lock = DummyLock()
    return channel, sock


def make_request(command="GET", version="1.0"):
    from tests.test_task import DummyParser

    request = DummyParser()
    request.command = command
    request.version = version
    return request


def drain(channel):
    """Flush every queued outbuf the way the async main loop would."""
    for _ in range(1000):
        if channel.total_outbufs_len == 0:
            break
        channel._flush_some()
    return channel


def serve(channel, app, command="GET", version="1.0"):
    from waitress.task import WSGITask

    request = make_request(command, version)
    channel.requests = [request]
    channel.server.application = app
    task = WSGITask(channel, request)
    task.service()
    drain(channel)
    return task


def file_wrapper_app(file_object, block_size=8192, content_length=None):
    def app(environ, start_response):
        headers = [("Content-Type", "application/octet-stream")]
        if content_length is not None:
            headers.append(("Content-Length", str(content_length)))
        start_response("200 OK", headers)
        return environ["wsgi.file_wrapper"](file_object, block_size)

    return app


def split_response(raw):
    header, _, body = raw.partition(b"\r\n\r\n")
    return header, body


def header_value(header_block, name):
    needle = name.lower().encode("latin-1") + b":"
    for line in header_block.split(b"\r\n"):
        if line.lower().startswith(needle):
            return line.split(b":", 1)[1].strip().decode("latin-1")
    return None


class TestPreparedWindowSemantics(unittest.TestCase):
    """``ReadOnlyFileBasedBuffer`` window accounting from a non-zero offset."""

    def _make_one(self, file_object, block_size=8192):
        from waitress.buffers import ReadOnlyFileBasedBuffer

        return ReadOnlyFileBasedBuffer(file_object, block_size)

    def test_prepare_uses_current_position_not_whole_file(self):
        f = TrackingFile()
        f.seek(WINDOW_START)
        wrapper = self._make_one(f)

        remain = wrapper.prepare()

        self.assertEqual(remain, WINDOW_LEN + SUFFIX_LEN)
        self.assertEqual(wrapper.remain, WINDOW_LEN + SUFFIX_LEN)
        # prepare restores the handle to the position it was given
        self.assertEqual(f.tell(), WINDOW_START)

    def test_prepare_with_explicit_length_limits_remain(self):
        f = TrackingFile()
        f.seek(WINDOW_START)
        wrapper = self._make_one(f)

        remain = wrapper.prepare(WINDOW_LEN)

        self.assertEqual(remain, WINDOW_LEN)
        self.assertEqual(wrapper.remain, WINDOW_LEN)
        self.assertEqual(f.tell(), WINDOW_START)

    def test_prepare_explicit_length_longer_than_remaining_clamps_to_eof(self):
        f = TrackingFile()
        f.seek(WINDOW_START)
        wrapper = self._make_one(f)

        # claims far more than the bytes left in the file
        remain = wrapper.prepare(FILE_LEN * 2)

        self.assertEqual(remain, WINDOW_LEN + SUFFIX_LEN)
        self.assertEqual(wrapper.remain, WINDOW_LEN + SUFFIX_LEN)

    def test_prepare_after_partial_read_tracks_shrunk_remaining(self):
        f = TrackingFile()
        f.seek(WINDOW_START)
        f.read(4)  # application consumed 4 window bytes before wrapping
        wrapper = self._make_one(f)

        self.assertEqual(wrapper.prepare(), WINDOW_LEN + SUFFIX_LEN - 4)
        self.assertEqual(f.tell(), WINDOW_START + 4)

    def test_get_never_crosses_end_of_window(self):
        f = TrackingFile()
        f.seek(WINDOW_START)
        wrapper = self._make_one(f)
        wrapper.prepare(WINDOW_LEN)

        # ask for way more than the window in one go
        first = wrapper.get(FILE_LEN, skip=True)
        self.assertEqual(first, WINDOW_DATA)
        self.assertEqual(wrapper.remain, 0)
        self.assertEqual(f.tell(), WINDOW_END)
        f.assert_reads_within_window(self)

    def test_get_skip_in_chunks_keeps_file_position_and_remain(self):
        f = TrackingFile()
        f.seek(WINDOW_START)
        wrapper = self._make_one(f)
        wrapper.prepare(WINDOW_LEN)

        collected = b""
        while wrapper.remain:
            collected += wrapper.get(4, skip=True)

        self.assertEqual(collected, WINDOW_DATA)
        self.assertEqual(wrapper.remain, 0)
        self.assertEqual(f.tell(), WINDOW_END)
        f.assert_reads_within_window(self)
        # the suffix marker must remain unread immediately after the window
        self.assertEqual(f.read(1), bytes([SUFFIX_MARKER]))

    def test_get_without_skip_does_not_advance_handle(self):
        f = TrackingFile()
        f.seek(WINDOW_START)
        wrapper = self._make_one(f)
        wrapper.prepare(WINDOW_LEN)

        peeked = wrapper.get(4, skip=False)

        self.assertEqual(peeked, bytes([WINDOW_MARKER]) * 4)
        self.assertEqual(f.tell(), WINDOW_START)
        self.assertEqual(wrapper.remain, WINDOW_LEN)

    def test_early_eof_read_returns_only_available_window_bytes(self):
        # file ends inside the claimed window
        short_data = (
            bytes([PREFIX_MARKER]) * PREFIX_LEN
            + bytes([WINDOW_MARKER]) * 6
        )
        f = TrackingFile(short_data)
        f.seek(WINDOW_START)
        wrapper = self._make_one(f)
        # prepare itself clamps to the real EOF
        self.assertEqual(wrapper.prepare(WINDOW_LEN), 6)

        delivered = wrapper.get(WINDOW_LEN, skip=True)
        self.assertEqual(delivered, bytes([WINDOW_MARKER]) * 6)
        self.assertEqual(wrapper.remain, 0)
        f.assert_reads_within_window(self, WINDOW_START, WINDOW_START + 6)


class TestChannelWindowTransfer(unittest.TestCase):
    """End-to-end transfer through a real ``HTTPChannel`` outbuf machinery."""

    def _wrapper_app(self, file_object, block_size=8192, content_length=None):
        return file_wrapper_app(file_object, block_size, content_length)

    def test_get_from_nonzero_position_sends_only_window(self):
        f = TrackingFile()
        f.seek(WINDOW_START)
        channel, sock = make_channel()
        app = self._wrapper_app(f, content_length=WINDOW_LEN)

        serve(channel, app)

        header, body = split_response(sock.remote_sent)
        self.assertEqual(body, WINDOW_DATA)
        self.assertEqual(header_value(header, "Content-Length"), str(WINDOW_LEN))
        self.assertNotIn(bytes([PREFIX_MARKER]), body)
        self.assertNotIn(bytes([SUFFIX_MARKER]), body)
        f.assert_reads_within_window(self)

    def test_no_content_length_computes_remainder_from_position(self):
        f = TrackingFile()
        f.seek(WINDOW_START)
        channel, sock = make_channel()
        # no Content-Length: waitress must size from the current handle
        app = self._wrapper_app(f, content_length=None)

        task = serve(channel, app)

        header, body = split_response(sock.remote_sent)
        # remainder is window + suffix, starting exactly at WINDOW_START
        self.assertEqual(
            body,
            bytes([WINDOW_MARKER]) * WINDOW_LEN
            + bytes([SUFFIX_MARKER]) * SUFFIX_LEN,
        )
        self.assertEqual(
            header_value(header, "Content-Length"), str(WINDOW_LEN + SUFFIX_LEN)
        )
        self.assertEqual(task.content_length, WINDOW_LEN + SUFFIX_LEN)
        self.assertNotIn(bytes([PREFIX_MARKER]), body)
        # every read started at or after the authorized position
        self.assertTrue(
            all(start >= WINDOW_START for start, _ in f.read_ranges)
        )

    def test_short_writes_drain_full_window_without_leak(self):
        f = TrackingFile()
        f.seek(WINDOW_START)
        channel, sock = make_channel(ShortSendingDummySock(take=4))
        # small block size so several reads feed several short sends
        app = self._wrapper_app(f, block_size=6, content_length=WINDOW_LEN)

        serve(channel, app)

        header, body = split_response(sock.remote_sent)
        self.assertEqual(len(body), WINDOW_LEN)
        self.assertEqual(body, WINDOW_DATA)
        self.assertEqual(header_value(header, "Content-Length"), str(WINDOW_LEN))
        self.assertNotIn(bytes([PREFIX_MARKER]), body)
        self.assertNotIn(bytes([SUFFIX_MARKER]), body)
        f.assert_reads_within_window(self)
        # the channel accounted for every byte it queued
        self.assertEqual(channel.total_outbufs_len, 0)

    def test_short_writes_with_no_content_length(self):
        f = TrackingFile()
        f.seek(WINDOW_START)
        channel, sock = make_channel(ShortSendingDummySock(take=3))
        app = self._wrapper_app(f, block_size=5, content_length=None)

        serve(channel, app)

        _, body = split_response(sock.remote_sent)
        self.assertEqual(
            body,
            bytes([WINDOW_MARKER]) * WINDOW_LEN
            + bytes([SUFFIX_MARKER]) * SUFFIX_LEN,
        )
        self.assertNotIn(bytes([PREFIX_MARKER]), body)
        self.assertTrue(all(start >= WINDOW_START for start, _ in f.read_ranges))

    def test_early_eof_advertises_and_sends_only_real_bytes(self):
        short_data = (
            bytes([PREFIX_MARKER]) * PREFIX_LEN
            + bytes([WINDOW_MARKER]) * 6
        )
        f = TrackingFile(short_data)
        f.seek(WINDOW_START)
        channel, sock = make_channel(ShortSendingDummySock(take=3))
        # application over-promises a Content-Length the file cannot satisfy
        app = self._wrapper_app(f, block_size=4, content_length=WINDOW_LEN)

        task = serve(channel, app)

        header, body = split_response(sock.remote_sent)
        self.assertEqual(body, bytes([WINDOW_MARKER]) * 6)
        # the advertised length is corrected down to the actual remainder
        self.assertEqual(header_value(header, "Content-Length"), "6")
        self.assertEqual(task.content_length, 6)
        self.assertNotIn(bytes([PREFIX_MARKER]), body)
        f.assert_reads_within_window(self, WINDOW_START, WINDOW_START + 6)

    def test_nonseekable_iteration_path_respects_start_position(self):
        # Without seek/tell, Waitress falls back to WSGI iteration.  The
        # unauthorized prefix is never reached because iteration begins at the
        # handle's current position; Content-Length trims the emitted body to
        # the window even though the file may be read a little past it.
        f = NonSeekableFile(start=WINDOW_START)
        channel, sock = make_channel()
        app = self._wrapper_app(f, block_size=4, content_length=WINDOW_LEN)

        serve(channel, app)

        _, body = split_response(sock.remote_sent)
        self.assertEqual(body, WINDOW_DATA)
        self.assertNotIn(bytes([PREFIX_MARKER]), body)
        self.assertNotIn(bytes([SUFFIX_MARKER]), body)
        # every read starts at or after the authorized position: the prefix
        # marker region is never touched
        self.assertTrue(
            all(start >= WINDOW_START for start, _ in f.read_ranges)
        )

    def test_nonseekable_block_size_smaller_than_window(self):
        f = NonSeekableFile(start=WINDOW_START)
        channel, sock = make_channel(ShortSendingDummySock(take=2))
        app = self._wrapper_app(f, block_size=3, content_length=WINDOW_LEN)

        serve(channel, app)

        _, body = split_response(sock.remote_sent)
        self.assertEqual(body, WINDOW_DATA)
        # short writes plus small iteration chunks still keep the prefix out
        self.assertTrue(
            all(start >= WINDOW_START for start, _ in f.read_ranges)
        )
        self.assertNotIn(bytes([PREFIX_MARKER]), body)
        self.assertNotIn(bytes([SUFFIX_MARKER]), body)

    def test_seekable_window_is_bounded_at_read_not_trimmed_after(self):
        # This is the anti-"read then cut" guarantee.  A vulnerable server
        # could read the whole remainder (window + suffix) and then slice the
        # extra bytes off the output; the sent body would still look right.
        # Assert instead that the suffix region is never handed to read() at
        # all, which a Content-Length-only check cannot catch.
        f = TrackingFile()
        f.seek(WINDOW_START)
        channel, sock = make_channel()
        app = self._wrapper_app(f, block_size=4, content_length=WINDOW_LEN)

        serve(channel, app)

        _, body = split_response(sock.remote_sent)
        self.assertEqual(body, WINDOW_DATA)
        self.assertEqual(
            max(end for _, end in f.read_ranges),
            WINDOW_END,
            "the suffix was read and would have to be trimmed: %r"
            % (f.read_ranges,),
        )
        f.assert_reads_within_window(self)


class TestHeadRequestWindow(unittest.TestCase):
    """A HEAD must report the window metadata but emit no message body."""

    def _serve(self, file_object, command):
        self.channel, self.sock = make_channel()
        app = file_wrapper_app(file_object, content_length=WINDOW_LEN)
        self.task = serve(
            self.channel, app, command=command, version="1.1"
        )
        return file_object

    def test_head_sends_no_body_but_correct_length(self):
        f = TrackingFile()
        f.seek(WINDOW_START)
        self._serve(f, "HEAD")

        raw = self.sock.remote_sent
        header, body = split_response(raw)
        self.assertEqual(
            header_value(header, "Content-Length"), str(WINDOW_LEN)
        )
        # RFC 9110: a HEAD response has no message body
        self.assertEqual(body, b"")
        self.assertNotIn(bytes([WINDOW_MARKER]), raw.split(b"\r\n\r\n", 1)[1])

    def test_head_does_not_transfer_window_bytes(self):
        f = TrackingFile()
        f.seek(WINDOW_START)
        self._serve(f, "HEAD")

        # The window bytes must not be handed to the socket.  Preparing the
        # wrapper only measures the file; a data-bearing read would prove the
        # body was materialized for a HEAD.
        self.assertEqual(
            f.read_ranges,
            [],
            "HEAD must not read body bytes from the file: %r"
            % (f.read_ranges,),
        )

    def test_get_equivalent_still_sends_window(self):
        # control case proving the same wrapper app serves the window for GET
        f = TrackingFile()
        f.seek(WINDOW_START)
        self._serve(f, "GET")

        _, body = split_response(self.sock.remote_sent)
        self.assertEqual(body, WINDOW_DATA)
        f.assert_reads_within_window(self)


class TestResourceCloseOwnership(unittest.TestCase):
    """Who closes the file handle: channel vs. task."""

    def test_channel_owns_and_closes_queued_wrapper(self):
        f = TrackingFile()
        f.seek(WINDOW_START)
        channel, sock = make_channel()
        app = file_wrapper_app(f, content_length=WINDOW_LEN)

        serve(channel, app)

        # once handed to the channel and fully flushed, the handle is closed
        self.assertEqual(f.close_count, 1)
        self.assertTrue(f.closed)

    def test_channel_close_owns_wrapper_when_not_flushed(self):
        # Even if the socket accepts nothing, queued wrapper ownership is with
        # the channel; closing the channel must close the underlying file.
        from tests.test_channel import DummySock

        class NeverSendingSock(DummySock):
            def send(self, data):
                return 0

            def local(self):
                outer = self

                class Local:
                    def send(self, data):
                        return 0

                    def recv(self, buffer_size):
                        return b""

                    def close(self):
                        outer.closed = True

                    @property
                    def sent(self):
                        return outer.remote_sent

                    @property
                    def closed(self):
                        return outer.closed

                    @property
                    def remote(self):
                        return outer

                return Local()

        f = TrackingFile()
        f.seek(WINDOW_START)
        channel, sock = make_channel(NeverSendingSock())
        app = file_wrapper_app(f, content_length=WINDOW_LEN)
        request = make_request()
        channel.requests = [request]
        channel.server.application = app
        from waitress.task import WSGITask

        WSGITask(channel, request).service()
        # wrapper is queued but nothing was sent; channel shutdown closes it
        channel.handle_close()

        self.assertEqual(f.close_count, 1)
        self.assertTrue(f.closed)

    def test_task_closes_wrapper_when_prepare_reports_zero(self):
        f = TrackingFile()
        f.seek(FILE_LEN)  # positioned at EOF, nothing to send
        channel, sock = make_channel()
        app = file_wrapper_app(f, content_length=0)

        serve(channel, app)

        # nothing queued to the channel, so the task retains close ownership
        self.assertEqual(f.close_count, 1)
        self.assertTrue(f.closed)

    def test_task_closes_nonseekable_wrapper(self):
        f = NonSeekableFile(start=WINDOW_START)
        channel, sock = make_channel()
        app = file_wrapper_app(f, block_size=4, content_length=WINDOW_LEN)

        serve(channel, app)

        # iteration path keeps ownership in the task's finally block
        self.assertEqual(f.close_count, 1)

    def test_wrapper_not_double_closed_after_flush(self):
        f = TrackingFile()
        f.seek(WINDOW_START)
        channel, sock = make_channel()
        app = file_wrapper_app(f, content_length=WINDOW_LEN)

        serve(channel, app)
        # an extra channel close must not close the handle a second time
        channel.handle_close()

        self.assertEqual(f.close_count, 1)


if __name__ == "__main__":
    unittest.main()
