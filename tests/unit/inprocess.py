"""Drive real Flower handlers without binding a socket.

The unit suite normally uses ``tornado.testing.AsyncHTTPTestCase``.  Some
sandboxes forbid local port binding, so these helpers build the request and
execute the same handler class the router would pick.  They are only for
tests that need the HTTP handler layer.
"""
import asyncio
import base64
from urllib.parse import urlencode

from tornado.httputil import HTTPHeaders, HTTPServerRequest, RequestStartLine


class _Connection:
    def __init__(self):
        self.chunks = []
        self.start_line = None
        self.headers = None
        self.finished = False

    def write_headers(self, start_line, headers, chunk=None, callback=None):
        self.start_line = start_line
        self.headers = headers
        if chunk is not None:
            self.chunks.append(chunk)
        if callback is not None:
            callback()

    def write(self, chunk, callback=None):
        self.chunks.append(chunk)
        if callback is not None:
            callback()

    def finish(self):
        self.finished = True

    def detach(self):
        pass

    def set_close_callback(self, callback):
        self.close_callback = callback

    def set_nodelay(self, value):
        pass


class Response:
    def __init__(self, code, body, handler):
        self.code = code
        self.body = body
        self.handler = handler

    def json(self):
        import json
        return json.loads(self.body)


class InProcessClient:
    def __init__(self, app):
        self.app = app

    def get(self, path, auth=None, headers=None):
        return self.request('GET', path, headers=headers, auth=auth)

    def post(self, path, body=None, auth=None, headers=None):
        return self.request('POST', path, body=body, headers=headers,
                            auth=auth)

    def request(self, method, path, body=None, headers=None, auth=None):
        headers = dict(headers or {})
        payload = b''
        if isinstance(body, dict):
            payload = urlencode(body).encode()
            headers.setdefault('Content-Type',
                               'application/x-www-form-urlencoded')
        elif body is not None:
            payload = bytes(body)
        headers.setdefault('Host', 'localhost')
        if auth is not None:
            token = base64.b64encode(
                f'{auth[0]}:{auth[1]}'.encode()).decode()
            headers['Authorization'] = 'Basic ' + token
        request = HTTPServerRequest(
            start_line=RequestStartLine(method, path, 'HTTP/1.1'),
            headers=HTTPHeaders(headers), body=payload,
            connection=_Connection())
        request.remote_ip = '127.0.0.1'
        delegate = self.app.find_handler(request)
        handler = delegate.handler_class(
            self.app, request, **delegate.handler_kwargs)

        async def go():
            try:
                await handler._execute(
                    [], *delegate.path_args, **delegate.path_kwargs)
            except Exception as exc:  # handler turns HTTPError into a response
                handler._handle_request_exception(exc)

        asyncio.run(go())
        code = (request.connection.start_line.code
                if request.connection.start_line is not None
                else handler.get_status())
        return Response(code, b''.join(request.connection.chunks), handler)
