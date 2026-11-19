#
# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.

from gunicorn.http.message import Message, Request
from gunicorn.http.parser import RequestParser


def get_parser(cfg, source, source_addr, http2_connection=False,
               listener=None):
    """Get appropriate parser based on protocol config.

    Args:
        cfg: Gunicorn config object
        source: Socket or iterable source
        source_addr: Source address tuple or None
        http2_connection: If True, create HTTP/2 connection handler
        listener: The listening socket that accepted the connection, if
            known. Proxy trust is resolved from it per request.

    Returns:
        Parser instance (RequestParser, UWSGIParser, or HTTP2ServerConnection)
    """
    # HTTP/2 connection
    if http2_connection:
        from gunicorn.http2.connection import HTTP2ServerConnection
        return HTTP2ServerConnection(cfg, source, source_addr,
                                     listener=listener)

    # uWSGI protocol
    protocol = getattr(cfg, 'protocol', 'http')
    if protocol == 'uwsgi':
        from gunicorn.uwsgi.parser import UWSGIParser
        return UWSGIParser(cfg, source, source_addr, listener=listener)

    # Default HTTP/1.x
    return RequestParser(cfg, source, source_addr, listener=listener)


__all__ = ['Message', 'Request', 'RequestParser', 'get_parser']
