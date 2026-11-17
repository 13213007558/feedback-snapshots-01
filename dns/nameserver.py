import os
import time
from urllib.parse import urlparse

import dns.asyncbackend
import dns.asyncquery
import dns.cookie
import dns.exception
import dns.message
import dns.query
import dns.rcode


class Nameserver:
    def __init__(self):
        pass

    def __str__(self):
        raise NotImplementedError  # pragma: no cover

    def kind(self) -> str:
        raise NotImplementedError  # pragma: no cover

    def is_always_max_size(self) -> bool:
        raise NotImplementedError  # pragma: no cover

    def answer_nameserver(self) -> str:
        raise NotImplementedError  # pragma: no cover

    def answer_port(self) -> int:
        raise NotImplementedError  # pragma: no cover

    def query(
        self,
        request: dns.message.QueryMessage,
        timeout: float,
        source: str | None,
        source_port: int,
        max_size: bool,
        one_rr_per_rrset: bool = False,
        ignore_trailing: bool = False,
    ) -> dns.message.Message:
        raise NotImplementedError  # pragma: no cover

    async def async_query(
        self,
        request: dns.message.QueryMessage,
        timeout: float,
        source: str | None,
        source_port: int,
        max_size: bool,
        backend: dns.asyncbackend.Backend,
        one_rr_per_rrset: bool = False,
        ignore_trailing: bool = False,
    ) -> dns.message.Message:
        raise NotImplementedError  # pragma: no cover


class AddressAndPortNameserver(Nameserver):
    def __init__(self, address: str, port: int):
        super().__init__()
        self.address = address
        self.port = port

    def kind(self) -> str:
        raise NotImplementedError  # pragma: no cover

    def is_always_max_size(self) -> bool:
        return False

    def __str__(self):
        ns_kind = self.kind()
        return f"{ns_kind}:{self.address}@{self.port}"

    def answer_nameserver(self) -> str:
        return self.address

    def answer_port(self) -> int:
        return self.port


class Do53Nameserver(AddressAndPortNameserver):
    def __init__(
        self,
        address: str,
        port: int = 53,
        cookie_policy: dns.cookie.CookiePolicy | None = None,
    ):
        """Initialize a Do53 nameserver.

        :param address: The nameserver address.
        :param port: The nameserver port.
        :param cookie_policy: An optional :py:class:`dns.cookie.CookiePolicy`.
            If ``None``, DNS Cookies are not used.  The policy is applied to
            UDP queries only.  A policy assigned to a resolver's
            ``cookie_policy`` attribute is propagated to its Do53 nameservers.
        """

        super().__init__(address, port)
        self.cookie_policy = cookie_policy

    def kind(self):
        return "Do53"

    def _udp_query(
        self,
        request: dns.message.QueryMessage,
        timeout: float,
        source: str | None,
        source_port: int,
        one_rr_per_rrset: bool,
        ignore_trailing: bool,
    ) -> dns.message.Message:
        return dns.query.udp(
            request,
            self.address,
            timeout=timeout,
            port=self.port,
            source=source,
            source_port=source_port,
            raise_on_truncation=True,
            one_rr_per_rrset=one_rr_per_rrset,
            ignore_trailing=ignore_trailing,
            ignore_errors=True,
            ignore_unexpected=True,
        )

    def _udp_query_with_cookie(
        self,
        request: dns.message.QueryMessage,
        timeout: float,
        source: str | None,
        source_port: int,
        one_rr_per_rrset: bool,
        ignore_trailing: bool,
        policy: dns.cookie.CookiePolicy,
    ) -> dns.message.Message:
        endpoint = policy.endpoint(self.address, self.port, source)
        client_cookie = policy.client_cookie(endpoint)
        deadline = time.time() + timeout
        state = dns.cookie.save_edns_state(request)
        try:
            for attempt in range(2):
                attempt_timeout = deadline - time.time()
                if attempt_timeout <= 0:
                    raise dns.exception.Timeout(timeout=timeout)
                used_server_cookie = len(policy.server_cookie(endpoint)) > 0
                dns.cookie.set_cookie_option(request, policy.request_cookie(endpoint))
                response = self._udp_query(
                    request,
                    attempt_timeout,
                    source,
                    source_port,
                    one_rr_per_rrset,
                    ignore_trailing,
                )
                validation = policy.validate_response(response, endpoint, client_cookie)
                if response.rcode() == dns.rcode.BADCOOKIE and attempt == 0:
                    # A BADCOOKIE response must still echo the client Cookie;
                    # validate_response() has checked that.  We retry once
                    # only when we actually sent a server Cookie which the
                    # server has now replaced, and the response gave us a
                    # fresh one.  Otherwise there is nothing to learn, so let
                    # the resolver record BADCOOKIE.
                    if used_server_cookie and validation.bound:
                        continue
                response.cookie_validation = validation
                return response
            raise AssertionError("unreachable")  # pragma: no cover
        finally:
            dns.cookie.restore_edns_state(request, state)

    def query(
        self,
        request: dns.message.QueryMessage,
        timeout: float,
        source: str | None,
        source_port: int,
        max_size: bool,
        one_rr_per_rrset: bool = False,
        ignore_trailing: bool = False,
    ) -> dns.message.Message:
        if max_size:
            response = dns.query.tcp(
                request,
                self.address,
                timeout=timeout,
                port=self.port,
                source=source,
                source_port=source_port,
                one_rr_per_rrset=one_rr_per_rrset,
                ignore_trailing=ignore_trailing,
            )
        elif self.cookie_policy is not None and self.cookie_policy.enabled:
            response = self._udp_query_with_cookie(
                request,
                timeout,
                source,
                source_port,
                one_rr_per_rrset,
                ignore_trailing,
                self.cookie_policy,
            )
        else:
            response = self._udp_query(
                request,
                timeout,
                source,
                source_port,
                one_rr_per_rrset,
                ignore_trailing,
            )
        return response

    async def _async_udp_query(
        self,
        request: dns.message.QueryMessage,
        timeout: float,
        source: str | None,
        source_port: int,
        one_rr_per_rrset: bool,
        ignore_trailing: bool,
        backend: dns.asyncbackend.Backend,
    ) -> dns.message.Message:
        return await dns.asyncquery.udp(
            request,
            self.address,
            timeout=timeout,
            port=self.port,
            source=source,
            source_port=source_port,
            raise_on_truncation=True,
            backend=backend,
            one_rr_per_rrset=one_rr_per_rrset,
            ignore_trailing=ignore_trailing,
            ignore_errors=True,
            ignore_unexpected=True,
        )

    async def _async_udp_query_with_cookie(
        self,
        request: dns.message.QueryMessage,
        timeout: float,
        source: str | None,
        source_port: int,
        one_rr_per_rrset: bool,
        ignore_trailing: bool,
        backend: dns.asyncbackend.Backend,
        policy: dns.cookie.CookiePolicy,
    ) -> dns.message.Message:
        endpoint = policy.endpoint(self.address, self.port, source)
        client_cookie = policy.client_cookie(endpoint)
        deadline = time.time() + timeout
        state = dns.cookie.save_edns_state(request)
        try:
            for attempt in range(2):
                attempt_timeout = deadline - time.time()
                if attempt_timeout <= 0:
                    raise dns.exception.Timeout(timeout=timeout)
                used_server_cookie = len(policy.server_cookie(endpoint)) > 0
                dns.cookie.set_cookie_option(request, policy.request_cookie(endpoint))
                response = await self._async_udp_query(
                    request,
                    attempt_timeout,
                    source,
                    source_port,
                    one_rr_per_rrset,
                    ignore_trailing,
                    backend,
                )
                validation = policy.validate_response(response, endpoint, client_cookie)
                if response.rcode() == dns.rcode.BADCOOKIE and attempt == 0:
                    if used_server_cookie and validation.bound:
                        continue
                response.cookie_validation = validation
                return response
            raise AssertionError("unreachable")  # pragma: no cover
        finally:
            dns.cookie.restore_edns_state(request, state)

    async def async_query(
        self,
        request: dns.message.QueryMessage,
        timeout: float,
        source: str | None,
        source_port: int,
        max_size: bool,
        backend: dns.asyncbackend.Backend,
        one_rr_per_rrset: bool = False,
        ignore_trailing: bool = False,
    ) -> dns.message.Message:
        if max_size:
            response = await dns.asyncquery.tcp(
                request,
                self.address,
                timeout=timeout,
                port=self.port,
                source=source,
                source_port=source_port,
                backend=backend,
                one_rr_per_rrset=one_rr_per_rrset,
                ignore_trailing=ignore_trailing,
            )
        elif self.cookie_policy is not None and self.cookie_policy.enabled:
            response = await self._async_udp_query_with_cookie(
                request,
                timeout,
                source,
                source_port,
                one_rr_per_rrset,
                ignore_trailing,
                backend,
                self.cookie_policy,
            )
        else:
            response = await self._async_udp_query(
                request,
                timeout,
                source,
                source_port,
                one_rr_per_rrset,
                ignore_trailing,
                backend,
            )
        return response


class DoHNameserver(Nameserver):
    def __init__(
        self,
        url: str,
        bootstrap_address: str | None = None,
        verify: bool | str | os.PathLike = True,
        want_get: bool = False,
        http_version: dns.query.HTTPVersion = dns.query.HTTPVersion.DEFAULT,
    ):
        super().__init__()
        self.url = url
        self.bootstrap_address = bootstrap_address
        self.verify = verify
        self.want_get = want_get
        self.http_version = http_version

    def kind(self):
        return "DoH"

    def is_always_max_size(self) -> bool:
        return True

    def __str__(self):
        return self.url

    def answer_nameserver(self) -> str:
        return self.url

    def answer_port(self) -> int:
        port = urlparse(self.url).port
        if port is None:
            port = 443
        return port

    def query(
        self,
        request: dns.message.QueryMessage,
        timeout: float,
        source: str | None,
        source_port: int,
        max_size: bool = False,
        one_rr_per_rrset: bool = False,
        ignore_trailing: bool = False,
    ) -> dns.message.Message:
        return dns.query.https(
            request,
            self.url,
            timeout=timeout,
            source=source,
            source_port=source_port,
            bootstrap_address=self.bootstrap_address,
            one_rr_per_rrset=one_rr_per_rrset,
            ignore_trailing=ignore_trailing,
            verify=self.verify,
            post=(not self.want_get),
            http_version=self.http_version,
        )

    async def async_query(
        self,
        request: dns.message.QueryMessage,
        timeout: float,
        source: str | None,
        source_port: int,
        max_size: bool,
        backend: dns.asyncbackend.Backend,
        one_rr_per_rrset: bool = False,
        ignore_trailing: bool = False,
    ) -> dns.message.Message:
        return await dns.asyncquery.https(
            request,
            self.url,
            timeout=timeout,
            source=source,
            source_port=source_port,
            bootstrap_address=self.bootstrap_address,
            one_rr_per_rrset=one_rr_per_rrset,
            ignore_trailing=ignore_trailing,
            verify=self.verify,
            post=(not self.want_get),
            http_version=self.http_version,
        )


class DoTNameserver(AddressAndPortNameserver):
    def __init__(
        self,
        address: str,
        port: int = 853,
        hostname: str | None = None,
        verify: bool | str | os.PathLike = True,
    ):
        super().__init__(address, port)
        self.hostname = hostname
        self.verify = verify

    def kind(self):
        return "DoT"

    def query(
        self,
        request: dns.message.QueryMessage,
        timeout: float,
        source: str | None,
        source_port: int,
        max_size: bool = False,
        one_rr_per_rrset: bool = False,
        ignore_trailing: bool = False,
    ) -> dns.message.Message:
        return dns.query.tls(
            request,
            self.address,
            port=self.port,
            timeout=timeout,
            one_rr_per_rrset=one_rr_per_rrset,
            ignore_trailing=ignore_trailing,
            server_hostname=self.hostname,
            verify=self.verify,
        )

    async def async_query(
        self,
        request: dns.message.QueryMessage,
        timeout: float,
        source: str | None,
        source_port: int,
        max_size: bool,
        backend: dns.asyncbackend.Backend,
        one_rr_per_rrset: bool = False,
        ignore_trailing: bool = False,
    ) -> dns.message.Message:
        return await dns.asyncquery.tls(
            request,
            self.address,
            port=self.port,
            timeout=timeout,
            one_rr_per_rrset=one_rr_per_rrset,
            ignore_trailing=ignore_trailing,
            server_hostname=self.hostname,
            verify=self.verify,
        )


class DoQNameserver(AddressAndPortNameserver):
    def __init__(
        self,
        address: str,
        port: int = 853,
        verify: bool | str | os.PathLike = True,
        server_hostname: str | None = None,
    ):
        super().__init__(address, port)
        self.verify = verify
        self.server_hostname = server_hostname

    def kind(self):
        return "DoQ"

    def query(
        self,
        request: dns.message.QueryMessage,
        timeout: float,
        source: str | None,
        source_port: int,
        max_size: bool = False,
        one_rr_per_rrset: bool = False,
        ignore_trailing: bool = False,
    ) -> dns.message.Message:
        return dns.query.quic(
            request,
            self.address,
            port=self.port,
            timeout=timeout,
            one_rr_per_rrset=one_rr_per_rrset,
            ignore_trailing=ignore_trailing,
            verify=self.verify,
            server_hostname=self.server_hostname,
        )

    async def async_query(
        self,
        request: dns.message.QueryMessage,
        timeout: float,
        source: str | None,
        source_port: int,
        max_size: bool,
        backend: dns.asyncbackend.Backend,
        one_rr_per_rrset: bool = False,
        ignore_trailing: bool = False,
    ) -> dns.message.Message:
        return await dns.asyncquery.quic(
            request,
            self.address,
            port=self.port,
            timeout=timeout,
            one_rr_per_rrset=one_rr_per_rrset,
            ignore_trailing=ignore_trailing,
            verify=self.verify,
            server_hostname=self.server_hostname,
        )
