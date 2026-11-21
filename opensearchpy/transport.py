# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright OpenSearch Contributors. See
# GitHub history for details.
#
#  Licensed to Elasticsearch B.V. under one or more contributor
#  license agreements. See the NOTICE file distributed with
#  this work for additional information regarding copyright
#  ownership. Elasticsearch B.V. licenses this file to you under
#  the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
# 	http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing,
#  software distributed under the License is distributed on an
#  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#  KIND, either express or implied.  See the License for the
#  specific language governing permissions and limitations
#  under the License.


import inspect
import logging
import threading
import time
from itertools import chain
from typing import (
    Any,
    Callable,
    Collection,
    Dict,
    List,
    Mapping,
    Optional,
    Type,
    Union,
)

from opensearchpy.metrics import Metrics, MetricsNone

from .connection import Connection, Urllib3HttpConnection
from .connection_policy import ConnectionPolicy
from .connection_pool import ConnectionPool, DummyConnectionPool, EmptyConnectionPool
from .exceptions import (
    ConnectionError,
    ConnectionPolicyError,
    ConnectionTimeout,
    SerializationError,
    TransportError,
)
from .serializer import DEFAULT_SERIALIZERS, Deserializer, JSONSerializer, Serializer

logger = logging.getLogger("opensearch")


def get_host_info(
    node_info: Dict[str, Any], host: Optional[Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    """
    Simple callback that takes the node info from `/_cluster/nodes` and a
    parsed connection information and return the connection information. If
    `None` is returned this node will be skipped.

    Useful for filtering nodes (by proximity for example) or if additional
    information needs to be provided for the :class:`~opensearchpy.Connection`
    class. By default cluster_manager only nodes are filtered out since they shouldn't
    typically be used for API operations.

    :arg node_info: node information from `/_cluster/nodes`
    :arg host: connection information (host, port) extracted from the node info
    """
    # ignore cluster_manager only nodes
    if node_info.get("roles", []) == ["cluster_manager"]:
        return None
    return host


class Transport:
    """
    Encapsulation of transport-related to logic. Handles instantiation of the
    individual connections as well as creating a connection pool to hold them.

    Main interface is the `perform_request` method.
    """

    DEFAULT_CONNECTION_CLASS: Type[Connection] = Urllib3HttpConnection

    connection_pool: Any
    deserializer: Deserializer

    max_retries: int
    retry_on_timeout: bool
    retry_on_status: Collection[int]
    send_get_body_as: str
    serializer: Serializer
    connection_pool_class: Any
    connection_class: Type[Connection]
    kwargs: Any
    hosts: Any
    seed_connections: List[Connection]
    sniffer_timeout: Optional[float]
    sniff_on_start: bool
    sniff_on_connection_fail: bool
    last_sniff: float
    sniff_timeout: Optional[float]
    host_info_callback: Any
    metrics: Metrics
    generation: Any
    generation_label: Any

    def __init__(
        self,
        hosts: Any,
        connection_class: Optional[Type[Connection]] = None,
        connection_pool_class: Type[ConnectionPool] = ConnectionPool,
        host_info_callback: Callable[
            [Dict[str, Any], Optional[Dict[str, Any]]], Optional[Dict[str, Any]]
        ] = get_host_info,
        sniff_on_start: bool = False,
        sniffer_timeout: Optional[float] = None,
        sniff_timeout: float = 0.1,
        sniff_on_connection_fail: bool = False,
        serializer: Serializer = JSONSerializer(),
        serializers: Optional[Mapping[str, Serializer]] = None,
        default_mimetype: str = "application/json",
        max_retries: int = 3,
        pool_maxsize: Optional[int] = None,
        retry_on_status: Collection[int] = (502, 503, 504),
        retry_on_timeout: bool = False,
        send_get_body_as: str = "GET",
        metrics: Metrics = MetricsNone(),
        **kwargs: Any
    ) -> None:
        """
        :arg hosts: list of dictionaries, each containing keyword arguments to
            create a `connection_class` instance
        :arg connection_class: subclass of :class:`~opensearchpy.Connection` to use
        :arg connection_pool_class: subclass of :class:`~opensearchpy.ConnectionPool` to use
        :arg host_info_callback: callback responsible for taking the node information from
            `/_cluster/nodes`, along with already extracted information, and
            producing a list of arguments (same as `hosts` parameter)
        :arg sniff_on_start: flag indicating whether to obtain a list of nodes
            from the cluster at startup time
        :arg sniffer_timeout: number of seconds between automatic sniffs
        :arg sniff_on_connection_fail: flag controlling if connection failure triggers a sniff
        :arg sniff_timeout: timeout used for the sniff request - it should be a
            fast api call and we are talking potentially to more nodes so we want
            to fail quickly. Not used during initial sniffing (if
            ``sniff_on_start`` is on) when the connection still isn't
            initialized.
        :arg serializer: serializer instance
        :arg serializers: optional dict of serializer instances that will be
            used for deserializing data coming from the server. (key is the mimetype)
        :arg default_mimetype: when no mimetype is specified by the server
            response assume this mimetype, defaults to `'application/json'`
        :arg max_retries: maximum number of retries before an exception is propagated
        :arg retry_on_status: set of HTTP status codes on which we should retry
            on a different node. defaults to ``(502, 503, 504)``
        :arg retry_on_timeout: should timeout trigger a retry on different
            node? (default `False`)
        :arg send_get_body_as: for GET requests with body this option allows
            you to specify an alternate way of execution for environments that
            don't support passing bodies with GET requests. If you set this to
            'POST' a POST method will be used instead, if to 'source' then the body
            will be serialized and passed as a query parameter `source`.
        :arg pool_maxsize: Maximum connection pool size used by pool-manager
            For custom connection-pooling on current session
        :arg metrics: metrics is an instance of a subclass of the
            :class:`~opensearchpy.Metrics` class, used for collecting
            and reporting metrics related to the client's operations;

        Any extra keyword arguments will be passed to the `connection_class`
        when creating and instance unless overridden by that connection's
        options provided as part of the hosts parameter.
        """
        self.metrics = metrics
        if connection_class is None:
            connection_class = self.DEFAULT_CONNECTION_CLASS

        # serialization config
        _serializers = DEFAULT_SERIALIZERS.copy()
        # if a serializer has been specified, use it for deserialization as well
        _serializers[serializer.mimetype] = serializer
        # if custom serializers map has been supplied, override the defaults with it
        if serializers:
            _serializers.update(serializers)
        # create a deserializer with our config
        self.deserializer = Deserializer(_serializers, default_mimetype)

        self.max_retries = max_retries
        self.pool_maxsize = pool_maxsize
        self.retry_on_timeout = retry_on_timeout
        self.retry_on_status = retry_on_status
        self.send_get_body_as = send_get_body_as

        # data serializer
        self.serializer = serializer

        # store all strategies...
        self.connection_pool_class = connection_pool_class
        self.connection_class = connection_class

        # ...save kwargs to be passed to the connections
        self.kwargs = kwargs
        # Client-wide options are kept separately: policy options are merged
        # onto these on every reload, never onto the previous policy.
        self._base_kwargs = dict(kwargs)
        self.hosts = hosts

        # Start with an empty pool specifically for `AsyncTransport`.
        # It should never be used, will be replaced on first call to
        # .set_connections()
        self.connection_pool = EmptyConnectionPool()
        self.generation: Any = 0
        self.generation_label: Any = "initial"

        # Guards replacement of ``connection_pool`` and tracks requests that
        # were delegated to a pool which has since been superseded.  Old pools
        # are only closed once the last in-flight request using them returns.
        self._pool_lock = threading.RLock()
        self._pool_refcounts: Dict[int, int] = {}
        self._retired_pools: Dict[int, Any] = {}
        self._generation_counter = 0

        if hosts:
            # ...and instantiate them
            self.set_connections(hosts)
            # retain the original connection instances for sniffing
            self.seed_connections = list(self.connection_pool.connections[:])
        else:
            self.seed_connections = []

        # sniffing data
        self.sniffer_timeout = sniffer_timeout
        self.sniff_on_start = sniff_on_start
        self.sniff_on_connection_fail = sniff_on_connection_fail
        self.last_sniff = time.time()
        self.sniff_timeout = sniff_timeout

        # callback to construct host dict from data in /_cluster/nodes
        self.host_info_callback = host_info_callback

        if sniff_on_start:
            self.sniff_hosts(True)

    def add_connection(self, host: Any) -> None:
        """
        Create a new :class:`~opensearchpy.Connection` instance and add it to the pool.

        :arg host: kwargs that will be used to create the instance
        """
        self.hosts.append(host)
        self.set_connections(self.hosts)

    def set_connections(self, hosts: Any, reuse_connections: bool = True) -> None:
        """
        Instantiate all the connections and create new connection pool to hold them.
        Tries to identify unchanged hosts and re-use existing
        :class:`~opensearchpy.Connection` instances.

        :arg hosts: same as `__init__`
        :arg reuse_connections: when ``False`` every connection is rebuilt.  A
            policy reload uses this so that new TLS material is guaranteed to
            be used even when the host options did not change.
        """

        # construct the connections
        def _create_connection(host: Any) -> Any:
            # if this is not the initial setup look at the existing connection
            # options and identify connections that haven't changed and can be
            # kept around.
            if reuse_connections and hasattr(self, "connection_pool"):
                for connection, old_host in self.connection_pool.connection_opts:
                    if old_host == host:
                        return connection

            # previously unseen params, create new connection
            kwargs = self.kwargs.copy()
            kwargs.update(host)
            if self.pool_maxsize and isinstance(self.pool_maxsize, int):
                kwargs["pool_maxsize"] = self.pool_maxsize
            return self.connection_class(metrics=self.metrics, **kwargs)

        connections = list(zip(map(_create_connection, hosts), hosts))
        self.connection_pool = self._make_pool(connections)

    def _make_pool(
        self,
        connections: Any,
        pool_class: Optional[Type[ConnectionPool]] = None,
        pool_kwargs: Optional[Mapping[str, Any]] = None,
        generation: Any = None,
        label: Any = None,
    ) -> Any:
        """Build a pool and stamp each connection with its generation."""
        generation = self.generation if generation is None else generation
        label = self.generation_label if label is None else label
        for connection, _ in connections:
            try:
                connection.generation = generation
                connection.generation_label = label
            except AttributeError:
                # Bare objects used by custom pools/tests may not allow
                # arbitrary attributes; generation semantics do not apply.
                pass

        kwargs = dict(pool_kwargs if pool_kwargs is not None else self.kwargs)
        kwargs["generation"] = generation
        kwargs["label"] = label

        target_class = (
            pool_class
            if pool_class is not None
            else DummyConnectionPool
            if len(connections) == 1
            else self.connection_pool_class
        )
        if not self._accepts_kwargs(target_class):
            kwargs.pop("generation", None)
            kwargs.pop("label", None)
        # pass the hosts dicts to the connection pool to optionally extract parameters from
        return target_class(connections, **kwargs)

    @staticmethod
    def _accepts_kwargs(target: Any) -> bool:
        try:
            parameters = inspect.signature(target.__init__).parameters.values()
        except (TypeError, ValueError):  # pragma: no cover - builtins
            return True
        return any(
            parameter.kind is inspect.Parameter.VAR_KEYWORD
            for parameter in parameters
        )

    def get_connection(self) -> Any:
        """
        Retrieve a :class:`~opensearchpy.Connection` instance from the
        :class:`~opensearchpy.ConnectionPool` instance.
        """
        self._maybe_sniff()
        return self.connection_pool.get_connection()

    def _maybe_sniff(self) -> None:
        if self.sniffer_timeout:
            if time.time() >= self.last_sniff + self.sniffer_timeout:
                self.sniff_hosts()

    def _get_sniff_data(self, initial: bool = False) -> Any:
        """
        Perform the request to get sniffing information. Returns a list of
        dictionaries (one per node) containing all the information from the
        cluster.

        It also sets the last_sniff attribute in case of a successful attempt.

        In rare cases it might be possible to override this method in your
        custom Transport class to serve data from alternative source like
        configuration management.
        """
        previous_sniff = self.last_sniff

        try:
            # reset last_sniff timestamp
            self.last_sniff = time.time()
            # go through all current connections as well as the
            # seed_connections for good measure
            for c in chain(self.connection_pool.connections, self.seed_connections):
                try:
                    # use small timeout for the sniffing request, should be a fast api call
                    _, headers, node_info = c.perform_request(
                        "GET",
                        "/_nodes/_all/http",
                        timeout=self.sniff_timeout if not initial else None,
                    )

                    # Lowercase all the header names for consistency in accessing them.
                    headers = {
                        header.lower(): value for header, value in headers.items()
                    }

                    node_info = self.deserializer.loads(
                        node_info, headers.get("content-type")
                    )
                    break
                except (ConnectionError, SerializationError):
                    pass
            else:
                raise TransportError("N/A", "Unable to sniff hosts.")
        except Exception:
            # keep the previous value on error
            self.last_sniff = previous_sniff
            raise

        return list(node_info["nodes"].values())

    def _get_host_info(self, host_info: Any) -> Any:
        host = {}
        address = host_info.get("http", {}).get("publish_address")

        # malformed or no address given
        if not address or ":" not in address:
            return None

        if "/" in address:
            # Support 7.x host/ip:port behavior where http.publish_host has been set.
            fqdn, ipaddress = address.split("/", 1)
            host["host"] = fqdn
            _, host["port"] = ipaddress.rsplit(":", 1)
            host["port"] = int(host["port"])

        else:
            host["host"], host["port"] = address.rsplit(":", 1)
            host["port"] = int(host["port"])

        return self.host_info_callback(host_info, host)

    def sniff_hosts(self, initial: bool = False) -> Any:
        """
        Obtain a list of nodes from the cluster and create a new connection
        pool using the information retrieved.

        To extract the node connection parameters use the ``nodes_to_host_callback``.

        :arg initial: flag indicating if this is during startup
            (``sniff_on_start``), ignore the ``sniff_timeout`` if ``True``
        """
        node_info = self._get_sniff_data(initial)

        hosts: Any = list(filter(None, (self._get_host_info(n) for n in node_info)))

        # we weren't able to get any nodes or host_info_callback blocked all -
        # raise error.
        if not hosts:
            raise TransportError(
                "N/A", "Unable to sniff hosts - no viable hosts found."
            )

        self.set_connections(hosts)

    def mark_dead(self, connection: Connection) -> None:
        """
        Mark a connection as dead (failed) in the connection pool. If sniffing
        on failure is enabled this will initiate the sniffing process.

        :arg connection: instance of :class:`~opensearchpy.Connection` that failed
        """
        self._mark_dead_on(self.connection_pool, connection)

    def _mark_dead_on(self, pool: Any, connection: Connection) -> None:
        # mark as dead even when sniffing to avoid hitting this host during the sniff process
        pool.mark_dead(connection)
        if self.sniff_on_connection_fail:
            self.sniff_hosts()

    def _acquire_pool(self) -> Any:
        """Pin the current pool for the duration of a request.

        Requests that were delegated before a policy reload keep using the
        pool they started with, and keep it from being closed until they
        finish.
        """
        with self._pool_lock:
            pool = self.connection_pool
            key = id(pool)
            self._pool_refcounts[key] = self._pool_refcounts.get(key, 0) + 1
            return pool

    def _release_pool(self, pool: Any) -> Any:
        """Release a pinned pool.

        Returns the pool when it had already been superseded by a reload and
        this was its last in-flight request, so the caller can close it.
        """
        with self._pool_lock:
            key = id(pool)
            count = self._pool_refcounts.get(key, 1) - 1
            if count > 0:
                self._pool_refcounts[key] = count
                return None
            self._pool_refcounts.pop(key, None)
            return self._retired_pools.pop(key, None)

    def _retire_pool_locked(self, pool: Any) -> Any:
        """Return a pool to close now, or stash it until in-flight requests end."""
        key = id(pool)
        if self._pool_refcounts.get(key, 0) > 0:
            self._retired_pools[key] = pool
            return None
        return pool

    def _close_pool(self, pool: Any) -> None:
        if pool is None:
            return
        try:
            pool.close()
        except Exception:  # pragma: no cover - closing is best effort
            logger.exception("Error while closing a superseded connection pool.")

    def _resolve_connection_policy(self, policy: Any) -> ConnectionPolicy:
        # A loader callback lets an application read the new CA material at
        # reload time. If it raises, nothing is swapped.
        if callable(policy) and not isinstance(policy, type):
            policy = policy()

        if isinstance(policy, ConnectionPolicy):
            resolved = policy
        elif isinstance(policy, Mapping):
            resolved = ConnectionPolicy.from_mapping(policy)
        else:
            raise ConnectionPolicyError(
                "A connection policy must be a ConnectionPolicy, a mapping or a "
                f"callable returning one; got {type(policy).__name__}."
            )

        if resolved.generation is None:
            with self._pool_lock:
                self._generation_counter += 1
                resolved = resolved.with_generation(self._generation_counter)
        elif isinstance(resolved.generation, int):
            with self._pool_lock:
                self._generation_counter = max(
                    self._generation_counter, resolved.generation
                )

        if resolved.label is None:
            resolved = ConnectionPolicy(
                hosts=resolved.hosts,
                generation=resolved.generation,
                connection_class=resolved.connection_class,
                connection_pool_class=resolved.connection_pool_class,
                label=str(resolved.generation),
                options=resolved.options,
            )

        resolved.validate(base=self._base_kwargs)
        return resolved

    def _build_policy_pool(self, policy: ConnectionPolicy) -> Any:
        # Merged view of client-wide options and the new policy. Paths that
        # do not exist are rejected by ``validate`` before anything is built.
        effective = policy.connection_kwargs(self._base_kwargs)
        connection_class = policy.connection_class or self.connection_class
        pool_class = policy.connection_pool_class

        connections = []
        try:
            for host in policy.hosts or ():
                kwargs = dict(effective)
                kwargs.update(host)
                if self.pool_maxsize and isinstance(self.pool_maxsize, int):
                    kwargs["pool_maxsize"] = self.pool_maxsize
                connections.append(
                    (connection_class(metrics=self.metrics, **kwargs), host)
                )
        except Exception:
            # Do not leak partially constructed (and possibly TLS) sockets.
            for connection, _ in connections:
                try:
                    connection.close()
                except Exception:
                    pass
            raise

        try:
            return self._make_pool(
                connections,
                pool_class=pool_class,
                pool_kwargs=effective,
                generation=policy.generation,
                label=policy.label,
            )
        except Exception:
            for connection, _ in connections:
                try:
                    connection.close()
                except Exception:
                    pass
            raise

    def reload_connection_policy(self, policy: Any) -> Any:
        """Atomically switch the transport to a new connection policy.

        ``policy`` may be a :class:`~opensearchpy.ConnectionPolicy`, a mapping
        with the same fields, or a zero-argument callable that loads one (for
        example by reading a rotated CA bundle). The replacement pool and all
        of its connections are built and validated *before* the swap. If the
        loader, validation or connection construction fails,
        :class:`~opensearchpy.ConnectionPolicyError` is raised and the current
        pool remains fully usable.

        Requests that were already delegated to the previous pool keep using
        it and complete normally; the previous pool is closed only after the
        last such request returns.

        Returns the newly activated pool. Its ``generation`` (and the
        ``generation`` of every connection in it) identifies the policy.
        """
        try:
            resolved = self._resolve_connection_policy(policy)
            new_pool = self._build_policy_pool(resolved)
        except ConnectionPolicyError:
            raise
        except Exception as e:
            raise ConnectionPolicyError(
                f"Unable to load connection policy: {e}"
            ) from e

        to_close = self._install_policy(resolved, new_pool)
        self._close_pool(to_close)
        return new_pool

    def _install_policy(self, policy: ConnectionPolicy, new_pool: Any) -> Any:
        """Swap the pool and publish the matching generation metadata."""
        with self._pool_lock:
            old_pool = self.connection_pool
            self.connection_pool = new_pool
            self.connection_policy = policy
            self.generation = policy.generation
            self.generation_label = policy.label
            self.hosts = list(policy.hosts or ())
            # Sniffing must fall back to connections built with the new policy.
            self.seed_connections = list(new_pool.connections)
            # Keep new TLS/connection options for future sniff-driven rebuilds.
            self.kwargs = policy.connection_kwargs(self._base_kwargs)
            return self._retire_pool_locked(old_pool)

    def perform_request(
        self,
        method: str,
        url: str,
        params: Optional[Mapping[str, Any]] = None,
        body: Any = None,
        timeout: Optional[Union[int, float]] = None,
        ignore: Collection[int] = (),
        headers: Optional[Mapping[str, str]] = None,
    ) -> Any:
        """
        Perform the actual request. Retrieve a connection from the connection
        pool, pass all the information to its perform_request method and
        return the data.

        If an exception was raised, mark the connection as failed and retry (up
        to `max_retries` times).

        If the operation was successful and the connection used was previously
        marked as dead, mark it as live, resetting its failure count.

        :arg method: HTTP method to use
        :arg url: absolute url (without host) to target
        :arg headers: dictionary of headers, will be handed over to the
            underlying :class:`~opensearchpy.Connection` class
        :arg params: dictionary of query parameters, will be handed over to the
            underlying :class:`~opensearchpy.Connection` class for serialization
        :arg body: body of the request, will be serialized using serializer and
            passed to the connection
        :arg timeout: timeout of the request. If it is not presented as argument
            will be extracted from `params`
        """
        method, params, body, ignore, timeout = self._resolve_request_args(
            method, params, body, ignore, timeout
        )

        self._maybe_sniff()
        # Pin one pool for the entire request (including retries) so that a
        # concurrent policy reload cannot split a request across generations.
        pool = self._acquire_pool()
        try:
            for attempt in range(self.max_retries + 1):
                connection = pool.get_connection()

                try:
                    status, headers_response, data = connection.perform_request(
                        method,
                        url,
                        params,
                        body,
                        headers=headers,
                        ignore=ignore,
                        timeout=timeout,
                    )

                    # Lowercase all the header names for consistency in accessing them.
                    headers_response = {
                        header.lower(): value
                        for header, value in headers_response.items()
                    }

                except TransportError as e:
                    if method == "HEAD" and e.status_code == 404:
                        return False

                    retry = False
                    if isinstance(e, ConnectionTimeout):
                        retry = self.retry_on_timeout
                    elif isinstance(e, ConnectionError):
                        retry = True
                    elif e.status_code in self.retry_on_status:
                        retry = True

                    if retry:
                        try:
                            # only mark as dead if we are retrying
                            self._mark_dead_on(pool, connection)
                        except TransportError:
                            # If sniffing on failure, it could fail too. Catch the
                            # exception not to interrupt the retries.
                            pass
                        # raise exception on last retry
                        if attempt == self.max_retries:
                            raise e
                    else:
                        raise e

                else:
                    # connection didn't fail, confirm its live status
                    pool.mark_live(connection)

                    if method == "HEAD":
                        return 200 <= status < 300

                    if data:
                        data = self.deserializer.loads(
                            data, headers_response.get("content-type")
                        )
                    return data
        finally:
            retired = self._release_pool(pool)
            if retired is not None:
                self._close_pool(retired)

    def close(self) -> Any:
        """
        Explicitly closes connections
        """
        with self._pool_lock:
            pools = [self.connection_pool]
            pools.extend(self._retired_pools.values())
            self._retired_pools.clear()
            self._pool_refcounts.clear()
        for pool in pools:
            self._close_pool(pool)

    def _resolve_request_args(
        self,
        method: str,
        params: Any,
        body: Any,
        ignore: Collection[int],
        timeout: Optional[Union[int, float]],
    ) -> Any:
        """Resolves parameters for .perform_request()"""
        if body is not None:
            body = self.serializer.dumps(body)

            # some clients or environments don't support sending GET with body
            if method in ("HEAD", "GET") and self.send_get_body_as != "GET":
                # send it as post instead
                if self.send_get_body_as == "POST":
                    method = "POST"

                # or as source parameter
                elif self.send_get_body_as == "source":
                    if params is None:
                        params = {}
                    params["source"] = body
                    body = None

        if body is not None:
            try:
                body = body.encode("utf-8", "surrogatepass")
            except (UnicodeDecodeError, AttributeError):
                # bytes/str - no need to re-encode
                pass

        if params:
            if not timeout:
                timeout = params.pop("request_timeout", None) or params.pop(
                    "timeout", None
                )
            if not ignore:
                ignore = params.pop("ignore", ())
            if isinstance(ignore, int):
                ignore = (ignore,)

        return method, params, body, ignore, timeout


__all__ = ["TransportError"]
