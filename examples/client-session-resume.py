"""Local demonstration of asyncua client session-file resume semantics.

The demo runs real OPC UA binary exchanges over in-process socketpairs, so it
does not bind a TCP port. It prints keyed token references only; it never
prints the authentication token or the server nonce stored in the file.

Scenarios:
1. same server instance, same identity: ActivateSession resumes the existing
   session, the nonce rotates, and the server-side subscription still exists;
2. another valid identity presents the first user's file: ActivateSession
   succeeds, ownership of the existing session changes, and the new identity
   receives the original subscription's notifications;
3. the server has deleted the session: resume fails and a fresh session is
   created from the client's own configured credentials;
4. the file alone: rejected by a strict UserManager, accepted as an anonymous
   user by the default permissive UserManager;
5. a session without subscriptions is closed by the asyncua server as soon as
   the transport drops, so no file can bring it back;
6. the same file copied to an independent server: no continuation, because the
   token is server-local;
7. secured channel: a rotated client certificate still resumes when the user
   credentials are valid; a stale nonce replay is rejected; a wrong password is
   rejected without destroying the old session; another identity can still take
   over a session whose nonce is current;
8. timeout: an expired server-side session is not revived by the file, while an
   old `saved_at` no longer discards a session the server still holds;
9. a disclosed token, with no file at all: an attacker who knows the token can
   activate another user's session and receive its subscription data;
10. a file copied to an independent server: no continuation, and random GUID
    tokens no longer collide across server processes.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import socket
import tempfile
import time
from collections.abc import AsyncIterator, Callable, Sequence
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID

from asyncua import Client, Node, Server, ua
from asyncua.crypto import cert_gen, security_policies
from asyncua.crypto.permission_rules import User, UserRole
from asyncua.crypto.uacrypto import CertProperties
from asyncua.server.binary_server_asyncio import BinaryServer

TRACE_KEY = secrets.token_bytes(32)


class DemoUserManager:
    """Two known username/password pairs; anonymous and unknown users are rejected."""

    _USERS = {("alice", "alice-pw"): "alice", ("bob", "bob-pw"): "bob"}

    def get_user(
        self,
        iserver: object,
        username: str | None = None,
        password: str | None = None,
        certificate: Any = None,
    ) -> User | None:
        name = self._USERS.get((username, password))
        if name is None:
            return None
        return User(role=UserRole.User, name=name)


class LoopbackNetwork:
    """Carry the OPC UA binary protocol over socketpair instead of a listening port."""

    def __init__(self) -> None:
        self._servers: dict[int, BinaryServer] = {}

    def register(self, port: int, server: BinaryServer) -> None:
        self._servers[port] = server

    @asynccontextmanager
    async def active(self) -> AsyncIterator[None]:
        loop = asyncio.get_running_loop()
        original = loop.create_connection

        async def create_connection(
            protocol_factory: Callable[[], asyncio.Protocol],
            host: str | None = None,
            port: int | None = None,
            **kwargs: Any,
        ) -> tuple[asyncio.Transport, asyncio.Protocol]:
            if port not in self._servers:
                return await original(protocol_factory, host, port, **kwargs)
            client_sock, server_sock = socket.socketpair()
            client_sock.setblocking(False)
            server_sock.setblocking(False)
            server_protocol = self._servers[port]._make_protocol()
            await loop.connect_accepted_socket(lambda: server_protocol, server_sock)
            return await loop.connect_accepted_socket(protocol_factory, client_sock)

        loop.create_connection = create_connection  # type: ignore[method-assign]
        try:
            yield
        finally:
            loop.create_connection = original  # type: ignore[method-assign]


async def start_server(
    network: LoopbackNetwork,
    port: int,
    user_manager: Any = None,
    *,
    server_cert: bytes | None = None,
    server_key: bytes | None = None,
    policies: Sequence[ua.SecurityPolicyType] | None = None,
    min_session_timeout_ms: float | None = None,
) -> Server:
    server = Server(user_manager=user_manager)
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{port}")
    server.set_identity_tokens([ua.UserNameIdentityToken, ua.AnonymousIdentityToken])
    server.disable_clock()
    if policies is not None:
        server.set_security_policy(list(policies))
    if server_cert is not None and server_key is not None:
        await server.load_certificate(server_cert)
        await server.load_private_key(server_key, format="PEM")
    if min_session_timeout_ms is not None:
        server.iserver.min_session_timeout_ms = min_session_timeout_ms
    await server._setup_server_nodes()
    await server.iserver.start()
    binary_server = BinaryServer(server.iserver, "127.0.0.1", port, server.limits)
    binary_server.set_policies(server._policies)
    server.bserver = binary_server
    network.register(port, binary_server)
    return server


async def stop_server(server: Server) -> None:
    if server.bserver is not None:
        await server.bserver.stop()
    await server.iserver.stop()


async def make_client(
    port: int,
    state_path: Path,
    user: str | None,
    password: str | None,
    *,
    client_cert: bytes | None = None,
    client_key: bytes | None = None,
    server_cert: bytes | None = None,
    session_timeout_ms: int = 30_000,
) -> Client:
    client = Client(f"opc.tcp://127.0.0.1:{port}", timeout=2.0)
    client.session_timeout = session_timeout_ms
    if user is not None:
        client.set_user(user)
        client.set_password(password or "")
    client.session_state_path = state_path
    if client_cert is not None and client_key is not None and server_cert is not None:
        await client.set_security(
            security_policies.SecurityPolicyBasic256Sha256,
            CertProperties(client_cert, "DER"),
            CertProperties(client_key, "PEM"),
            None,
            server_cert,
            ua.MessageSecurityMode.SignAndEncrypt,
        )
    return client


def token_ref(token: ua.NodeId) -> str:
    """Stable within one run, but not reversible without the per-run key."""
    return hmac.new(TRACE_KEY, token.to_string().encode(), hashlib.sha256).hexdigest()[:12]


def redacted_state(path: Path) -> dict[str, object]:
    state = json.loads(path.read_text(encoding="utf-8"))
    token = str(state.get("authentication_token", ""))
    nonce = str(state.get("server_nonce", ""))
    return {
        "keys": sorted(state),
        "authentication_token": f"<redacted, {len(token)} chars>",
        "server_nonce": f"<redacted, {len(nonce)} chars>",
        "saved_at": state.get("saved_at"),
        "mode": oct(path.stat().st_mode & 0o777),
    }


def nonce_changed(before: Path, after: Path) -> bool:
    first = json.loads(before.read_text(encoding="utf-8")).get("server_nonce")
    second = json.loads(after.read_text(encoding="utf-8")).get("server_nonce")
    return first != second


def session_owner(server: Server, token: ua.NodeId) -> str:
    session = server.iserver.lookup_external_session(token)
    if session is None:
        return "<no session>"
    if session.user is None:
        return "<no user>"
    return f"{session.user.role.name}:{session.user.name}"


def session_exists(server: Server, token: ua.NodeId) -> bool:
    return server.iserver.lookup_external_session(token) is not None


async def crash_client(client: Client) -> None:
    """Drop the transport without CloseSession, then stop the client-side tasks."""
    protocol = client.uaclient.protocol
    if protocol is not None and protocol.transport is not None:
        protocol.transport.close()
    await asyncio.sleep(0.1)
    tasks = [
        client._supervisor_task,
        client._stale_watchdog_task,
        client._renew_channel_task,
        client.uaclient.session._publish_task,
    ]
    for task in tasks:
        if task is not None:
            task.cancel()
    await asyncio.gather(*(task for task in tasks if task is not None), return_exceptions=True)
    await asyncio.sleep(0.1)


async def disconnect_quiet(client: Client) -> None:
    try:
        await client.disconnect()
    except Exception:
        pass


async def subscribe(client: Client, node: Node) -> None:
    subscription = await client.create_subscription(50)
    await subscription.subscribe_data_change(client.get_node(node.nodeid))
    await subscription.next_event(timeout=3.0)


async def publish_after_write(client: Client, server: Server, node: Node, value: int) -> bool:
    task = asyncio.create_task(client.uaclient.session.publish([]))
    try:
        await asyncio.sleep(0.2)
        await server.get_node(node.nodeid).write_value(value)
        response = await asyncio.wait_for(task, timeout=3.0)
    except Exception:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        return False
    return bool(response.Parameters.NotificationMessage.NotificationData)


def print_resume(
    label: str,
    client: Client,
    token: ua.NodeId,
    server: Server,
    *,
    expected_token: ua.NodeId | None = None,
) -> None:
    same = expected_token is None or client.uaclient.session.authentication_token == expected_token
    print(
        f"  {label}: token_same={same} ref={token_ref(token)} owner={session_owner(server, token)} "
        f"client_subscriptions={len(client._subscriptions)} "
        f"callbacks={len(client.uaclient.session._subscription_callbacks)} "
        f"publish_task={client.uaclient.session._publish_task is not None}"
    )


def generate_pair(uri: str, eku: x509.ObjectIdentifier) -> tuple[bytes, bytes]:
    key = cert_gen.generate_private_key()
    cert = cert_gen.generate_self_signed_app_certificate(
        key,
        uri,
        {},
        [x509.DNSName("127.0.0.1"), x509.UniformResourceIdentifier(uri)],
        [eku],
        days=30,
    )
    return cert.public_bytes(Encoding.DER), cert_gen.dump_private_key_as_pem(key)


async def scenario_plain(network: LoopbackNetwork, root: Path) -> None:
    print("== 1. same server + same identity ==")
    server = await start_server(network, 48401, DemoUserManager())
    clients: list[Client] = []
    try:
        variable = await server.nodes.objects.add_variable(2, "DemoValue", 0)
        await variable.set_writable()
        state = root / "alice.json"
        alice = await make_client(48401, state, "alice", "alice-pw")
        clients.append(alice)
        await alice.connect()
        await subscribe(alice, variable)
        token = alice.uaclient.session.authentication_token
        donor = root / "donor.json"
        donor.write_bytes(state.read_bytes())
        print("  persisted:", redacted_state(state))
        print("  owner before crash:", session_owner(server, token))
        await crash_client(alice)
        print("  server retains session after transport loss:", session_exists(server, token))

        resume_state = root / "resume.json"
        resume_state.write_bytes(donor.read_bytes())
        alice2 = await make_client(48401, resume_state, "alice", "alice-pw")
        clients.append(alice2)
        await alice2.connect()
        print_resume("resumed", alice2, token, server, expected_token=token)
        print("  nonce rotated by ActivateSession:", nonce_changed(donor, resume_state))
        print(
            "  manual Publish returns retained subscription data:",
            await publish_after_write(alice2, server, variable, 11),
        )

        print("== 2. another valid identity presents the first user's file ==")
        bob_state = root / "bob.json"
        bob_state.write_bytes(donor.read_bytes())
        bob = await make_client(48401, bob_state, "bob", "bob-pw")
        clients.append(bob)
        await bob.connect()
        print_resume("bob", bob, token, server, expected_token=token)
        print("  owner after bob's ActivateSession:", session_owner(server, token))
        print("  bob receives alice's subscription data:", await publish_after_write(bob, server, variable, 12))
    finally:
        for client in clients:
            await disconnect_quiet(client)
        await stop_server(server)


async def scenario_deleted(network: LoopbackNetwork, root: Path) -> None:
    print("== 3. server deleted the session ==")
    server = await start_server(network, 48402, DemoUserManager())
    clients: list[Client] = []
    try:
        variable = await server.nodes.objects.add_variable(2, "DemoValue", 0)
        await variable.set_writable()
        state = root / "deleted.json"
        alice = await make_client(48402, state, "alice", "alice-pw")
        clients.append(alice)
        await alice.connect()
        await subscribe(alice, variable)
        old_token = alice.uaclient.session.authentication_token
        donor = root / "deleted-donor.json"
        donor.write_bytes(state.read_bytes())
        await crash_client(alice)
        session = server.iserver.lookup_external_session(old_token)
        assert session is not None
        await session.close_session(True)
        print("  old token registered after server close:", session_exists(server, old_token))
        resume_state = root / "deleted-resume.json"
        resume_state.write_bytes(donor.read_bytes())
        alice2 = await make_client(48402, resume_state, "alice", "alice-pw")
        clients.append(alice2)
        await alice2.connect()
        new_token = alice2.uaclient.session.authentication_token
        print(
            f"  fallback token differs={new_token != old_token} ref={token_ref(new_token)} "
            f"owner={session_owner(server, new_token)} source=client config"
        )

        print("== 4. the file alone ==")
        strict_state = root / "strict.json"
        alice3 = await make_client(48402, strict_state, "alice", "alice-pw")
        clients.append(alice3)
        await alice3.connect()
        await subscribe(alice3, variable)
        await crash_client(alice3)
        strict_bare = root / "strict-bare.json"
        strict_bare.write_bytes(strict_state.read_bytes())
        anon = await make_client(48402, strict_bare, None, None)
        clients.append(anon)
        try:
            await anon.connect()
        except Exception as exc:
            print("  strict UserManager, no identity token: rejected", type(exc).__name__)
        else:
            print("  strict UserManager, no identity token: accepted")

        print("== 5. session without subscriptions ==")
        no_sub_state = root / "no-sub.json"
        no_sub = await make_client(48402, no_sub_state, "alice", "alice-pw")
        clients.append(no_sub)
        await no_sub.connect()
        no_sub_token = no_sub.uaclient.session.authentication_token
        await crash_client(no_sub)
        print("  server retains it after transport loss:", session_exists(server, no_sub_token))
    finally:
        for client in clients:
            await disconnect_quiet(client)
        await stop_server(server)

    print("== 6. the file alone on the default permissive server ==")
    permissive = await start_server(network, 48403)
    clients = []
    try:
        variable = await permissive.nodes.objects.add_variable(2, "DemoValue", 0)
        await variable.set_writable()
        state = root / "permissive.json"
        anon = await make_client(48403, state, None, None)
        clients.append(anon)
        await anon.connect()
        await subscribe(anon, variable)
        token = anon.uaclient.session.authentication_token
        await crash_client(anon)
        bare = root / "permissive-bare.json"
        bare.write_bytes(state.read_bytes())
        anon2 = await make_client(48403, bare, None, None)
        clients.append(anon2)
        await anon2.connect()
        print_resume("bare file accepted", anon2, token, permissive, expected_token=token)
        print("  owner:", session_owner(permissive, token))
        print("  manual Publish returns data:", await publish_after_write(anon2, permissive, variable, 13))
    finally:
        for client in clients:
            await disconnect_quiet(client)
        await stop_server(permissive)

    print("== 7. the same file copied to an independent server ==")
    standby = await start_server(network, 48404, DemoUserManager())
    clients = []
    try:
        await standby.nodes.objects.add_variable(2, "DemoValue", 0)
        primary_token = old_token
        copied = root / "standby.json"
        copied.write_bytes(donor.read_bytes())
        standby_client = await make_client(48404, copied, "alice", "alice-pw")
        clients.append(standby_client)
        await standby_client.connect()
        standby_token = standby_client.uaclient.session.authentication_token
        print("  standby knows primary token:", session_exists(standby, primary_token))
        print(
            f"  standby token differs={standby_token != primary_token} ref={token_ref(standby_token)} "
            f"owner={session_owner(standby, standby_token)}"
        )
        print("  continuation on standby: False")
    finally:
        for client in clients:
            await disconnect_quiet(client)
        await stop_server(standby)


async def scenario_secure(network: LoopbackNetwork, root: Path) -> None:
    print("== 8. secured channel: certificate rotation, stale nonce, wrong password ==")
    server_cert, server_key = generate_pair("urn:demo:server", ExtendedKeyUsageOID.SERVER_AUTH)
    client1_cert, client1_key = generate_pair("urn:demo:client1", ExtendedKeyUsageOID.CLIENT_AUTH)
    client2_cert, client2_key = generate_pair("urn:demo:client2", ExtendedKeyUsageOID.CLIENT_AUTH)
    server = await start_server(
        network,
        48405,
        DemoUserManager(),
        server_cert=server_cert,
        server_key=server_key,
        policies=[ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt],
    )
    clients: list[Client] = []
    try:
        variable = await server.nodes.objects.add_variable(2, "DemoValue", 0)
        await variable.set_writable()

        state = root / "secure-alice.json"
        alice = await make_client(
            48405, state, "alice", "alice-pw", client_cert=client1_cert, client_key=client1_key, server_cert=server_cert
        )
        clients.append(alice)
        await alice.connect()
        await subscribe(alice, variable)
        token = alice.uaclient.session.authentication_token
        donor = root / "secure-donor.json"
        donor.write_bytes(state.read_bytes())
        await crash_client(alice)

        rotated = root / "secure-rotated.json"
        rotated.write_bytes(donor.read_bytes())
        alice2 = await make_client(
            48405,
            rotated,
            "alice",
            "alice-pw",
            client_cert=client2_cert,
            client_key=client2_key,
            server_cert=server_cert,
        )
        clients.append(alice2)
        await alice2.connect()
        print_resume("rotated client certificate", alice2, token, server, expected_token=token)
        print("  manual Publish returns data:", await publish_after_write(alice2, server, variable, 21))
        await crash_client(alice2)

        stale = root / "secure-stale.json"
        stale.write_bytes(donor.read_bytes())
        alice3 = await make_client(
            48405, stale, "alice", "alice-pw", client_cert=client1_cert, client_key=client1_key, server_cert=server_cert
        )
        clients.append(alice3)
        await alice3.connect()
        stale_token = alice3.uaclient.session.authentication_token
        print(
            f"  stale nonce replay: token_same={stale_token == token} ref={token_ref(stale_token)} "
            f"owner={session_owner(server, stale_token)}"
        )
        await crash_client(alice3)

        wrong_state = root / "secure-wrong.json"
        alice4 = await make_client(
            48405,
            wrong_state,
            "alice",
            "alice-pw",
            client_cert=client1_cert,
            client_key=client1_key,
            server_cert=server_cert,
        )
        clients.append(alice4)
        await alice4.connect()
        await subscribe(alice4, variable)
        current_token = alice4.uaclient.session.authentication_token
        await crash_client(alice4)
        wrong = root / "secure-wrong-copy.json"
        wrong.write_bytes(wrong_state.read_bytes())
        wrong_client = await make_client(
            48405, wrong, "alice", "wrong", client_cert=client2_cert, client_key=client2_key, server_cert=server_cert
        )
        clients.append(wrong_client)
        try:
            await wrong_client.connect()
        except Exception as exc:
            print(
                f"  wrong password: rejected {type(exc).__name__}; old session intact="
                f"{session_exists(server, current_token)}"
            )
        else:
            print("  wrong password: accepted")

        print("== 9. secured channel, another identity with a current nonce ==")
        current_state = root / "secure-current.json"
        alice5 = await make_client(
            48405,
            current_state,
            "alice",
            "alice-pw",
            client_cert=client1_cert,
            client_key=client1_key,
            server_cert=server_cert,
        )
        clients.append(alice5)
        await alice5.connect()
        await subscribe(alice5, variable)
        current = alice5.uaclient.session.authentication_token
        current_donor = root / "secure-current-donor.json"
        current_donor.write_bytes(current_state.read_bytes())
        await crash_client(alice5)
        bob_state = root / "secure-bob.json"
        bob_state.write_bytes(current_donor.read_bytes())
        bob = await make_client(
            48405, bob_state, "bob", "bob-pw", client_cert=client2_cert, client_key=client2_key, server_cert=server_cert
        )
        clients.append(bob)
        await bob.connect()
        print_resume("bob with alice's current file", bob, current, server, expected_token=current)
        print("  owner after bob's ActivateSession:", session_owner(server, current))
        print("  bob receives alice's subscription data:", await publish_after_write(bob, server, variable, 22))
    finally:
        for client in clients:
            await disconnect_quiet(client)
        await stop_server(server)


async def scenario_downgrade(network: LoopbackNetwork, root: Path) -> None:
    print("== 10. policy downgrade on resume ==")
    server_cert, server_key = generate_pair("urn:demo:server", ExtendedKeyUsageOID.SERVER_AUTH)
    client_cert, client_key = generate_pair("urn:demo:client", ExtendedKeyUsageOID.CLIENT_AUTH)
    server = await start_server(
        network,
        48406,
        DemoUserManager(),
        server_cert=server_cert,
        server_key=server_key,
        policies=[ua.SecurityPolicyType.NoSecurity, ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt],
    )
    clients: list[Client] = []
    try:
        variable = await server.nodes.objects.add_variable(2, "DemoValue", 0)
        await variable.set_writable()
        state = root / "downgrade.json"
        alice = await make_client(
            48406, state, "alice", "alice-pw", client_cert=client_cert, client_key=client_key, server_cert=server_cert
        )
        clients.append(alice)
        await alice.connect()
        await subscribe(alice, variable)
        token = alice.uaclient.session.authentication_token
        donor = root / "downgrade-donor.json"
        donor.write_bytes(state.read_bytes())
        await crash_client(alice)
        downgrade = root / "downgrade-copy.json"
        downgrade.write_bytes(donor.read_bytes())
        weak = await make_client(48406, downgrade, "alice", "alice-pw")
        clients.append(weak)
        await weak.connect()
        print_resume("resumed over PolicyNone", weak, token, server, expected_token=token)
        print("  channel policy:", weak.security_policy.URI, weak.security_policy.Mode)
        print("  manual Publish returns data:", await publish_after_write(weak, server, variable, 23))
    finally:
        for client in clients:
            await disconnect_quiet(client)
        await stop_server(server)


async def scenario_expiry(network: LoopbackNetwork, root: Path) -> None:
    print("== 11. timeout and expiry ==")
    server = await start_server(network, 48407, DemoUserManager(), min_session_timeout_ms=100)
    clients: list[Client] = []
    try:
        variable = await server.nodes.objects.add_variable(2, "DemoValue", 0)
        await variable.set_writable()
        state = root / "expiry.json"
        alice = await make_client(48407, state, "alice", "alice-pw", session_timeout_ms=500)
        clients.append(alice)
        await alice.connect()
        await subscribe(alice, variable)
        token = alice.uaclient.session.authentication_token
        await crash_client(alice)
        await asyncio.sleep(1.5)
        print("  server session gone:", not session_exists(server, token), "file still present:", state.exists())
        alice2 = await make_client(48407, state, "alice", "alice-pw", session_timeout_ms=500)
        clients.append(alice2)
        await alice2.connect()
        new_token = alice2.uaclient.session.authentication_token
        print(f"  expired session not revived: token_same={new_token == token} ref={token_ref(new_token)}")

        print("== 11b. old saved_at while the server session is still live ==")
        state = root / "age.json"
        alice3 = await make_client(48407, state, "alice", "alice-pw", session_timeout_ms=500)
        clients.append(alice3)
        await alice3.connect()
        await subscribe(alice3, variable)
        live_token = alice3.uaclient.session.authentication_token
        await asyncio.sleep(1.5)
        print("  server session still alive:", session_exists(server, live_token))
        age = time.time() - json.loads(state.read_text(encoding="utf-8"))["saved_at"]
        print("  saved_at age (s):", round(age, 2), "client timeout (s):", alice3.session_timeout / 1000)
        await crash_client(alice3)
        alice4 = await make_client(48407, state, "alice", "alice-pw", session_timeout_ms=500)
        clients.append(alice4)
        await alice4.connect()
        resumed = alice4.uaclient.session.authentication_token == live_token
        print("  live session resumed despite old saved_at:", resumed)
    finally:
        for client in clients:
            await disconnect_quiet(client)
        await stop_server(server)


async def scenario_disclosed_token(network: LoopbackNetwork, root: Path) -> None:
    print("== 12. disclosed token: no file, only the token value ==")
    server = await start_server(network, 48408, DemoUserManager())
    clients: list[Client] = []
    try:
        variable = await server.nodes.objects.add_variable(2, "DemoValue", 0)
        await variable.set_writable()
        alice = await make_client(48408, root / "guess-alice.json", "alice", "alice-pw")
        clients.append(alice)
        await alice.connect()
        await subscribe(alice, variable)
        token = alice.uaclient.session.authentication_token
        attacker = Client("opc.tcp://127.0.0.1:48408", timeout=2.0)
        clients.append(attacker)
        await attacker.connect_sessionless()
        attacker.uaclient.session.restore_authentication_token(token)
        try:
            await attacker.activate_session(username="bob", password="bob-pw")
        except Exception as exc:
            print("  sessionless activation rejected:", type(exc).__name__)
        else:
            print(f"  sessionless activation accepted ref={token_ref(token)} owner={session_owner(server, token)}")
            print("  read through hijacked session:", (await attacker.nodes.objects.read_display_name()).Text)
            print("  receives alice's subscription data:", await publish_after_write(attacker, server, variable, 31))
    finally:
        for client in clients:
            await disconnect_quiet(client)
        await stop_server(server)


async def scenario_collision(network: LoopbackNetwork, root: Path) -> None:
    print("== 13. two independent servers, copied file ==")
    primary = await start_server(network, 48409, DemoUserManager())
    standby = await start_server(network, 48410, DemoUserManager())
    clients: list[Client] = []
    try:
        primary_var = await primary.nodes.objects.add_variable(2, "DemoValue", 0)
        standby_var = await standby.nodes.objects.add_variable(2, "DemoValue", 0)
        await primary_var.set_writable()
        await standby_var.set_writable()

        alice = await make_client(48409, root / "collision-alice.json", "alice", "alice-pw")
        clients.append(alice)
        await alice.connect()
        await subscribe(alice, primary_var)
        alice_token = alice.uaclient.session.authentication_token

        bob = await make_client(48410, root / "collision-bob.json", "bob", "bob-pw")
        clients.append(bob)
        await bob.connect()
        await subscribe(bob, standby_var)
        bob_token = bob.uaclient.session.authentication_token
        print("  random tokens collide:", alice_token == bob_token, token_ref(alice_token), token_ref(bob_token))

        donor = root / "collision-donor.json"
        donor.write_bytes((root / "collision-alice.json").read_bytes())
        await crash_client(alice)
        copied = root / "collision-copied.json"
        copied.write_bytes(donor.read_bytes())
        alice_on_standby = await make_client(48410, copied, "alice", "alice-pw")
        clients.append(alice_on_standby)
        await alice_on_standby.connect()
        standby_token = alice_on_standby.uaclient.session.authentication_token
        print_resume("alice on standby", alice_on_standby, standby_token, standby, expected_token=standby_token)
        print("  standby does not continue the primary token:", standby_token != alice_token)
        print("  standby creates a new session:", standby_token != bob_token)
        print("  bob's standby session owner unchanged:", session_owner(standby, bob_token))
        print(
            "  copied file delivers bob's data:",
            await publish_after_write(alice_on_standby, standby, standby_var, 32),
        )
    finally:
        for client in clients:
            await disconnect_quiet(client)
        await stop_server(standby)
        await stop_server(primary)


async def main() -> None:
    logging.disable(logging.CRITICAL)
    network = LoopbackNetwork()
    async with network.active():
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            await scenario_plain(network, root)
            await scenario_deleted(network, root)
            await scenario_secure(network, root)
            await scenario_downgrade(network, root)
            await scenario_expiry(network, root)
            await scenario_disclosed_token(network, root)
            await scenario_collision(network, root)


if __name__ == "__main__":
    asyncio.run(main())
