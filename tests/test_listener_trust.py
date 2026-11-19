#
# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.

"""Proxy trust is resolved from the listener that accepted the connection.

A public listener and an internal one can serve the same peer address and
must not share a rule. These tests pin the resolution, the fallback and the
key spellings; the entry-point behaviour is in
test_listener_trust_entries.py.
"""

from unittest import mock

import pytest

from gunicorn import sock, trust
from gunicorn.config import Config


class _Listener:
    """The part of gunicorn.sock.BaseSocket the resolver reads."""

    def __init__(self, address, bind_spec=None):
        self.address = address
        self.bind_spec = bind_spec

    def getsockname(self):
        return self.address


def test_normalize_bind_key_spellings():
    assert trust.normalize_bind_key("10.0.0.5:8001") == "10.0.0.5:8001"
    assert trust.normalize_bind_key("tcp://10.0.0.5:8001") == "10.0.0.5:8001"
    assert trust.normalize_bind_key(("10.0.0.5", 8001)) == "10.0.0.5:8001"
    assert trust.normalize_bind_key("[::1]:8001") == "[::1]:8001"
    assert trust.normalize_bind_key(("::1", 8001)) == "[::1]:8001"
    assert trust.normalize_bind_key("unix:/run/app.sock") == "unix:/run/app.sock"
    assert trust.normalize_bind_key("unix:///run/app.sock") == "unix:/run/app.sock"
    assert trust.normalize_bind_key("/run/app.sock") == "unix:/run/app.sock"
    assert trust.normalize_bind_key("fd://7") == "fd://7"


def test_listener_keys_cover_both_spellings():
    listener = _Listener(("10.0.0.5", 8001), bind_spec="tcp://10.0.0.5:8001")
    keys = trust.listener_bind_keys(listener)
    assert "10.0.0.5:8001" in keys
    assert "tcp://10.0.0.5:8001" not in keys


def _cfg(**settings):
    cfg = Config()
    for name, value in settings.items():
        cfg.set(name, value)
    return cfg


def test_public_listener_override_does_not_touch_internal_one():
    cfg = _cfg(
        forwarded_allow_ips="127.0.0.1,::1",
        forwarded_allow_ips_by_bind={"10.0.0.5:8001": "10.0.0.0/8"},
    )
    public = trust.resolve(cfg, _Listener(("0.0.0.0", 8000)))
    internal = trust.resolve(cfg, _Listener(("10.0.0.5", 8001)))

    # Same peer address reaching both entries; only the internal one says yes.
    assert public.trusts_forwarded(("10.9.9.9", 50000)) is False
    assert internal.trusts_forwarded(("10.9.9.9", 50000)) is True
    # The public entry falls back to the global setting.
    assert public.forwarded_allow_ips == ["127.0.0.1", "::1"]
    assert public.forwarded_overridden is False
    assert internal.forwarded_overridden is True


def test_missing_entry_uses_global_setting():
    cfg = _cfg(
        forwarded_allow_ips="192.0.2.0/24",
        proxy_allow_ips="198.51.100.0/24",
        forwarded_allow_ips_by_bind={"10.0.0.5:8001": "10.0.0.0/8"},
        proxy_allow_ips_by_bind={"10.0.0.5:8001": "10.0.0.0/8"},
    )
    resolved = trust.resolve(cfg, _Listener(("0.0.0.0", 8000)))
    assert resolved.forwarded_allow_ips == ["192.0.2.0/24"]
    assert resolved.proxy_allow_ips == ["198.51.100.0/24"]
    assert resolved.forwarded_overridden is False
    assert resolved.proxy_overridden is False


def test_empty_entry_trusts_nobody_and_does_not_fall_back():
    cfg = _cfg(
        forwarded_allow_ips="*",
        proxy_allow_ips="*",
        forwarded_allow_ips_by_bind={"0.0.0.0:8000": ""},
        proxy_allow_ips_by_bind={"0.0.0.0:8000": ""},
    )
    resolved = trust.resolve(cfg, _Listener(("0.0.0.0", 8000)))
    assert resolved.forwarded_overridden is True
    assert resolved.proxy_overridden is True
    assert resolved.trusts_forwarded(("127.0.0.1", 1)) is False
    assert resolved.trusts_proxy(("127.0.0.1", 1)) is False


def test_unix_peer_is_trusted_like_before():
    cfg = _cfg(forwarded_allow_ips="")
    resolved = trust.resolve(cfg, _Listener("unix:/run/app.sock"))
    assert resolved.trusts_forwarded("") is True
    assert resolved.trusts_proxy("") is True


def test_unix_peer_stays_unconditionally_trusted():
    """The forwarded_allow_ips note applies per listener: a peer with no IP
    address is allowed, whatever the list says."""
    cfg = _cfg(
        forwarded_allow_ips="127.0.0.1,::1",
        forwarded_allow_ips_by_bind={"unix:/run/app.sock": ""},
    )
    resolved = trust.resolve(cfg, _Listener("unix:/run/app.sock"))
    assert resolved.forwarded_overridden is True
    assert resolved.trusts_forwarded("") is True


def test_resolver_tolerates_a_listener_without_bind_spec():
    cfg = _cfg(forwarded_allow_ips="10.0.0.0/8")
    resolved = trust.resolve(cfg, _Listener(("10.0.0.5", 8001)))
    assert resolved.trusts_forwarded(("10.1.1.1", 1)) is True


def test_resolve_without_listener_has_no_rule():
    cfg = _cfg(forwarded_allow_ips="*")
    assert trust.resolve(cfg, None) is None
    default = trust.resolve_or_default(cfg, None)
    assert default.trusts_forwarded(("203.0.113.9", 1)) is True


def test_wildcard_and_cidr_entries():
    cfg = _cfg(forwarded_allow_ips_by_bind={
        "0.0.0.0:8000": "*",
        "10.0.0.5:8001": "10.0.0.0/8,192.0.2.7",
    })
    public = trust.resolve(cfg, _Listener(("0.0.0.0", 8000)))
    internal = trust.resolve(cfg, _Listener(("10.0.0.5", 8001)))
    assert public.trusts_forwarded(("203.0.113.9", 1)) is True
    assert internal.trusts_forwarded(("10.9.9.9", 1)) is True
    assert internal.trusts_forwarded(("192.0.2.7", 1)) is True
    assert internal.trusts_forwarded(("203.0.113.9", 1)) is False


def test_config_accepts_cli_and_mapping_forms():
    cfg = Config()
    cfg.set("forwarded_allow_ips_by_bind",
            ["10.0.0.5:8001=10.0.0.0/8", "0.0.0.0:8000="])
    assert cfg.forwarded_allow_ips_by_bind == {
        "10.0.0.5:8001": ["10.0.0.0/8"],
        "0.0.0.0:8000": [],
    }
    cfg.set("proxy_allow_ips_by_bind", {"unix:/run/app.sock": "*"})
    assert cfg.proxy_allow_ips_by_bind == {"unix:/run/app.sock": ["*"]}


@pytest.mark.parametrize("value", [
    {"x": None},
])
def test_config_treats_none_value_as_empty(value):
    cfg = Config()
    cfg.set("forwarded_allow_ips_by_bind", value)
    assert cfg.forwarded_allow_ips_by_bind == {"x": []}


@pytest.mark.parametrize("value", [
    {"": "10.0.0.1"},
    {"a": 1},
    "10.0.0.1",  # no "="
])
def test_config_rejects_bad_entries(value):
    cfg = Config()
    with pytest.raises((TypeError, ValueError)):
        cfg.set("forwarded_allow_ips_by_bind", value)


def test_config_rejects_bad_network():
    cfg = Config()
    with pytest.raises(ValueError):
        cfg.set("proxy_allow_ips_by_bind", {"10.0.0.5:8001": "10.0.0"})


def test_config_rejects_two_spellings_of_the_same_listener():
    cfg = Config()
    with pytest.raises(ValueError):
        cfg.set("forwarded_allow_ips_by_bind", {
            "127.0.0.1:8000": "10.0.0.0/8",
            "tcp://127.0.0.1:8000": "*",
        })


def test_bind_spec_follows_the_configured_bind_order():
    cfg = Config()
    cfg.set("bind", ["0.0.0.0:8000", "10.0.0.5:8001"])
    assert sock._bind_spec_for(cfg, cfg.address[0]) == "0.0.0.0:8000"
    assert sock._bind_spec_for(cfg, cfg.address[1]) == "10.0.0.5:8001"


def test_bind_spec_is_none_for_an_unknown_address():
    cfg = Config()
    cfg.set("bind", ["fd://3"])
    assert sock._bind_spec_for(cfg, 3) == "fd://3"
    # An address the configuration never named (an inherited socket) has no
    # bind string; its listener is keyed by getsockname() alone.
    assert sock._bind_spec_for(cfg, ("192.0.2.1", 9000)) is None


def test_inherited_fd_listener_is_keyed_by_its_bind_entry():
    cfg = Config()
    cfg.set("bind", ["fd://3"])
    ready = mock.Mock()
    ready.getsockname.return_value = ("127.0.0.1", 8000)
    ready.getsockopt.return_value = 1

    with mock.patch.object(sock.socket, "fromfd", return_value=ready), \
            mock.patch.object(sock.os, "close"):
        listeners = sock.create_sockets(cfg, mock.Mock(), fds=[3])

    assert listeners[0].bind_spec == "fd://3"


def test_worker_side_socket_keeps_the_bind_spec():
    """reuse_port rebuilds the listeners in the worker; the trust key must
    survive that."""
    cfg = Config()
    cfg.set("bind", ["0.0.0.0:8000"])
    listener = sock.TCPSocket.__new__(sock.TCPSocket)
    listener.conf = cfg
    listener.log = mock.Mock()
    listener.cfg_addr = ("0.0.0.0", 8000)
    listener.sock = mock.Mock()
    listener.bind_spec = "0.0.0.0:8000"
    assert trust.listener_bind_keys(listener) == ("0.0.0.0:8000",)
