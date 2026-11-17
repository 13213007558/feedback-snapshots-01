"""
Fixtures for the change-of-value tests.

Three full BACnet Applications share one in-memory VirtualNetwork (the same
shape as the MCP test fixtures):

* ``subscriber_a`` (device,901, MAC 0x01) and ``subscriber_b``
  (device,902, MAC 0x02) are the COV clients.
* ``publisher``    (device,903, MAC 0x03) hosts an analog-value object that
  supports COV subscriptions and is the source of the notifications.

The applications run on the real BACnet stack, so the tests exercise the
complete subscribe / notify / ACK path without touching a real network.
"""

from __future__ import annotations

import itertools
from typing import Any, AsyncIterator, Dict, List

import pytest

from bacpypes3.app import Application
from bacpypes3.vlan import VirtualNetwork

SUBSCRIBER_A_ADDRESS = "0x01"
SUBSCRIBER_B_ADDRESS = "0x02"
PUBLISHER_ADDRESS = "0x03"

PUBLISHER_INSTANCE = 903
ANALOG_VALUE_ID = "analog-value,1"

# VirtualNetwork names are global and must be unique
_network_counter = itertools.count(1)


def _device_object(instance: int, name: str) -> Dict[str, Any]:
    return {
        "apdu-segment-timeout": 1000,
        "apdu-timeout": 3000,
        "application-software-version": "1.0",
        "database-revision": 1,
        "firmware-revision": "N/A",
        "max-apdu-length-accepted": 1024,
        "model-name": "N/A",
        "number-of-apdu-retries": 3,
        "object-identifier": f"device,{instance}",
        "object-name": name,
        "object-type": "device",
        "protocol-revision": 22,
        "protocol-version": 1,
        "segmentation-supported": "segmented-both",
        "system-status": "operational",
        "vendor-identifier": 999,
        "vendor-name": "BACpypes",
    }


def _network_port(network_name: str, mac_address: str) -> Dict[str, Any]:
    return {
        "changes-pending": False,
        "mac-address": mac_address,
        "network-interface-name": network_name,
        "network-type": "virtual",
        "object-identifier": "network-port,1",
        "object-name": "NetworkPort-1",
        "object-type": "network-port",
        "out-of-service": False,
        "protocol-level": "bacnet-application",
        "reliability": "no-fault-detected",
    }


def _build_application(objects: List[Dict[str, Any]]) -> Application:
    return Application.from_json(objects)


@pytest.fixture
async def cov_apps() -> AsyncIterator[Dict[str, Application]]:
    """Build the two subscribers and the publisher on a fresh VLAN."""
    network_name = f"cov-test-{next(_network_counter)}"
    VirtualNetwork(network_name)

    subscriber_a = _build_application(
        [
            _device_object(901, "Subscriber A"),
            _network_port(network_name, SUBSCRIBER_A_ADDRESS),
        ]
    )
    subscriber_b = _build_application(
        [
            _device_object(902, "Subscriber B"),
            _network_port(network_name, SUBSCRIBER_B_ADDRESS),
        ]
    )
    publisher = _build_application(
        [
            _device_object(PUBLISHER_INSTANCE, "Publisher"),
            _network_port(network_name, PUBLISHER_ADDRESS),
            {
                "object-identifier": ANALOG_VALUE_ID,
                "object-name": "Ramp",
                "object-type": "analog-value",
                "out-of-service": False,
                "present-value": 10.0,
                "status-flags": [False, False, False, False],
                "event-state": "normal",
                "units": "no-units",
                "cov-increment": 1.0,
            },
        ]
    )

    apps = {
        "subscriber_a": subscriber_a,
        "subscriber_b": subscriber_b,
        "publisher": publisher,
    }
    try:
        yield apps
    finally:
        for app in apps.values():
            app.close()
        VirtualNetwork._networks.pop(network_name, None)
