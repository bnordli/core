# Copyright 2019 Klas Lindfors <klali@avm.se>

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""The Plejd service code."""

import asyncio
import binascii
from datetime import datetime, timedelta
import logging
import os
import re
import struct

from homeassistant.const import EVENT_HOMEASSISTANT_STOP
from homeassistant.core import callback
from homeassistant.helpers.event import async_track_point_in_utc_time
import homeassistant.util.dt as dt_util

from .const import (
    BLUEZ_ADAPTER_IFACE,
    BLUEZ_DEVICE_IFACE,
    BLUEZ_SERVICE_NAME,
    DBUS_OM_IFACE,
    DBUS_PROP_IFACE,
    DOMAIN,
    GATT_CHRC_IFACE,
    GATT_SERVICE_IFACE,
    PLEJD_AUTH_UUID,
    PLEJD_DATA_UUID,
    PLEJD_LAST_DATA_UUID,
    PLEJD_LIGHTLEVEL_UUID,
    PLEJD_PING_UUID,
    PLEJD_SVC_UUID,
    TIME_DELTA_SYNC,
)

_LOGGER = logging.getLogger(__name__)


class PlejdService:
    """Representation of the Plejd service."""

    def __init__(self, hass):
        """Initialize the service."""
        self.hass = hass
        self.pi = hass.data[DOMAIN]
        hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, self._stop_plejd)

    async def _connect(self):
        pi = self.pi
        pi["characteristics"] = None
        (bus, om) = await _get_bus(pi["dbus_address"])

        om_objects = await om.call_get_managed_objects()
        adapter = await _get_adapter(bus, om_objects)

        if not adapter:
            _LOGGER.error("No bluetooth adapter localized")
            return False
        await _disconnect_devices(bus, om_objects, adapter)

        plejds = await _get_plejds(bus, om, pi, adapter)
        _LOGGER.debug(f"Found {len(plejds)} plejd devices")
        if len(plejds) == 0:
            _LOGGER.warning("No plejd devices found")
            return False

        await asyncio.sleep(pi["discovery_timeout"])
        plejd_service = await _get_plejd_service(bus, om)
        if not plejd_service:
            _LOGGER.warning("Failed connecting to plejd service")
            return False
        pi["address"] = plejd_service[0]
        pi["characteristics"] = plejd_service[1]
        if not await self._authenticate(pi["key"]):
            return False

        @callback
        def handle_notification_cb(iface, changed_props, invalidated_props):
            if iface != GATT_CHRC_IFACE:
                return
            if not len(changed_props):
                return
            value = changed_props.get("Value", None)
            if not value:
                return

            dec = _plejd_enc_dec(pi["key"], pi["address"], value.value)
            # check if this is a device we care about
            if dec[0] in pi["devices"]:
                device = pi["devices"][dec[0]]
            elif dec[0] == 0x01 and dec[3:5] == b"\x00\x1b":
                n = dt_util.now().replace(tzinfo=None)
                time = datetime.fromtimestamp(struct.unpack_from("<I", dec, 5)[0])
                n = n + timedelta(minutes=pi["offset_minutes"])
                delta = abs(time - n)
                _LOGGER.debug(f"Plejd network reports time as '{time}'")
                s = delta.total_seconds()
                if s > TIME_DELTA_SYNC:
                    _LOGGER.info(
                        f"Plejd time delta is {s} seconds, setting time to '{n}'."
                    )
                    ntime = b"\x00\x01\x10\x00\x1b"
                    ntime += struct.pack("<I", int(n.timestamp())) + b"\x00"
                    pi["hass"].async_create_task(self._write(ntime))
                return
            else:
                _LOGGER.debug(
                    f"No match for device '{dec[0]:02x}' ({binascii.b2a_hex(dec)})"
                )
                return
            dim = None
            state = None
            if dec[3:5] == b"\x00\xc8" or dec[3:5] == b"\x00\x98":
                # 00c8 and 0098 both mean state+dim
                state = dec[5]
                dim = int.from_bytes(dec[6:8], "little")
            elif dec[3:5] == b"\x00\x97":
                # 0097 is state only
                state = dec[5]
            else:
                _LOGGER.debug(
                    "No match for command '%s' (%s)"
                    % (binascii.b2a_hex(dec[3:5]), binascii.b2a_hex(dec))
                )
                return

            device.update_state(bool(state), dim)

        @callback
        def handle_lightlevel_cb(iface, changed_props, invalidated_props):
            if iface != GATT_CHRC_IFACE:
                return
            if not len(changed_props):
                return
            value = changed_props.get("Value", None)
            if not value:
                return

            value = value.value
            if len(value) != 20 and len(value) != 10:
                lightlevel = binascii.b2a_hex(value)
                _LOGGER.debug(
                    f"Unknown length data received for lightlevel: '{lightlevel}'"
                )
                return

            msgs = [value[0:10]]
            if len(value) == 20:
                msgs.append(value[10:20])

            for m in msgs:
                if m[0] not in pi["devices"]:
                    continue
                device = pi["devices"][m[0]]
                device.update_state(bool(m[1]), int.from_bytes(m[5:7], "little"))

        await adapter.call_stop_discovery()
        await self._add_callback("last_data", handle_notification_cb)
        await self._add_callback("lightlevel", handle_lightlevel_cb)

        return True

    async def _add_callback(self, method, callback):
        pi = self.pi
        pi["characteristics"][method + "prop"].on_properties_changed(callback)
        await pi["characteristics"][method].call_start_notify()

    async def _ping(self, now):
        pi = self.pi
        if not await self._send_ping():
            await self._connect()
        pi["remove_timer"] = async_track_point_in_utc_time(
            self.hass, self._ping, dt_util.utcnow() + timedelta(seconds=300)
        )

    async def _stop_plejd(self, event):
        pi = self.pi
        if "remove_timer" in pi:
            pi["remove_timer"]()

    async def _authenticate(self, key):
        from dbus_next.errors import DBusError

        char = self.pi["characteristics"]["auth"]

        try:
            await char.call_write_value(b"\x00", {})
            chal = await char.call_read_value({})
            r = _plejd_chalresp(key, chal)
            await char.call_write_value(r, {})
        except DBusError as e:
            _LOGGER.warning(f"Plejd authentication errored: {e}")
            return False
        return True

    async def _send_ping(self):
        from dbus_next.errors import DBusError

        ping = os.urandom(1)
        pi = self.pi
        char = pi["characteristics"]["ping"]
        try:
            await char.call_write_value(ping, {})
            pong = await char.call_read_value({})
        except DBusError as e:
            _LOGGER.warning(f"Plejd ping errored: {e}")
            return False
        if (ping[0] + 1) & 0xFF != pong[0]:
            _LOGGER.warning(f"Plejd ping failed {ping[0]:02x} - {pong[0]:02x}")
            return False

        _LOGGER.debug(f"Successfully pinged with {ping[0]:02x}")
        return True

    async def _write(self, payload):
        from dbus_next.errors import DBusError

        pi = self.pi
        pi = self.hass.data[DOMAIN]
        if "characteristics" not in pi:
            _LOGGER.warning("Tried to write to plejd when not connected")
            return

        try:
            data = _plejd_enc_dec(pi["key"], pi["address"], payload)
            await pi["characteristics"]["data"].call_write_value(data, {})
        except DBusError as e:
            _LOGGER.warning(f"Write failed, reconnecting: '{e}'")
            await self._connect()
            data = _plejd_enc_dec(pi["key"], pi["address"], payload)
            await pi["characteristics"]["data"].call_write_value(data, {})

    async def _request_update(self):
        pi = self.pi
        await pi["characteristics"]["lightlevel"].call_write_value(b"\x01", {})


async def _get_bus(address):
    from dbus_next import BusType
    from dbus_next.aio import MessageBus

    bus = await MessageBus(bus_type=BusType.SYSTEM, bus_address=address).connect()

    om_introspection = await bus.introspect(BLUEZ_SERVICE_NAME, "/")
    om = bus.get_proxy_object(BLUEZ_SERVICE_NAME, "/", om_introspection).get_interface(
        DBUS_OM_IFACE
    )

    return bus, om


async def _get_adapter(bus, om_objects):
    for path, interfaces in om_objects.items():
        if BLUEZ_ADAPTER_IFACE in interfaces.keys():
            _LOGGER.debug(f"Discovered bluetooth adapter {path}")
            adapter_introspection = await bus.introspect(BLUEZ_SERVICE_NAME, path)
            return bus.get_proxy_object(
                BLUEZ_SERVICE_NAME, path, adapter_introspection
            ).get_interface(BLUEZ_ADAPTER_IFACE)


async def _disconnect_devices(bus, om_objects, adapter):
    for path, interfaces in om_objects.items():
        if BLUEZ_DEVICE_IFACE in interfaces.keys():
            device_introspection = await bus.introspect(BLUEZ_SERVICE_NAME, path)
            dev = bus.get_proxy_object(
                BLUEZ_SERVICE_NAME, path, device_introspection
            ).get_interface(BLUEZ_DEVICE_IFACE)
            connected = await dev.get_connected()
            if connected:
                _LOGGER.debug(f"Disconnecting {path}")
                await dev.call_disconnect()
                _LOGGER.debug(f"Disconnected {path}")
            await adapter.call_remove_device(path)


async def _get_plejds(bus, om, pi, adapter):
    from dbus_next import Variant
    from dbus_next.errors import DBusError

    plejds = []

    @callback
    def on_interfaces_added(path, interfaces):
        if (
            BLUEZ_DEVICE_IFACE in interfaces
            and PLEJD_SVC_UUID in interfaces[BLUEZ_DEVICE_IFACE]["UUIDs"].value
        ):
            plejds.append({"path": path})

    om.on_interfaces_added(on_interfaces_added)

    scan_filter = {
        "UUIDs": Variant("as", [PLEJD_SVC_UUID]),
        "Transport": Variant("s", "le"),
    }
    await adapter.call_set_discovery_filter(scan_filter)
    await adapter.call_start_discovery()
    await asyncio.sleep(pi["discovery_timeout"])

    for plejd in plejds:
        device_introspection = await bus.introspect(BLUEZ_SERVICE_NAME, plejd["path"])
        dev = bus.get_proxy_object(
            BLUEZ_SERVICE_NAME, plejd["path"], device_introspection
        ).get_interface(BLUEZ_DEVICE_IFACE)
        plejd["RSSI"] = await dev.get_rssi()
        plejd["obj"] = dev
        _LOGGER.debug(f"Discovered plejd {plejd['path']} with RSSI {plejd['RSSI']}")

    plejds.sort(key=lambda a: a["RSSI"], reverse=True)
    for plejd in plejds:
        try:
            _LOGGER.debug(f"Connecting to {plejd['path']}")
            await plejd["obj"].call_connect()
            _LOGGER.debug(f"Connected to {plejd['path']}")
            break
        except DBusError as e:
            _LOGGER.warning(f"Error connecting to plejd: {e}")

    return plejds


async def _get_plejd_service(bus, om):
    objects = await om.call_get_managed_objects()
    chrcs = []

    for path, interfaces in objects.items():
        if GATT_CHRC_IFACE in interfaces.keys():
            chrcs.append(path)

    async def process_plejd_service(service_path, chrc_paths, bus):
        service_introspection = await bus.introspect(BLUEZ_SERVICE_NAME, service_path)
        service = bus.get_proxy_object(
            BLUEZ_SERVICE_NAME, service_path, service_introspection
        ).get_interface(GATT_SERVICE_IFACE)
        uuid = await service.get_uuid()
        if uuid != PLEJD_SVC_UUID:
            return None

        dev = await service.get_device()
        x = re.search("dev_([0-9A-F_]+)$", dev)
        addr = binascii.a2b_hex(x.group(1).replace("_", ""))[::-1]

        chars = {}

        # Process the characteristics.
        for chrc_path in chrc_paths:
            chrc_introspection = await bus.introspect(BLUEZ_SERVICE_NAME, chrc_path)
            chrc_obj = bus.get_proxy_object(
                BLUEZ_SERVICE_NAME, chrc_path, chrc_introspection
            )
            chrc = chrc_obj.get_interface(GATT_CHRC_IFACE)
            chrc_prop = chrc_obj.get_interface(DBUS_PROP_IFACE)

            uuid = await chrc.get_uuid()

            if uuid == PLEJD_DATA_UUID:
                chars["data"] = chrc
            elif uuid == PLEJD_LAST_DATA_UUID:
                chars["last_data"] = chrc
                chars["last_data_prop"] = chrc_prop
            elif uuid == PLEJD_AUTH_UUID:
                chars["auth"] = chrc
            elif uuid == PLEJD_PING_UUID:
                chars["ping"] = chrc
            elif uuid == PLEJD_LIGHTLEVEL_UUID:
                chars["lightlevel"] = chrc
                chars["lightlevel_prop"] = chrc_prop

        return (addr, chars)

    for path, interfaces in objects.items():
        if GATT_SERVICE_IFACE not in interfaces.keys():
            continue

        chrc_paths = [d for d in chrcs if d.startswith(path + "/")]

        plejd_service = await process_plejd_service(path, chrc_paths, bus)
        if plejd_service:
            return plejd_service

    return None


def _plejd_chalresp(key, chal):
    import hashlib

    k = int.from_bytes(key, "big")
    c = int.from_bytes(chal, "big")

    intermediate = hashlib.sha256((k ^ c).to_bytes(16, "big")).digest()
    part1 = int.from_bytes(intermediate[:16], "big")
    part2 = int.from_bytes(intermediate[16:], "big")
    resp = (part1 ^ part2).to_bytes(16, "big")
    return resp


def _plejd_enc_dec(key, addr, data):
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    buf = bytearray(addr * 2)
    buf += addr[:4]

    ct = (
        Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        .encryptor()
        .update(buf)
    )

    output = b""
    for i in range(len(data)):
        output += struct.pack("B", data[i] ^ ct[i % 16])

    return output
